//! Bounded UDP request/response transaction tracking for STUN/TURN.
//!
//! The manager is deterministic and does not own a socket or timer. The caller
//! sends the initial request, periodically calls poll(), sends returned
//! retransmissions, and passes received datagrams to accept_response().

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

use crate::stun::{StunClass, StunMessage};

pub const DEFAULT_RTO: Duration = Duration::from_millis(500);
pub const DEFAULT_MAX_REQUESTS: u8 = 7;
pub const DEFAULT_RM: u32 = 16;
pub const MAX_OUTSTANDING_PER_SERVER: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransactionError {
    #[error("transaction ID generation failed")]
    RandomGeneration,
    #[error("request is not a STUN request")]
    InvalidRequest,
    #[error("transaction ID is already outstanding")]
    DuplicateTransaction,
    #[error("too many outstanding transactions for this server")]
    TooManyOutstanding,
    #[error("invalid transaction policy")]
    InvalidPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionPolicy {
    pub initial_rto: Duration,
    /// Total number of request transmissions, including the first send.
    pub max_requests: u8,
    /// Final response grace period, as a multiple of the initial RTO.
    pub final_timeout_multiplier: u32,
}

impl Default for TransactionPolicy {
    fn default() -> Self {
        Self {
            initial_rto: DEFAULT_RTO,
            max_requests: DEFAULT_MAX_REQUESTS,
            final_timeout_multiplier: DEFAULT_RM,
        }
    }
}

impl TransactionPolicy {
    fn validate(self) -> Result<(), TransactionError> {
        if self.initial_rto.is_zero()
            || self.max_requests == 0
            || self.final_timeout_multiplier == 0
        {
            return Err(TransactionError::InvalidPolicy);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionEvent {
    Retransmit {
        transaction_id: [u8; 12],
        request: Vec<u8>,
        attempt: u8,
        destination: SocketAddr,
    },
    TimedOut {
        transaction_id: [u8; 12],
        destination: SocketAddr,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedResponse {
    pub transaction_id: [u8; 12],
    pub response: StunMessage,
    /// True if the request was retransmitted. Per RFC 6298/Karn, do not use
    /// this transaction to update an RTT estimator.
    pub was_retransmitted: bool,
}

#[derive(Debug)]
struct PendingTransaction {
    method: u16,
    destination: SocketAddr,
    request: Vec<u8>,
    requests_sent: u8,
    retransmitted: bool,
    next_deadline: Instant,
    retry_interval: Duration,
    policy: TransactionPolicy,
}

#[derive(Debug, Default)]
pub struct TransactionManager {
    pending: BTreeMap<[u8; 12], PendingTransaction>,
}

impl TransactionManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate an unpredictable 96-bit STUN transaction identifier.
    pub fn random_transaction_id() -> Result<[u8; 12], TransactionError> {
        let mut id = [0u8; 12];
        getrandom::getrandom(&mut id).map_err(|_| TransactionError::RandomGeneration)?;
        Ok(id)
    }

    /// Register a request that the caller has just transmitted.
    pub fn register(
        &mut self,
        request: Vec<u8>,
        destination: SocketAddr,
        now: Instant,
        policy: TransactionPolicy,
    ) -> Result<[u8; 12], TransactionError> {
        policy.validate()?;
        let decoded = StunMessage::decode(&request).map_err(|_| TransactionError::InvalidRequest)?;
        if decoded.class != StunClass::Request {
            return Err(TransactionError::InvalidRequest);
        }
        if self.pending.contains_key(&decoded.transaction_id) {
            return Err(TransactionError::DuplicateTransaction);
        }
        let outstanding = self.pending.values()
            .filter(|pending| pending.destination == destination)
            .count();
        if outstanding >= MAX_OUTSTANDING_PER_SERVER {
            return Err(TransactionError::TooManyOutstanding);
        }
        let id = decoded.transaction_id;
        self.pending.insert(id, PendingTransaction {
            method: decoded.method,
            destination,
            request,
            requests_sent: 1,
            retransmitted: false,
            next_deadline: now + policy.initial_rto,
            retry_interval: policy.initial_rto,
            policy,
        });
        Ok(id)
    }

    /// Match only a response from the exact server endpoint and expected method.
    /// The caller MUST verify MESSAGE-INTEGRITY (where required) before applying
    /// any response-driven state transition.
    pub fn accept_response(
        &mut self,
        response: StunMessage,
        source: SocketAddr,
    ) -> Option<MatchedResponse> {
        if !matches!(response.class, StunClass::SuccessResponse | StunClass::ErrorResponse) {
            return None;
        }
        let pending = self.pending.get(&response.transaction_id)?;
        if pending.destination != source || pending.method != response.method {
            return None;
        }
        Some(MatchedResponse {
            transaction_id: response.transaction_id,
            response,
            was_retransmitted: pending.retransmitted,
        })
    }

    /// Complete a transaction only after the caller has verified response
    /// integrity and accepted the corresponding state transition. Keeping the
    /// request pending until then prevents unauthenticated datagrams from
    /// cancelling a live transaction.
    pub fn complete(&mut self, transaction_id: &[u8; 12]) -> bool {
        self.pending.remove(transaction_id).is_some()
    }

    /// Produce due retransmissions and timeout events. No I/O or sleeping occurs here.
    pub fn poll(&mut self, now: Instant) -> Vec<TransactionEvent> {
        let due: Vec<[u8; 12]> = self.pending.iter()
            .filter_map(|(id, pending)| (now >= pending.next_deadline).then_some(*id))
            .collect();
        let mut events = Vec::with_capacity(due.len());
        for id in due {
            let Some(pending) = self.pending.get_mut(&id) else { continue };
            if pending.requests_sent < pending.policy.max_requests {
                pending.requests_sent += 1;
                pending.retransmitted = true;
                events.push(TransactionEvent::Retransmit {
                    transaction_id: id,
                    request: pending.request.clone(),
                    attempt: pending.requests_sent,
                    destination: pending.destination,
                });
                pending.retry_interval = pending.retry_interval.saturating_mul(2);
                let max_interval = pending.policy.initial_rto
                    .saturating_mul(pending.policy.final_timeout_multiplier);
                pending.retry_interval = pending.retry_interval.min(max_interval);
                pending.next_deadline = now + pending.retry_interval;
            } else {
                events.push(TransactionEvent::TimedOut {
                    transaction_id: id,
                    destination: pending.destination,
                });
                self.pending.remove(&id);
            }
        }
        events
    }

    pub fn cancel(&mut self, transaction_id: &[u8; 12]) -> bool {
        self.pending.remove(transaction_id).is_some()
    }

    pub fn outstanding_for(&self, destination: SocketAddr) -> usize {
        self.pending.values().filter(|pending| pending.destination == destination).count()
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stun::{StunAttribute, METHOD_ALLOCATE};

    fn endpoint() -> SocketAddr {
        "192.0.2.10:3478".parse().unwrap()
    }

    fn request(id: [u8; 12]) -> Vec<u8> {
        StunMessage {
            method: METHOD_ALLOCATE,
            class: StunClass::Request,
            transaction_id: id,
            attributes: vec![StunAttribute {
                kind: crate::stun::ATTR_REQUESTED_TRANSPORT,
                value: vec![17, 0, 0, 0],
            }],
        }.encode().unwrap()
    }

    fn policy() -> TransactionPolicy {
        TransactionPolicy::default()
    }

    #[test]
    fn retransmits_with_rfc8489_default_schedule_then_times_out() {
        let start = Instant::now();
        let mut manager = TransactionManager::new();
        let id = [7; 12];
        manager.register(request(id), endpoint(), start, policy()).unwrap();

        let expected_ms = [500, 1500, 3500, 7500, 15500, 31500];
        for (index, elapsed) in expected_ms.into_iter().enumerate() {
            let events = manager.poll(start + Duration::from_millis(elapsed));
            assert!(matches!(&events[..], [TransactionEvent::Retransmit { attempt, .. }] if *attempt == index as u8 + 2));
        }
        let events = manager.poll(start + Duration::from_millis(39500));
        assert_eq!(events, vec![TransactionEvent::TimedOut {
            transaction_id: id,
            destination: endpoint(),
        }]);
        assert!(manager.is_empty());
    }

    #[test]
    fn matches_transaction_id_method_and_source() {
        let now = Instant::now();
        let mut manager = TransactionManager::new();
        let id = [9; 12];
        manager.register(request(id), endpoint(), now, policy()).unwrap();
        let response = StunMessage {
            method: METHOD_ALLOCATE,
            class: StunClass::SuccessResponse,
            transaction_id: id,
            attributes: vec![],
        };
        assert!(manager.accept_response(response.clone(), "192.0.2.11:3478".parse().unwrap()).is_none());
        let mut wrong_method = response.clone();
        wrong_method.method = crate::stun::METHOD_REFRESH;
        assert!(manager.accept_response(wrong_method, endpoint()).is_none());
        let matched = manager.accept_response(response, endpoint()).unwrap();
        assert_eq!(matched.transaction_id, id);
        assert!(!matched.was_retransmitted);
        assert_eq!(manager.len(), 1);
        assert!(manager.complete(&id));
        assert!(manager.is_empty());
    }

    #[test]
    fn retransmitted_transaction_is_marked_for_karn() {
        let start = Instant::now();
        let mut manager = TransactionManager::new();
        let id = [4; 12];
        manager.register(request(id), endpoint(), start, policy()).unwrap();
        manager.poll(start + DEFAULT_RTO);
        let response = StunMessage {
            method: METHOD_ALLOCATE,
            class: StunClass::SuccessResponse,
            transaction_id: id,
            attributes: vec![],
        };
        assert!(manager.accept_response(response, endpoint()).unwrap().was_retransmitted);
        assert_eq!(manager.len(), 1);
        assert!(manager.complete(&id));
    }

    #[test]
    fn enforces_ten_outstanding_per_server() {
        let now = Instant::now();
        let mut manager = TransactionManager::new();
        for n in 0..MAX_OUTSTANDING_PER_SERVER {
            manager.register(request([n as u8; 12]), endpoint(), now, policy()).unwrap();
        }
        assert_eq!(
            manager.register(request([99; 12]), endpoint(), now, policy()),
            Err(TransactionError::TooManyOutstanding)
        );
    }

    #[test]
    fn rejects_indications_and_responses_as_requests() {
        let now = Instant::now();
        let mut manager = TransactionManager::new();
        let invalid = StunMessage {
            method: METHOD_ALLOCATE,
            class: StunClass::Indication,
            transaction_id: [1; 12],
            attributes: vec![],
        }.encode().unwrap();
        assert_eq!(
            manager.register(invalid, endpoint(), now, policy()),
            Err(TransactionError::InvalidRequest)
        );
    }

    #[test]
    fn retransmissions_preserve_the_exact_authenticated_request_bytes() {
        let start = Instant::now();
        let mut manager = TransactionManager::new();
        let id = [0xA5; 12];
        let wire = request(id);
        manager.register(wire.clone(), endpoint(), start, TransactionPolicy {
            initial_rto: Duration::from_millis(10),
            max_requests: 3,
            final_timeout_multiplier: 4,
        }).unwrap();

        for (attempt, elapsed_ms) in [(2, 10), (3, 30)] {
            let events = manager.poll(start + Duration::from_millis(elapsed_ms));
            assert!(matches!(&events[..], [TransactionEvent::Retransmit {
                request: retransmitted, attempt: actual, ..
            }] if *actual == attempt && retransmitted == &wire));
        }
    }

    #[test]
    fn cancellation_removes_pending_transaction() {
        let now = Instant::now();
        let mut manager = TransactionManager::new();
        let id = [2; 12];
        manager.register(request(id), endpoint(), now, policy()).unwrap();
        assert!(manager.cancel(&id));
        assert!(!manager.cancel(&id));
    }
}
