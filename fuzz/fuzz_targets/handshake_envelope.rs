#![no_main]
use libfuzzer_sys::fuzz_target;
use ghulakh_protocol::handshake_datagram::HandshakeEnvelope;

fuzz_target!(|data: &[u8]| {
    if let Ok(envelope) = HandshakeEnvelope::decode(data) {
        let encoded = envelope.encode()
            .expect("a decoded handshake envelope must encode");
        let decoded = HandshakeEnvelope::decode(&encoded)
            .expect("an encoded handshake envelope must decode");
        assert_eq!(decoded, envelope);
    }
});
