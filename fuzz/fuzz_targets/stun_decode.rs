#![no_main]
use libfuzzer_sys::fuzz_target;
use ghulakh_protocol::stun::StunMessage;

fuzz_target!(|data: &[u8]| {
    if let Ok(message) = StunMessage::decode(data) {
        if let Ok(encoded) = message.encode() {
            let decoded = StunMessage::decode(&encoded)
                .expect("an encoded STUN message must decode");
            assert_eq!(decoded, message);
        }
    }
});
