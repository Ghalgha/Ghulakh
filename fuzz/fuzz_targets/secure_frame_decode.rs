#![no_main]
use ghulakh_protocol::secure_frame::{FrameDirection, FrameOpener};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut opener = FrameOpener::new(
        [0x42; 32],
        [0x24; 4],
        [0x91; 8],
        FrameDirection::ClientToServer,
    );
    let _ = opener.open(data);
});
