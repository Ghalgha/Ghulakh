#![no_main]
use ghulakh_protocol::turn_channel_data::decode_channel_data;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode_channel_data(data);
});
