#![no_main]
use ghulakh_protocol::ordered_datagram::SequencedDataDatagram;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = SequencedDataDatagram::decode(data);
});
