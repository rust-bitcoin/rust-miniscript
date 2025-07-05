#![allow(unexpected_cfgs)]

use honggfuzz::fuzz;
use miniscript::{DefiniteDescriptorKey, Descriptor};

fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data);

    if let Ok(desc) = data_str.parse::<Descriptor<DefiniteDescriptorKey>>() {
        let _ = desc.to_string();
        let _ = desc.address(miniscript::bitcoin::Network::Bitcoin);
    }
}

fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}
