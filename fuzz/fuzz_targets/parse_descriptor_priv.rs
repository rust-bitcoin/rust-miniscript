#![allow(unexpected_cfgs)]

use honggfuzz::fuzz;
use miniscript::bitcoin::secp256k1;
use miniscript::Descriptor;

fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data);

    if let Ok((desc, _)) = Descriptor::parse_descriptor(&data_str) {
        let _output = desc.to_string();
        let _sanity_check = desc.sanity_check();
    }
}

fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}
