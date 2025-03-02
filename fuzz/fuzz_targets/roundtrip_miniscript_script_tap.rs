#![allow(unexpected_cfgs)]

use honggfuzz::fuzz;
use miniscript::bitcoin::blockdata::script;
use miniscript::{Miniscript, Tap};

fn do_test(data: &[u8]) {
    // Try round-tripping as a script
    let script = script::Script::from_bytes(data);

    if let Ok(pt) = Miniscript::<miniscript::bitcoin::key::XOnlyPublicKey, Tap>::parse(script) {
        let output = pt.encode();
        assert_eq!(pt.script_size(), output.len());
        assert_eq!(&output, script);
    }
}

fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}
