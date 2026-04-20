#![allow(unexpected_cfgs)]

use honggfuzz::fuzz;
use miniscript::{Miniscript, Tap};

fn do_test(data: &[u8]) {
    // Try round-tripping as a script
    let script = miniscript::Script::from_bytes(data);

    if let Ok(pt) =
        Miniscript::<miniscript::bitcoin::secp256k1::XOnlyPublicKey, Tap>::decode(script)
    {
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
