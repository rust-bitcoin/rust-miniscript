#![allow(unexpected_cfgs)]

use honggfuzz::fuzz;
use miniscript::{Miniscript, Tap};

fn do_test(data: &[u8]) {
    // Try round-tripping as a script
    let script = miniscript::bitcoin::script::ScriptPubKey::from_bytes(data);

    if let Ok(pt) = Miniscript::<miniscript::bitcoin::XOnlyPublicKey, Tap>::decode(script) {
        let output: miniscript::bitcoin::script::ScriptPubKeyBuf = pt.encode();
        assert_eq!(pt.script_size(), output.len());
        assert_eq!(output.as_bytes(), script.as_bytes());
    }
}

fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}
