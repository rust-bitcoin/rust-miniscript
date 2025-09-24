// SPDX-License-Identifier: CC0-1.0

#![cfg_attr(fuzzing, no_main)]

use miniscript::bitcoin::blockdata::script;
use miniscript::{Miniscript, Segwitv0};

fn do_test(data: &[u8]) {
    // Try round-tripping as a script
    let script = script::Script::from_bytes(data);

    if let Ok(pt) = Miniscript::<miniscript::bitcoin::PublicKey, Segwitv0>::decode(script) {
        let output = pt.encode();
        assert_eq!(pt.script_size(), output.len());
        assert_eq!(&output, script);
    }
}

#[cfg(fuzzing)]
libfuzzer_sys::fuzz_target!(|data| { do_test(data); });

#[cfg(not(fuzzing))]
fn main() { do_test(&[]); }

#[cfg(test)]
mod tests {
    use miniscript::hex;

    #[test]
    fn duplicate_crash() {
        let v = hex::decode_to_vec("abcd").unwrap();
        super::do_test(&v);
    }
}
