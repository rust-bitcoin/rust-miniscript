// SPDX-License-Identifier: CC0-1.0

#![cfg_attr(fuzzing, no_main)]

use miniscript::bitcoin::secp256k1;
use miniscript::Descriptor;

fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data);
    let secp = &secp256k1::Secp256k1::signing_only();

    if let Ok((desc, _)) = Descriptor::parse_descriptor(secp, &data_str) {
        let _output = desc.to_string();
        let _sanity_check = desc.sanity_check();
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
