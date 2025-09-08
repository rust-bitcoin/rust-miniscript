// SPDX-License-Identifier: CC0-1.0

#![cfg_attr(fuzzing, no_main)]

use std::str::FromStr;

use miniscript::{Miniscript, Segwitv0, Tap};

fn do_test(data: &[u8]) {
    let s = String::from_utf8_lossy(data);
    if let Ok(desc) = Miniscript::<String, Segwitv0>::from_str(&s) {
        let str2 = desc.to_string();
        let desc2 = Miniscript::<String, Segwitv0>::from_str(&str2).unwrap();

        assert_eq!(desc, desc2);
    } else if let Ok(desc) = Miniscript::<String, Tap>::from_str(&s) {
        let str2 = desc.to_string();
        let desc2: Miniscript<String, Tap> = Miniscript::<String, Tap>::from_str(&str2).unwrap();

        assert_eq!(desc, desc2);
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
