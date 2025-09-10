// SPDX-License-Identifier: CC0-1.0

#![cfg_attr(fuzzing, no_main)]

use std::str::FromStr;

use miniscript::Descriptor;

fn do_test(data: &[u8]) {
    let s = String::from_utf8_lossy(data);
    if let Ok(desc) = Descriptor::<String>::from_str(&s) {
        let str2 = desc.to_string();
        let desc2 = Descriptor::<String>::from_str(&str2).unwrap();

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
