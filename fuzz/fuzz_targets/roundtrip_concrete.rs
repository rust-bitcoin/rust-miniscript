// SPDX-License-Identifier: CC0-1.0

#![cfg_attr(fuzzing, no_main)]

use std::str::FromStr;

use miniscript::policy;
use regex::Regex;

type Policy = policy::Concrete<String>;

fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data);
    if let Ok(pol) = Policy::from_str(&data_str) {
        let output = pol.to_string();
        //remove all instances of 1@
        let re = Regex::new("(\\D)1@").unwrap();
        let output = re.replace_all(&output, "$1");
        let data_str = re.replace_all(&data_str, "$1");
        assert_eq!(data_str.to_lowercase(), output.to_lowercase());
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
