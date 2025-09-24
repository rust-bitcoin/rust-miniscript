// SPDX-License-Identifier: CC0-1.0b

#![cfg_attr(fuzzing, no_main)]

use std::str::FromStr;

use miniscript::policy;

type Policy = policy::Semantic<String>;

fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data);
    if let Ok(pol) = Policy::from_str(&data_str) {
        let output = pol.to_string();
        assert_eq!(data_str.to_lowercase(), output.to_lowercase());
    }
}

#[cfg(fuzzing)]
libfuzzer_sys::fuzz_target!(|data| { do_test(data); });

#[cfg(not(fuzzing))]
fn main() { do_test(&[]); }
