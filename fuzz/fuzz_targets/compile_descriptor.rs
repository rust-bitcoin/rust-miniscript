// SPDX-License-Identifier: CC0-1.0

#![cfg_attr(fuzzing, no_main)]

use std::str::FromStr;

use miniscript::{policy, Miniscript, Segwitv0};
use policy::Liftable;

type Script = Miniscript<String, Segwitv0>;
type Policy = policy::Concrete<String>;

fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data);
    if let Ok(pol) = Policy::from_str(&data_str) {
        // Compile
        if let Ok(desc) = pol.compile::<Segwitv0>() {
            // Lift
            assert_eq!(desc.lift().unwrap().sorted(), pol.lift().unwrap().sorted());
            // Try to roundtrip the output of the compiler
            let output = desc.to_string();
            if let Ok(desc) = Script::from_str(&output) {
                let rtt = desc.to_string();
                assert_eq!(output.to_lowercase(), rtt.to_lowercase());
            } else {
                panic!("compiler output something unparseable: {}", output)
            }
        }
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
