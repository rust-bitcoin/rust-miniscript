
extern crate miniscript;
extern crate regex;

use std::str::FromStr;
use miniscript::{policy, DummyKey};
use regex::Regex;

type DummyPolicy = policy::Concrete<DummyKey>;
type DummyPolicy2 = policy::Semantic<DummyKey>;

fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data);
    if let Ok(pol) = DummyPolicy::from_str(&data_str) {
        let output = pol.to_string();
        //remove all instances of 1@
        let re = Regex::new("(\\D)1@").unwrap();
        let output = re.replace_al  l(&output, "$1");
        let data_str = re.replace_all(&data_str, "$1");
        assert_eq!(data_str, output);
    }
    if let Ok(pol) = DummyPolicy2::from_str(&data_str) {
        let output = pol.to_string();
        assert_eq!(data_str, output);
    }
}

#[cfg(feature = "afl")]
extern crate afl;
#[cfg(feature = "afl")]
fn main() {
    afl::read_stdio_bytes(|data| {
        do_test(&data);
    });
}

#[cfg(feature = "honggfuzz")]
#[macro_use] extern crate honggfuzz;
#[cfg(feature = "honggfuzz")]
fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}
