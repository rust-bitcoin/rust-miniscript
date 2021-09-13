extern crate miniscript;
extern crate regex;

use regex::Regex;
use std::str::FromStr;

use miniscript::DummyKey;
use miniscript::Miniscript;
use miniscript::Segwitv0;

fn do_test(data: &[u8]) {
    let s = String::from_utf8_lossy(data);
    if let Ok(desc) = Miniscript::<DummyKey, Segwitv0>::from_str(&s) {
        let str2 = desc.to_string();
        let desc2 = Miniscript::<DummyKey, Segwitv0>::from_str(&str2).unwrap();

        assert_eq!(desc, desc2);
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
#[macro_use]
extern crate honggfuzz;
#[cfg(feature = "honggfuzz")]
fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}
