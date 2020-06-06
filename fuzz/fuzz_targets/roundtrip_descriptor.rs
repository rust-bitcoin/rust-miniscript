
extern crate miniscript;

use miniscript::{Descriptor, DummyKey};

use std::str::FromStr;

fn do_test(data: &[u8]) {
    let s = String::from_utf8_lossy(data);
    if let Ok(desc) = Descriptor::<DummyKey>::from_str(&s) {
        let output = desc.to_string();
        let normalize_aliases = s.replace("c:pk_k(", "pk(");
        assert_eq!(normalize_aliases, output);
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