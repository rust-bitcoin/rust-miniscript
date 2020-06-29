extern crate miniscript;
extern crate regex;

use miniscript::{Descriptor, DummyKey};
use regex::Regex;
use std::str::FromStr;

fn do_test(data: &[u8]) {
    let s = String::from_utf8_lossy(data);
    if let Ok(desc) = Descriptor::<DummyKey>::from_str(&s) {
        let output = desc.to_string();

        let multi_wrap_pk_re = Regex::new("([a-z]+)c:pk_k\\(").unwrap();
        let multi_wrap_pkh_re = Regex::new("([a-z]+)c:pk_h\\(").unwrap();

        let normalize_aliases = multi_wrap_pk_re.replace_all(&s, "$1:pk(");
        let normalize_aliases = multi_wrap_pkh_re.replace_all(&normalize_aliases, "$1:pkh(");
        let normalize_aliases = normalize_aliases
            .replace("c:pk_k(", "pk(")
            .replace("c:pk_h(", "pkh(");

        assert_eq!(normalize_aliases.to_lowercase(), output.to_lowercase());
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
