
extern crate miniscript;

#[path = "../src/util.rs"] mod util;

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

#[cfg(test)]
mod tests {
    use util::extend_vec_from_hex;

    #[test]
    fn duplicate_crash() {
        let mut a = Vec::new();
        extend_vec_from_hex("00", &mut a);
        super::do_test(&a);
    }

    #[test]
    fn test_cpkk_alias() {
        let mut a = Vec::new();
        extend_vec_from_hex("633a706b5f6b2829", &mut a); // c:pk_k()
        super::do_test(&a);
    }
}
