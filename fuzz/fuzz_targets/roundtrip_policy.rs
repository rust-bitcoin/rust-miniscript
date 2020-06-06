
extern crate miniscript;

#[path = "../src/util.rs"] mod util;

use std::str::FromStr;
use miniscript::{policy, DummyKey};

type DummyPolicy = policy::Concrete<DummyKey>;
type DummyPolicy2 = policy::Semantic<DummyKey>;

fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data);
    if let Ok(pol) = DummyPolicy::from_str(&data_str) {
        let output = pol.to_string();
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
    fn duplicate_crash_2() {
        let mut a = Vec::new();
        extend_vec_from_hex("746872657368", &mut a); // thresh
        super::do_test(&a);
    }
}
