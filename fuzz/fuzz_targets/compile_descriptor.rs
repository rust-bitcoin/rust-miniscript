extern crate miniscript;

use miniscript::Segwitv0;
use miniscript::{policy, DummyKey, Miniscript};
use policy::Liftable;

use std::str::FromStr;

type DummyScript = Miniscript<DummyKey, Segwitv0>;
type DummyPolicy = policy::Concrete<DummyKey>;

fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data);
    if let Ok(pol) = DummyPolicy::from_str(&data_str) {
        // Compile
        if let Ok(desc) = pol.compile::<Segwitv0>() {
            // Lift
            assert_eq!(desc.clone().lift(), pol.clone().lift());
            // Try to roundtrip the output of the compiler
            let output = desc.to_string();
            if let Ok(desc) = DummyScript::from_str(&output) {
                let rtt = desc.to_string();
                assert_eq!(output.to_lowercase(), rtt.to_lowercase());
            } else {
                panic!("compiler output something unparseable: {}", output)
            }
        }
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
