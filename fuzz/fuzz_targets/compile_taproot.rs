#![allow(unexpected_cfgs)]

use std::str::FromStr;

use honggfuzz::fuzz;
use miniscript::{policy, Miniscript, Tap};
use policy::Liftable;

type Script = Miniscript<String, Tap>;
type Policy = policy::Concrete<String>;

fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data);
    if let Ok(pol) = Policy::from_str(&data_str) {
        // Compile
        if let Ok(desc) = pol.compile::<Tap>() {
            // Lift
            assert_eq!(desc.lift().unwrap().sorted(), pol.lift().unwrap().sorted());
            // Try to roundtrip the output of the compiler
            let output = desc.to_string();
            if let Ok(desc) = Script::from_str(&output) {
                let rtt = desc.to_string();
                assert_eq!(output.to_lowercase(), rtt.to_lowercase());
            } else {
                panic!("compiler output something unparsable: {}", output)
            }
        }
    }
}

fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}
