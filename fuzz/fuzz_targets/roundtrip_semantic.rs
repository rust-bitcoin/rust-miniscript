use std::str::FromStr;

use honggfuzz::fuzz;
use miniscript::policy;

type Policy = policy::Semantic<String>;

fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data);
    if let Ok(pol) = Policy::from_str(&data_str) {
        let output = pol.to_string();
        assert_eq!(data_str.to_lowercase(), output.to_lowercase());
    }
}

fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}
