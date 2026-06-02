#![allow(unexpected_cfgs)]

use std::str::FromStr;

use honggfuzz::fuzz;
use miniscript::policy;

type Policy = policy::Semantic<String>;

fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data);
    let is_legacy = !data_str.starts_with('(')
        && !data_str.contains('∧')
        && !data_str.contains('∨')
        && !data_str.contains("#{");
    if is_legacy {
        return;
    }
    if let Ok(pol) = Policy::from_str(&data_str) {
        let output = pol.to_string();
        let strip_ws: fn(&str) -> String = |s| s.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(strip_ws(&data_str), strip_ws(&output));
    }
}

fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}
