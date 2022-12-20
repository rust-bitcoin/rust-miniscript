extern crate miniscript;
extern crate regex;

use miniscript::Descriptor;
use miniscript::dummy;
use regex::Regex;
use std::str::FromStr;

fn do_test(data: &[u8]) {
    let s = String::from_utf8_lossy(data);
    if let Ok(desc) = Descriptor::<dummy::Key>::from_str(&s) {
        let str2 = desc.to_string();
        let desc2 = Descriptor::<dummy::Key>::from_str(&str2).unwrap();

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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test() {
        do_test(b"pkh()");
    }
}
