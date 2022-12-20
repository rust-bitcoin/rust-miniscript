extern crate miniscript;
extern crate regex;

use regex::Regex;
use std::str::FromStr;

use miniscript::dummy;
use miniscript::Miniscript;
use miniscript::Segwitv0;

fn do_test(data: &[u8]) {
    let s = String::from_utf8_lossy(data);
    if let Ok(desc) = Miniscript::<dummy::Key, Segwitv0>::from_str(&s) {
        let str2 = desc.to_string();
        let desc2 = Miniscript::<dummy::Key, Segwitv0>::from_str(&str2).unwrap();

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
    fn extend_vec_from_hex(hex: &str, out: &mut Vec<u8>) {
        let mut b = 0;
        for (idx, c) in hex.as_bytes().iter().enumerate() {
            b <<= 4;
            match *c {
                b'A'...b'F' => b |= c - b'A' + 10,
                b'a'...b'f' => b |= c - b'a' + 10,
                b'0'...b'9' => b |= c - b'0',
                _ => panic!("Bad hex"),
            }
            if (idx & 1) == 1 {
                out.push(b);
                b = 0;
            }
        }
    }

    #[test]
    fn duplicate_crash() {
        let mut a = Vec::new();
        extend_vec_from_hex("1479002d00000020323731363342740000004000000000000000000000000000000000000063630004636363639c00000000000000000000", &mut a);
        super::do_test(&a);
    }
}
