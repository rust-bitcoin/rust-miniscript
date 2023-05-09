use std::str::FromStr;

use honggfuzz::fuzz;
use miniscript::policy;
use regex::Regex;

type Policy = policy::Concrete<String>;

fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data);
    if let Ok(pol) = Policy::from_str(&data_str) {
        let output = pol.to_string();
        //remove all instances of 1@
        let re = Regex::new("(\\D)1@").unwrap();
        let output = re.replace_all(&output, "$1");
        let data_str = re.replace_all(&data_str, "$1");
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

#[cfg(test)]
mod tests {
    fn extend_vec_from_hex(hex: &str, out: &mut Vec<u8>) {
        let mut b = 0;
        for (idx, c) in hex.as_bytes().iter().enumerate() {
            b <<= 4;
            match *c {
                b'A'..=b'F' => b |= c - b'A' + 10,
                b'a'..=b'f' => b |= c - b'a' + 10,
                b'0'..=b'9' => b |= c - b'0',
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
        extend_vec_from_hex("048531e80700ae6400670000af5168", &mut a);
        super::do_test(&a);
    }
}
