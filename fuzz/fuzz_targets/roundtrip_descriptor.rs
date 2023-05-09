use std::str::FromStr;

use honggfuzz::fuzz;
use miniscript::Descriptor;

fn do_test(data: &[u8]) {
    let s = String::from_utf8_lossy(data);
    if let Ok(desc) = Descriptor::<String>::from_str(&s) {
        let str2 = desc.to_string();
        let desc2 = Descriptor::<String>::from_str(&str2).unwrap();

        assert_eq!(desc, desc2);
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
    use super::*;
    #[test]
    fn test() {
        do_test(b"pkh()");
    }
}
