use honggfuzz::fuzz;
use miniscript::bitcoin::blockdata::script;
use miniscript::{Miniscript, Segwitv0};

fn do_test(data: &[u8]) {
    // Try round-tripping as a script
    let script = script::Script::from_bytes(data);

    if let Ok(pt) = Miniscript::<miniscript::bitcoin::PublicKey, Segwitv0>::parse(script) {
        let output = pt.encode();
        assert_eq!(pt.script_size(), output.len());
        assert_eq!(&output, script);
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
    fn duplicate_crash3() {
        let mut a = Vec::new();
        extend_vec_from_hex("1479002d00000020323731363342740000004000000000000000000000000000000000000063630004636363639c00000000000000000000", &mut a);
        super::do_test(&a);
    }
}
