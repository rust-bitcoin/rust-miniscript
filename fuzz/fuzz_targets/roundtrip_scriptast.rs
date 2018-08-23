
extern crate bitcoin;
extern crate script_descriptor;
extern crate secp256k1;

use bitcoin::blockdata::script;
use script_descriptor::ParseTree;

fn do_test(data: &[u8]) {
    if data.len() > 50 {
        return;
    }

    let script = script::Script::from(data.to_owned());

    if let Ok(pt) = ParseTree::parse(&script) {
        let output = pt.serialize();
        println!("{:?}", pt);
        assert_eq!(output, script);
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
        extend_vec_from_hex("048531e80700ae6400670000af5168", &mut a);
        super::do_test(&a);
    }
}
