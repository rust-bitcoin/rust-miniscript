# Fuzz Tests

Repository for fuzz testing Miniscript. 

## How to reproduce crashes?

Travis should output a offending hex("048531e80700ae6400670000af5168" in the example) 
which you can use as shown. Copy and paste the following code lines into file reporting crashes and 
replace the hex with the offending hex. 
Refer to file [roundtrip_concrete.rs](./fuzz_targets/roundtrip_concrete.rs) for an example. 

```
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
```