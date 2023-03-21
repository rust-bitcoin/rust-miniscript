// SPDX-License-Identifier: CC0-1.0

//! Descriptor checksum
//!
//! This module contains a re-implementation of the function used by Bitcoin Core to calculate the
//! checksum of a descriptor

use core::fmt;
use core::iter::FromIterator;

use crate::prelude::*;
use crate::Error;

const INPUT_CHARSET: &str =  "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const CHECKSUM_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn poly_mod(mut c: u64, val: u64) -> u64 {
    let c0 = c >> 35;

    c = ((c & 0x7ffffffff) << 5) ^ val;
    if c0 & 1 > 0 {
        c ^= 0xf5dee51989
    };
    if c0 & 2 > 0 {
        c ^= 0xa9fdca3312
    };
    if c0 & 4 > 0 {
        c ^= 0x1bab10e32d
    };
    if c0 & 8 > 0 {
        c ^= 0x3706b1677a
    };
    if c0 & 16 > 0 {
        c ^= 0x644d626ffd
    };

    c
}

/// Compute the checksum of a descriptor
/// Note that this function does not check if the
/// descriptor string is syntactically correct or not.
/// This only computes the checksum
pub fn desc_checksum(desc: &str) -> Result<String, Error> {
    let mut eng = Engine::new();
    eng.input(desc)?;
    Ok(eng.checksum())
}

/// Helper function for FromStr for various
/// descriptor types. Checks and verifies the checksum
/// if it is present and returns the descriptor string
/// without the checksum
pub(super) fn verify_checksum(s: &str) -> Result<&str, Error> {
    for ch in s.as_bytes() {
        if *ch < 20 || *ch > 127 {
            return Err(Error::Unprintable(*ch));
        }
    }

    let mut parts = s.splitn(2, '#');
    let desc_str = parts.next().unwrap();
    if let Some(checksum_str) = parts.next() {
        let expected_sum = desc_checksum(desc_str)?;
        if checksum_str != expected_sum {
            return Err(Error::BadDescriptor(format!(
                "Invalid checksum '{}', expected '{}'",
                checksum_str, expected_sum
            )));
        }
    }
    Ok(desc_str)
}

/// An engine to compute a checksum from a string
pub struct Engine {
    c: u64,
    cls: u64,
    clscount: u64,
}

impl Default for Engine {
    fn default() -> Engine {
        Engine::new()
    }
}

impl Engine {
    /// Construct an engine with no input
    pub fn new() -> Self {
        Engine {
            c: 1,
            cls: 0,
            clscount: 0,
        }
    }

    /// Checksum some data
    ///
    /// If this function returns an error, the `Engine` will be left in an indeterminate
    /// state! It is safe to continue feeding it data but the result will not be meaningful.
    pub fn input(&mut self, s: &str) -> Result<(), Error> {
        for ch in s.chars() {
            let pos = INPUT_CHARSET.find(ch).ok_or_else(|| {
                Error::BadDescriptor(format!("Invalid character in checksum: '{}'", ch))
            })? as u64;
            self.c = poly_mod(self.c, pos & 31);
            self.cls = self.cls * 3 + (pos >> 5);
            self.clscount += 1;
            if self.clscount == 3 {
                self.c = poly_mod(self.c, self.cls);
                self.cls = 0;
                self.clscount = 0;
            }
        }
        Ok(())
    }

    /// Obtain the checksum of all the data thus-far fed to the engine
    pub fn checksum_chars(&mut self) -> [char; 8] {
        if self.clscount > 0 {
            self.c = poly_mod(self.c, self.cls);
        }
        (0..8).for_each(|_| self.c = poly_mod(self.c, 0));
        self.c ^= 1;

        let mut chars = [0 as char; 8];
        for j in 0..8 {
            chars[j] = CHECKSUM_CHARSET[((self.c >> (5 * (7 - j))) & 31) as usize] as char;
        }
        chars
    }

    /// Obtain the checksum of all the data thus-far fed to the engine
    pub fn checksum(&mut self) -> String {
        String::from_iter(self.checksum_chars().iter().copied())
    }
}

/// A wrapper around a `fmt::Formatter` which provides checksumming ability
pub struct Formatter<'f, 'a> {
    fmt: &'f mut fmt::Formatter<'a>,
    eng: Engine,
}

impl<'f, 'a> Formatter<'f, 'a> {
    /// Contruct a new `Formatter`, wrapping a given `fmt::Formatter`
    pub fn new(f: &'f mut fmt::Formatter<'a>) -> Self {
        Formatter {
            fmt: f,
            eng: Engine::new(),
        }
    }

    /// Writes the checksum into the underlying `fmt::Formatter`
    pub fn write_checksum(&mut self) -> fmt::Result {
        use fmt::Write;
        self.fmt.write_char('#')?;
        for ch in self.eng.checksum_chars().iter().copied() {
            self.fmt.write_char(ch)?;
        }
        Ok(())
    }

    /// Writes the checksum into the underlying `fmt::Formatter`, unless it has "alternate" display on
    pub fn write_checksum_if_not_alt(&mut self) -> fmt::Result {
        if !self.fmt.alternate() {
            self.write_checksum()?;
        }
        Ok(())
    }
}

impl<'f, 'a> fmt::Write for Formatter<'f, 'a> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.fmt.write_str(s)?;
        self.eng.input(s).map_err(|_| fmt::Error)
    }
}

#[cfg(test)]
mod test {
    use core::str;

    use super::*;

    macro_rules! check_expected {
        ($desc: expr, $checksum: expr) => {
            assert_eq!(desc_checksum($desc).unwrap(), $checksum);
        };
    }

    #[test]
    fn test_valid_descriptor_checksum() {
        check_expected!(
            "wpkh(tprv8ZgxMBicQKsPdpkqS7Eair4YxjcuuvDPNYmKX3sCniCf16tHEVrjjiSXEkFRnUH77yXc6ZcwHHcLNfjdi5qUvw3VDfgYiH5mNsj5izuiu2N/1/2/*)",
            "tqz0nc62"
        );
        check_expected!(
            "pkh(tpubD6NzVbkrYhZ4XHndKkuB8FifXm8r5FQHwrN6oZuWCz13qb93rtgKvD4PQsqC4HP4yhV3tA2fqr2RbY5mNXfM7RxXUoeABoDtsFUq2zJq6YK/44'/1'/0'/0/*)",
            "lasegmfs"
        );

        // https://github.com/bitcoin/bitcoin/blob/7ae86b3c6845873ca96650fc69beb4ae5285c801/src/test/descriptor_tests.cpp#L352-L354
        check_expected!(
            "sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))",
            "ggrsrxfy"
        );
        check_expected!(
            "sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))",
            "tjg09x5t"
        );
    }

    #[test]
    fn test_desc_checksum_invalid_character() {
        let sparkle_heart = vec![240, 159, 146, 150];
        let sparkle_heart = str::from_utf8(&sparkle_heart)
            .unwrap()
            .chars()
            .next()
            .unwrap();
        let invalid_desc = format!("wpkh(tprv8ZgxMBicQKsPdpkqS7Eair4YxjcuuvDPNYmKX3sCniCf16tHEVrjjiSXEkFRnUH77yXc6ZcwHHcL{}fjdi5qUvw3VDfgYiH5mNsj5izuiu2N/1/2/*)", sparkle_heart);

        assert_eq!(
            desc_checksum(&invalid_desc).err().unwrap().to_string(),
            format!(
                "Invalid descriptor: Invalid character in checksum: '{}'",
                sparkle_heart
            )
        );
    }
}
