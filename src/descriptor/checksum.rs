// SPDX-License-Identifier: CC0-1.0

//! Descriptor checksum
//!
//! This module contains a re-implementation of the function used by Bitcoin Core to calculate the
//! checksum of a descriptor. The checksum algorithm is specified in [BIP-380].
//!
//! [BIP-380]: <https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki>

use core::convert::TryFrom;
use core::fmt;
use core::iter::FromIterator;

use bech32::primitives::checksum::PackedFe32;
use bech32::{Checksum, Fe32};

pub use crate::expression::VALID_CHARS;
use crate::prelude::*;
use crate::Error;

const CHECKSUM_LENGTH: usize = 8;
const CODE_LENGTH: usize = 32767;

/// Compute the checksum of a descriptor.
///
/// Note that this function does not check if the descriptor string is
/// syntactically correct or not. This only computes the checksum.
pub fn desc_checksum(desc: &str) -> Result<String, Error> {
    let mut eng = Engine::new();
    eng.input(desc)?;
    Ok(eng.checksum())
}

/// Helper function for `FromStr` for various descriptor types.
///
/// Checks and verifies the checksum if it is present and returns the descriptor
/// string without the checksum.
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

/// An engine to compute a checksum from a string.
pub struct Engine {
    inner: bech32::primitives::checksum::Engine<DescriptorChecksum>,
    cls: u64,
    clscount: u64,
}

impl Default for Engine {
    fn default() -> Engine { Engine::new() }
}

impl Engine {
    /// Constructs an engine with no input.
    pub fn new() -> Self {
        Engine { inner: bech32::primitives::checksum::Engine::new(), cls: 0, clscount: 0 }
    }

    /// Inputs some data into the checksum engine.
    ///
    /// If this function returns an error, the `Engine` will be left in an indeterminate
    /// state! It is safe to continue feeding it data but the result will not be meaningful.
    pub fn input(&mut self, s: &str) -> Result<(), Error> {
        for ch in s.chars() {
            let pos = VALID_CHARS
                .get(ch as usize)
                .ok_or_else(|| {
                    Error::BadDescriptor(format!("Invalid character in checksum: '{}'", ch))
                })?
                .ok_or_else(|| {
                    Error::BadDescriptor(format!("Invalid character in checksum: '{}'", ch))
                })? as u64;

            let fe = Fe32::try_from(pos & 31).expect("pos is valid because of the mask");
            self.inner.input_fe(fe);

            self.cls = self.cls * 3 + (pos >> 5);
            self.clscount += 1;
            if self.clscount == 3 {
                let fe = Fe32::try_from(self.cls).expect("cls is valid");
                self.inner.input_fe(fe);
                self.cls = 0;
                self.clscount = 0;
            }
        }
        Ok(())
    }

    /// Obtains the checksum characters of all the data thus-far fed to the
    /// engine without allocating, to get a string use [`Self::checksum`].
    pub fn checksum_chars(&mut self) -> [char; CHECKSUM_LENGTH] {
        if self.clscount > 0 {
            let fe = Fe32::try_from(self.cls).expect("cls is valid");
            self.inner.input_fe(fe);
        }
        self.inner.input_target_residue();

        let mut chars = [0 as char; CHECKSUM_LENGTH];
        let mut checksum_remaining = CHECKSUM_LENGTH;

        for checksum_ch in &mut chars {
            checksum_remaining -= 1;
            let unpacked = self.inner.residue().unpack(checksum_remaining);
            let fe = Fe32::try_from(unpacked).expect("5 bits fits in an fe32");
            *checksum_ch = fe.to_char();
        }
        chars
    }

    /// Obtains the checksum of all the data thus-far fed to the engine.
    pub fn checksum(&mut self) -> String {
        String::from_iter(self.checksum_chars().iter().copied())
    }
}

/// The Output Script Descriptor checksum algorithm, defined in [BIP-380].
///
/// [BIP-380]: <https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki>
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum DescriptorChecksum {}

/// Generator coefficients, taken from BIP-380.
#[rustfmt::skip]
const GEN: [u64; 5] = [0xf5dee51989, 0xa9fdca3312, 0x1bab10e32d, 0x3706b1677a, 0x644d626ffd];

impl Checksum for DescriptorChecksum {
    type MidstateRepr = u64; // We need 40 bits (8 * 5).
    const CHECKSUM_LENGTH: usize = CHECKSUM_LENGTH;
    const CODE_LENGTH: usize = CODE_LENGTH;
    const GENERATOR_SH: [u64; 5] = GEN;
    const TARGET_RESIDUE: u64 = 1;
}

/// A wrapper around a `fmt::Formatter` which provides checksumming ability.
pub struct Formatter<'f, 'a> {
    fmt: &'f mut fmt::Formatter<'a>,
    eng: Engine,
}

impl<'f, 'a> Formatter<'f, 'a> {
    /// Contructs a new `Formatter`, wrapping a given `fmt::Formatter`.
    pub fn new(f: &'f mut fmt::Formatter<'a>) -> Self { Formatter { fmt: f, eng: Engine::new() } }

    /// Writes the checksum into the underlying `fmt::Formatter`.
    pub fn write_checksum(&mut self) -> fmt::Result {
        use fmt::Write;
        self.fmt.write_char('#')?;
        for ch in self.eng.checksum_chars().iter().copied() {
            self.fmt.write_char(ch)?;
        }
        Ok(())
    }

    /// Writes the checksum into the underlying `fmt::Formatter`, unless it has "alternate" display on.
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
            format!("Invalid descriptor: Invalid character in checksum: '{}'", sparkle_heart)
        );
    }

    #[test]
    fn bip_380_test_vectors_checksum_and_character_set_valid() {
        let tcs = vec![
            "raw(deadbeef)#89f8spxm", // Valid checksum.
            "raw(deadbeef)",          // No checksum.
        ];
        for tc in tcs {
            if verify_checksum(tc).is_err() {
                panic!("false negative: {}", tc)
            }
        }
    }

    #[test]
    fn bip_380_test_vectors_checksum_and_character_set_invalid() {
        let tcs = vec![
            "raw(deadbeef)#",          // Missing checksum.
            "raw(deadbeef)#89f8spxmx", // Too long checksum.
            "raw(deadbeef)#89f8spx",   // Too short checksum.
            "raw(dedbeef)#89f8spxm",   // Error in payload.
            "raw(deadbeef)##9f8spxm",  // Error in checksum.
            "raw(Ü)#00000000",         // Invalid characters in payload.
        ];
        for tc in tcs {
            if verify_checksum(tc).is_ok() {
                panic!("false positive: {}", tc)
            }
        }
    }
}
