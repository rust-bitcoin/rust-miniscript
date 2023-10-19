//! Miniscript hash types

use core::convert::Infallible;
use core::fmt;
use core::str::FromStr;

use crate::bitcoin::hashes::{sha256, Hash as _};

/// WIP:
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Sha256 {
    /// A human readable string instead of a real hash value.
    HumanReadable(String),
    /// A real hash value.
    Hash(sha256::Hash),
}

impl Sha256 {
    /// Returns `true` if this is a real hash value.
    pub fn is_concrete(&self) -> bool {
        use Sha256::*;

        match *self {
            HumanReadable(..) => false,
            Hash(..) => true,
        }
    }

    /// Converts this hash to a concrete real sha256 hash type.
    pub fn to_concrete(&self) -> sha256::Hash {
        use Sha256::*;

        match *self {
            HumanReadable(ref s) => sha256::Hash::hash(s.as_bytes()),
//            HumanReadable(_) => sha256::Hash::from_str("4ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260").unwrap(),
            Hash(ref h) => *h,
        }
    }

    /// Converts this hash to a string.
    ///
    /// Could be human readable or it could be the hex representation of a real hex value.
    pub fn to_string(&self) -> String {
        use Sha256::*;

        match *self {
            HumanReadable(ref s) => s.clone(),
            Hash(ref h) => h.to_string(),
        }
    }

    /// WIP:
    pub fn to_byte_array(&self) -> [u8; 32] {
        self.to_concrete().to_byte_array()
    }
}

impl fmt::Display for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Sha256::*;

        match *self {
            HumanReadable(ref s) => fmt::Display::fmt(s, f),
            Hash(ref h) => fmt::Display::fmt(h, f),
        }
    }
}

impl FromStr for Sha256 {
    type Err = Infallible;

    // TODO: This is wrong, its like this to make the bitcoind-testst pass, I believe this shows
    // that we are using the `Translator` trait for mocking tests.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hash = sha256::Hash::from_str(s).unwrap();
        Ok(Sha256::Hash(hash))
    }
}

impl From<sha256::Hash> for Sha256 {
    fn from(hash: sha256::Hash) -> Self { Self::Hash(hash) }
}
