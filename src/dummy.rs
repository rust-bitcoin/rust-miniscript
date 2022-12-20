//!  types sometimes useful for testing.

use core::str::FromStr;
use core::{fmt, hash, str};

use bitcoin::hashes::{hash160, ripemd160, sha256};

use crate::miniscript::hash256;
use crate::{MiniscriptKey, ToPublicKey};

/// Dummy key which de/serializes to the empty string; useful sometimes for testing
#[derive(Copy, Clone, PartialOrd, Ord, Debug, Default)]
pub struct Key;

impl str::FromStr for Key {
    type Err = &'static str;
    fn from_str(x: &str) -> Result<Key, &'static str> {
        if x.is_empty() {
            Ok(Key)
        } else {
            Err("non empty dummy key")
        }
    }
}

impl MiniscriptKey for Key {
    type Sha256 = Sha256Hash;
    type Hash256 = Hash256Hash;
    type Ripemd160 = Ripemd160Hash;
    type Hash160 = Hash160Hash;

    fn num_der_paths(&self) -> usize {
        0
    }
}

impl hash::Hash for Key {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        "Key".hash(state);
    }
}

impl PartialEq for Key {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for Key {}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("")
    }
}

impl ToPublicKey for Key {
    fn to_public_key(&self) -> bitcoin::PublicKey {
        bitcoin::PublicKey::from_str(
            "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352",
        )
        .unwrap()
    }

    fn to_sha256(_hash: &Sha256Hash) -> sha256::Hash {
        sha256::Hash::from_str("50863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352")
            .unwrap()
    }

    fn to_hash256(_hash: &Hash256Hash) -> hash256::Hash {
        hash256::Hash::from_str("50863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352")
            .unwrap()
    }

    fn to_ripemd160(_: &Ripemd160Hash) -> ripemd160::Hash {
        ripemd160::Hash::from_str("f54a5851e9372b87810a8e60cdd2e7cfd80b6e31").unwrap()
    }

    fn to_hash160(_: &Hash160Hash) -> hash160::Hash {
        hash160::Hash::from_str("f54a5851e9372b87810a8e60cdd2e7cfd80b6e31").unwrap()
    }
}

/// Dummy keyhash which de/serializes to the empty string; useful sometimes for testing
#[derive(Copy, Clone, PartialOrd, Ord, Debug, Default)]
pub struct KeyHash;

impl str::FromStr for KeyHash {
    type Err = &'static str;
    fn from_str(x: &str) -> Result<KeyHash, &'static str> {
        if x.is_empty() {
            Ok(KeyHash)
        } else {
            Err("non empty dummy key")
        }
    }
}

impl fmt::Display for KeyHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("")
    }
}

impl hash::Hash for KeyHash {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        "KeyHash".hash(state);
    }
}

impl PartialEq for KeyHash {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for KeyHash {}

/// Dummy keyhash which de/serializes to the empty string; useful for testing
#[derive(Copy, Clone, PartialOrd, Ord, Debug, Default)]
pub struct Sha256Hash;

impl str::FromStr for Sha256Hash {
    type Err = &'static str;
    fn from_str(x: &str) -> Result<Sha256Hash, &'static str> {
        if x.is_empty() {
            Ok(Sha256Hash)
        } else {
            Err("non empty dummy hash")
        }
    }
}

impl fmt::Display for Sha256Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("")
    }
}

impl hash::Hash for Sha256Hash {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        "Sha256Hash".hash(state);
    }
}

impl PartialEq for Sha256Hash {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for Sha256Hash {}

/// Dummy keyhash which de/serializes to the empty string; useful for testing
#[derive(Copy, Clone, PartialOrd, Ord, Debug, Default)]
pub struct Hash256Hash;

impl str::FromStr for Hash256Hash {
    type Err = &'static str;
    fn from_str(x: &str) -> Result<Hash256Hash, &'static str> {
        if x.is_empty() {
            Ok(Hash256Hash)
        } else {
            Err("non empty dummy hash")
        }
    }
}

impl fmt::Display for Hash256Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("")
    }
}

impl hash::Hash for Hash256Hash {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        "Sha256Hash".hash(state);
    }
}

impl PartialEq for Hash256Hash {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for Hash256Hash {}

/// Dummy keyhash which de/serializes to the empty string; useful for testing
#[derive(Copy, Clone, PartialOrd, Ord, Debug, Default)]
pub struct Ripemd160Hash;

impl str::FromStr for Ripemd160Hash {
    type Err = &'static str;
    fn from_str(x: &str) -> Result<Ripemd160Hash, &'static str> {
        if x.is_empty() {
            Ok(Ripemd160Hash)
        } else {
            Err("non empty dummy hash")
        }
    }
}

impl fmt::Display for Ripemd160Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("")
    }
}

impl hash::Hash for Ripemd160Hash {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        "Ripemd160Hash".hash(state);
    }
}

impl PartialEq for Ripemd160Hash {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for Ripemd160Hash {}

/// Dummy keyhash which de/serializes to the empty string; useful for testing
#[derive(Copy, Clone, PartialOrd, Ord, Debug, Default)]
pub struct Hash160Hash;

impl str::FromStr for Hash160Hash {
    type Err = &'static str;
    fn from_str(x: &str) -> Result<Hash160Hash, &'static str> {
        if x.is_empty() {
            Ok(Hash160Hash)
        } else {
            Err("non empty dummy hash")
        }
    }
}

impl fmt::Display for Hash160Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("")
    }
}

impl hash::Hash for Hash160Hash {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        "Hash160Hash".hash(state);
    }
}

impl PartialEq for Hash160Hash {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for Hash160Hash {}
