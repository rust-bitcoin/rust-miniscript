// Written in 2019 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Miniscript Fuzzing Library
//!
//! This contains data structures and utilities used by the fuzz tests.

use core::{fmt, str};

use miniscript::bitcoin::hashes::{hash160, ripemd160, sha256, Hash};
use miniscript::bitcoin::{secp256k1, PublicKey};
use miniscript::{hash256, MiniscriptKey, ToPublicKey};

/// A public key which is encoded as a single hex byte (two hex characters).
///
/// Implements `ToPublicKey` but (for now) always maps to the same bitcoin public key.
#[derive(Clone, PartialOrd, Ord, PartialEq, Eq, Debug, Hash)]
pub struct FuzzPk {
    compressed: bool,
}

impl FuzzPk {
    pub fn new_from_control_byte(control: u8) -> Self { Self { compressed: control & 1 == 1 } }
}

impl str::FromStr for FuzzPk {
    type Err = std::num::ParseIntError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let byte = u8::from_str_radix(s, 16)?;
        Ok(Self::new_from_control_byte(byte))
    }
}

impl fmt::Display for FuzzPk {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { "[fuzz pubkey]".fmt(f) }
}

impl MiniscriptKey for FuzzPk {
    type Sha256 = u8;
    type Ripemd160 = u8;
    type Hash160 = u8;
    type Hash256 = u8;
}

impl ToPublicKey for FuzzPk {
    fn to_public_key(&self) -> PublicKey {
        let secp_pk = secp256k1::PublicKey::from_slice(&[
            0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3b, 0x78,
            0xce, 0x56, 0x3f, 0x89, 0xa0, 0xed, 0x94, 0x14, 0xf5, 0xaa, 0x28, 0xad, 0x0d, 0x96,
            0xd6, 0x79, 0x5f, 0x9c, 0x63, 0x3f, 0x39, 0x79, 0xbf, 0x72, 0xae, 0x82, 0x02, 0x98,
            0x3d, 0xc9, 0x89, 0xae, 0xc7, 0xf2, 0xff, 0x2e, 0xd9, 0x1b, 0xdd, 0x69, 0xce, 0x02,
            0xfc, 0x07, 0x00, 0xca, 0x10, 0x0e, 0x59, 0xdd, 0xf3,
        ])
        .unwrap();
        PublicKey { inner: secp_pk, compressed: self.compressed }
    }

    fn to_sha256(hash: &Self::Sha256) -> sha256::Hash { sha256::Hash::from_byte_array([*hash; 32]) }

    fn to_hash256(hash: &Self::Hash256) -> hash256::Hash {
        hash256::Hash::from_byte_array([*hash; 32])
    }

    fn to_ripemd160(hash: &Self::Ripemd160) -> ripemd160::Hash {
        ripemd160::Hash::from_byte_array([*hash; 20])
    }

    fn to_hash160(hash: &Self::Ripemd160) -> hash160::Hash {
        hash160::Hash::from_byte_array([*hash; 20])
    }
}

impl old_miniscript::MiniscriptKey for FuzzPk {
    type Sha256 = u8;
    type Ripemd160 = u8;
    type Hash160 = u8;
    type Hash256 = u8;
}

impl old_miniscript::ToPublicKey for FuzzPk {
    fn to_public_key(&self) -> PublicKey {
        let secp_pk = secp256k1::PublicKey::from_slice(&[
            0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3b, 0x78,
            0xce, 0x56, 0x3f, 0x89, 0xa0, 0xed, 0x94, 0x14, 0xf5, 0xaa, 0x28, 0xad, 0x0d, 0x96,
            0xd6, 0x79, 0x5f, 0x9c, 0x63, 0x3f, 0x39, 0x79, 0xbf, 0x72, 0xae, 0x82, 0x02, 0x98,
            0x3d, 0xc9, 0x89, 0xae, 0xc7, 0xf2, 0xff, 0x2e, 0xd9, 0x1b, 0xdd, 0x69, 0xce, 0x02,
            0xfc, 0x07, 0x00, 0xca, 0x10, 0x0e, 0x59, 0xdd, 0xf3,
        ])
        .unwrap();
        PublicKey { inner: secp_pk, compressed: self.compressed }
    }

    fn to_sha256(hash: &Self::Sha256) -> sha256::Hash { sha256::Hash::from_byte_array([*hash; 32]) }

    fn to_hash256(hash: &Self::Hash256) -> old_miniscript::hash256::Hash {
        old_miniscript::hash256::Hash::from_byte_array([*hash; 32])
    }

    fn to_ripemd160(hash: &Self::Ripemd160) -> ripemd160::Hash {
        ripemd160::Hash::from_byte_array([*hash; 20])
    }

    fn to_hash160(hash: &Self::Ripemd160) -> hash160::Hash {
        hash160::Hash::from_byte_array([*hash; 20])
    }
}
