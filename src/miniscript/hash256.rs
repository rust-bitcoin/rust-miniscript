// Miniscript
// Written in 2022 by
//     Sanket Kanjalkar <sanket1729@gmail.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Hash256 type
//!
//! This module is _identical_ in functionality to the `bitcoin_hashes::sha256d` hash type
//! but the `FromHex/FromStr` and `ToHex/Display` implementations use `DISPLAY_BACKWARDS = false`.
//!
use core::ops::Index;
use core::slice::SliceIndex;
use core::str;

use bitcoin::hashes::{
    self, borrow_slice_impl, hex, hex_fmt_impl, serde_impl, sha256, Hash as HashTrait,
};

/// Output of the SHA256d hash function
#[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Hash([u8; 32]);

hex_fmt_impl!(Debug, Hash);
hex_fmt_impl!(Display, Hash);
hex_fmt_impl!(LowerHex, Hash);
serde_impl!(Hash, 32);
borrow_slice_impl!(Hash);

impl<I: SliceIndex<[u8]>> Index<I> for Hash {
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        &self.0[index]
    }
}

impl str::FromStr for Hash {
    type Err = hex::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        hex::FromHex::from_hex(s)
    }
}

impl HashTrait for Hash {
    type Engine = sha256::HashEngine;
    type Inner = [u8; 32];

    fn engine() -> sha256::HashEngine {
        sha256::Hash::engine()
    }

    fn from_engine(e: sha256::HashEngine) -> Hash {
        let sha2 = sha256::Hash::from_engine(e);
        let sha2d = sha256::Hash::hash(&sha2[..]);

        let mut ret = [0; 32];
        ret.copy_from_slice(&sha2d[..]);
        Hash(ret)
    }

    const LEN: usize = 32;

    fn from_slice(sl: &[u8]) -> Result<Hash, hashes::Error> {
        if sl.len() != 32 {
            Err(hashes::Error::InvalidLength(Self::LEN, sl.len()))
        } else {
            let mut ret = [0; 32];
            ret.copy_from_slice(sl);
            Ok(Hash(ret))
        }
    }

    /// sha256d has DISPLAY_BACKWARD as true
    const DISPLAY_BACKWARD: bool = false;

    fn into_inner(self) -> Self::Inner {
        self.0
    }

    fn as_inner(&self) -> &Self::Inner {
        &self.0
    }

    fn from_inner(inner: Self::Inner) -> Self {
        Hash(inner)
    }

    fn all_zeros() -> Self {
        Self([0u8; 32])
    }
}
