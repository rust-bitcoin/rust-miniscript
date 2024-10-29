// SPDX-License-Identifier: CC0-1.0

//! A map of public key to secret key.

use core::iter;

use bitcoin::secp256k1::{Secp256k1, Signing};

#[cfg(doc)]
use super::Descriptor;
use super::{DescriptorKeyParseError, DescriptorPublicKey, DescriptorSecretKey};
use crate::prelude::{btree_map, BTreeMap};

/// Alias type for a map of public key to secret key.
///
/// This map is returned whenever a descriptor that contains secrets is parsed using
/// [`Descriptor::parse_descriptor`], since the descriptor will always only contain
/// public keys. This map allows looking up the corresponding secret key given a
/// public key from the descriptor.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KeyMap {
    map: BTreeMap<DescriptorPublicKey, DescriptorSecretKey>,
}

impl KeyMap {
    /// Creates a new empty `KeyMap`.
    #[inline]
    pub fn new() -> Self { Self { map: BTreeMap::new() } }

    /// Inserts secret key into key map returning the associated public key.
    #[inline]
    pub fn insert<C: Signing>(
        &mut self,
        secp: &Secp256k1<C>,
        sk: DescriptorSecretKey,
    ) -> Result<DescriptorPublicKey, DescriptorKeyParseError> {
        let pk = sk.to_public(secp)?;
        if !self.map.contains_key(&pk) {
            self.map.insert(pk.clone(), sk);
        }
        Ok(pk)
    }

    /// Gets the secret key associated with `pk` if `pk` is in the map.
    #[inline]
    pub fn get(&self, pk: &DescriptorPublicKey) -> Option<&DescriptorSecretKey> { self.map.get(pk) }

    /// Returns the number of items in this map.
    #[inline]
    pub fn len(&self) -> usize { self.map.len() }

    /// Returns true if the map is empty.
    #[inline]
    pub fn is_empty(&self) -> bool { self.map.is_empty() }
}

impl Default for KeyMap {
    fn default() -> Self { Self::new() }
}

impl IntoIterator for KeyMap {
    type Item = (DescriptorPublicKey, DescriptorSecretKey);
    type IntoIter = btree_map::IntoIter<DescriptorPublicKey, DescriptorSecretKey>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter { self.map.into_iter() }
}

impl iter::Extend<(DescriptorPublicKey, DescriptorSecretKey)> for KeyMap {
    #[inline]
    fn extend<T>(&mut self, iter: T)
    where
        T: IntoIterator<Item = (DescriptorPublicKey, DescriptorSecretKey)>,
    {
        self.map.extend(iter)
    }
}
