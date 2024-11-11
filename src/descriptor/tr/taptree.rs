// SPDX-License-Identifier: CC0-1.0

use bitcoin::taproot::{LeafVersion, TapLeafHash};

use crate::miniscript::context::Tap;
use crate::sync::Arc;
use crate::{Miniscript, MiniscriptKey, ToPublicKey};

/// Iterator over all of the leaves of a Taproot tree.
///
/// If there is no tree (i.e. this is a keyspend-only Taproot descriptor)
/// then the iterator will yield nothing.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TapTreeIterItem<'tr, Pk: MiniscriptKey> {
    pub(super) node: &'tr Arc<Miniscript<Pk, Tap>>,
    pub(super) depth: u8,
}

impl<'tr, Pk: MiniscriptKey> TapTreeIterItem<'tr, Pk> {
    /// The Tapscript in the leaf.
    ///
    /// To obtain a [`bitcoin::Script`] from this node, call [`Miniscript::encode`]
    /// on the returned value.
    #[inline]
    pub fn miniscript(&self) -> &'tr Arc<Miniscript<Pk, Tap>> { self.node }

    /// The depth of this leaf.
    ///
    /// This is useful for reconstructing the shape of the tree.
    #[inline]
    pub fn depth(&self) -> u8 { self.depth }

    /// The Tapleaf version of this leaf.
    ///
    /// This function returns a constant value, since there is only one version in use
    /// on the Bitcoin network; however, it may be useful to use this method in case
    /// you wish to be forward-compatible with future versions supported by this
    /// library.
    #[inline]
    pub fn leaf_version(&self) -> LeafVersion { LeafVersion::TapScript }
}

impl<Pk: ToPublicKey> TapTreeIterItem<'_, Pk> {
    /// Computes the Bitcoin Script of the leaf.
    ///
    /// This function is potentially expensive.
    #[inline]
    pub fn compute_script(&self) -> bitcoin::ScriptBuf { self.node.encode() }

    /// Computes the [`TapLeafHash`] of the leaf.
    ///
    /// This function is potentially expensive, since it serializes the full Bitcoin
    /// Script of the leaf and hashes this data.
    #[inline]
    pub fn compute_tap_leaf_hash(&self) -> TapLeafHash {
        TapLeafHash::from_script(&self.compute_script(), self.leaf_version())
    }
}
