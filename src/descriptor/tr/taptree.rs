// SPDX-License-Identifier: CC0-1.0

use bitcoin::taproot::{LeafVersion, TapLeafHash};

use super::TapTree;
use crate::miniscript::context::Tap;
use crate::prelude::Vec;
use crate::sync::Arc;
use crate::{Miniscript, MiniscriptKey, ToPublicKey};

/// Iterator over the leaves of a Taptree.
///
/// Yields a pair of (depth, miniscript) in a depth first walk
/// For example, this tree:
///                                     - N0 -
///                                    /     \\
///                                   N1      N2
///                                  /  \    /  \\
///                                 A    B  C   N3
///                                            /  \\
///                                           D    E
/// would yield (2, A), (2, B), (2,C), (3, D), (3, E).
///
#[derive(Debug, Clone)]
pub struct TapTreeIter<'a, Pk: MiniscriptKey> {
    stack: Vec<(u8, &'a TapTree<Pk>)>,
}

impl<'tr, Pk: MiniscriptKey> TapTreeIter<'tr, Pk> {
    /// An empty iterator.
    pub fn empty() -> Self { Self { stack: vec![] } }

    /// An iterator over a given tree.
    pub(super) fn from_tree(tree: &'tr TapTree<Pk>) -> Self { Self { stack: vec![(0, tree)] } }
}

impl<'a, Pk> Iterator for TapTreeIter<'a, Pk>
where
    Pk: MiniscriptKey + 'a,
{
    type Item = TapTreeIterItem<'a, Pk>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some((depth, last)) = self.stack.pop() {
            match *last {
                TapTree::Tree { ref left, ref right, height: _ } => {
                    self.stack.push((depth + 1, right));
                    self.stack.push((depth + 1, left));
                }
                TapTree::Leaf(ref ms) => return Some(TapTreeIterItem { node: ms, depth }),
            }
        }
        None
    }
}

/// Iterator over all of the leaves of a Taproot tree.
///
/// If there is no tree (i.e. this is a keyspend-only Taproot descriptor)
/// then the iterator will yield nothing.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TapTreeIterItem<'tr, Pk: MiniscriptKey> {
    node: &'tr Arc<Miniscript<Pk, Tap>>,
    depth: u8,
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
