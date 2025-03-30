// SPDX-License-Identifier: CC0-1.0

use core::{cmp, fmt};

use bitcoin::taproot::{LeafVersion, TapLeafHash};

use crate::miniscript::context::Tap;
use crate::prelude::Vec;
use crate::sync::Arc;
use crate::{Miniscript, MiniscriptKey, ToPublicKey, TranslateErr, Translator};

/// A Taproot Tree representation.
// Hidden leaves are not yet supported in descriptor spec. Conceptually, it should
// be simple to integrate those here, but it is best to wait on core for the exact syntax.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum TapTree<Pk: MiniscriptKey> {
    /// A taproot tree structure
    Tree {
        /// Left tree branch.
        left: Arc<TapTree<Pk>>,
        /// Right tree branch.
        right: Arc<TapTree<Pk>>,
        /// Tree height, defined as `1 + max(left_height, right_height)`.
        height: usize,
    },
    /// A taproot leaf denoting a spending condition
    // A new leaf version would require a new Context, therefore there is no point
    // in adding a LeafVersion with Leaf type here. All Miniscripts right now
    // are of Leafversion::default
    Leaf(Arc<Miniscript<Pk, Tap>>),
}

impl<Pk: MiniscriptKey> TapTree<Pk> {
    /// Creates a `TapTree` by combining `left` and `right` tree nodes.
    pub fn combine(left: TapTree<Pk>, right: TapTree<Pk>) -> Self {
        let height = 1 + cmp::max(left.height(), right.height());
        TapTree::Tree { left: Arc::new(left), right: Arc::new(right), height }
    }

    /// Returns the height of this tree.
    pub fn height(&self) -> usize {
        match *self {
            TapTree::Tree { left: _, right: _, height } => height,
            TapTree::Leaf(..) => 0,
        }
    }

    /// Iterates over all miniscripts in DFS walk order compatible with the
    /// PSBT requirements (BIP 371).
    pub fn iter(&self) -> TapTreeIter<Pk> { TapTreeIter::from_tree(self) }

    // Helper function to translate keys
    pub(super) fn translate_helper<T>(
        &self,
        t: &mut T,
    ) -> Result<TapTree<T::TargetPk>, TranslateErr<T::Error>>
    where
        T: Translator<Pk>,
    {
        let frag = match *self {
            TapTree::Tree { ref left, ref right, ref height } => TapTree::Tree {
                left: Arc::new(left.translate_helper(t)?),
                right: Arc::new(right.translate_helper(t)?),
                height: *height,
            },
            TapTree::Leaf(ref ms) => TapTree::Leaf(Arc::new(ms.translate_pk(t)?)),
        };
        Ok(frag)
    }
}

impl<Pk: MiniscriptKey> fmt::Display for TapTree<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TapTree::Tree { ref left, ref right, height: _ } => {
                write!(f, "{{{},{}}}", *left, *right)
            }
            TapTree::Leaf(ref script) => write!(f, "{}", *script),
        }
    }
}

impl<Pk: MiniscriptKey> fmt::Debug for TapTree<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TapTree::Tree { ref left, ref right, height: _ } => {
                write!(f, "{{{:?},{:?}}}", *left, *right)
            }
            TapTree::Leaf(ref script) => write!(f, "{:?}", *script),
        }
    }
}

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
    fn from_tree(tree: &'tr TapTree<Pk>) -> Self { Self { stack: vec![(0, tree)] } }
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
