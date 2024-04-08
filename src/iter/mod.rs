// SPDX-License-Identifier: CC0-1.0

//! Abstract Tree Iteration
//!
//! This module provides functionality to treat Miniscript objects abstractly
//! as trees, iterating over them in various orders. The iterators in this
//! module can be used to avoid explicitly recursive algorithms.
//!

mod tree;

pub use tree::{
    PostOrderIter, PostOrderIterItem, PreOrderIter, PreOrderIterItem, Tree, TreeLike,
    VerbosePreOrderIter,
};

use crate::sync::Arc;
use crate::{Miniscript, MiniscriptKey, ScriptContext, Terminal};

impl<'a, Pk: MiniscriptKey, Ctx: ScriptContext> TreeLike for &'a Miniscript<Pk, Ctx> {
    fn as_node(&self) -> Tree<Self> {
        use Terminal::*;
        match self.node {
            PkK(..) | PkH(..) | RawPkH(..) | After(..) | Older(..) | Sha256(..) | Hash256(..)
            | Ripemd160(..) | Hash160(..) | True | False | Multi(..) | MultiA(..) => Tree::Nullary,
            Alt(ref sub)
            | Swap(ref sub)
            | Check(ref sub)
            | DupIf(ref sub)
            | Verify(ref sub)
            | NonZero(ref sub)
            | ZeroNotEqual(ref sub) => Tree::Unary(sub),
            AndV(ref left, ref right)
            | AndB(ref left, ref right)
            | OrB(ref left, ref right)
            | OrD(ref left, ref right)
            | OrC(ref left, ref right)
            | OrI(ref left, ref right) => Tree::Binary(left, right),
            AndOr(ref a, ref b, ref c) => Tree::Nary(Arc::from([a.as_ref(), b, c])),
            Thresh(ref thresh) => Tree::Nary(thresh.iter().map(Arc::as_ref).collect()),
        }
    }
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> TreeLike for Arc<Miniscript<Pk, Ctx>> {
    fn as_node(&self) -> Tree<Self> {
        use Terminal::*;
        match self.node {
            PkK(..) | PkH(..) | RawPkH(..) | After(..) | Older(..) | Sha256(..) | Hash256(..)
            | Ripemd160(..) | Hash160(..) | True | False | Multi(..) | MultiA(..) => Tree::Nullary,
            Alt(ref sub)
            | Swap(ref sub)
            | Check(ref sub)
            | DupIf(ref sub)
            | Verify(ref sub)
            | NonZero(ref sub)
            | ZeroNotEqual(ref sub) => Tree::Unary(Arc::clone(sub)),
            AndV(ref left, ref right)
            | AndB(ref left, ref right)
            | OrB(ref left, ref right)
            | OrD(ref left, ref right)
            | OrC(ref left, ref right)
            | OrI(ref left, ref right) => Tree::Binary(Arc::clone(left), Arc::clone(right)),
            AndOr(ref a, ref b, ref c) => {
                Tree::Nary(Arc::from([Arc::clone(a), Arc::clone(b), Arc::clone(c)]))
            }
            Thresh(ref thresh) => Tree::Nary(thresh.iter().map(Arc::clone).collect()),
        }
    }
}
