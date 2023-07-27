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
        match self.node {
            Terminal::PkK(..)
            | Terminal::PkH(..)
            | Terminal::RawPkH(..)
            | Terminal::After(..)
            | Terminal::Older(..)
            | Terminal::Sha256(..)
            | Terminal::Hash256(..)
            | Terminal::Ripemd160(..)
            | Terminal::Hash160(..)
            | Terminal::True
            | Terminal::False
            | Terminal::Multi(..)
            | Terminal::MultiA(..) => Tree::Nullary,
            Terminal::Alt(ref sub)
            | Terminal::Swap(ref sub)
            | Terminal::Check(ref sub)
            | Terminal::DupIf(ref sub)
            | Terminal::Verify(ref sub)
            | Terminal::NonZero(ref sub)
            | Terminal::ZeroNotEqual(ref sub) => Tree::Unary(sub),
            Terminal::AndV(ref left, ref right)
            | Terminal::AndB(ref left, ref right)
            | Terminal::OrB(ref left, ref right)
            | Terminal::OrD(ref left, ref right)
            | Terminal::OrC(ref left, ref right)
            | Terminal::OrI(ref left, ref right) => Tree::Binary(left, right),
            Terminal::AndOr(ref a, ref b, ref c) => Tree::Nary(Arc::from([a.as_ref(), b, c])),
            Terminal::Thresh(_, ref subs) => Tree::Nary(subs.iter().map(Arc::as_ref).collect()),
        }
    }
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> TreeLike for Arc<Miniscript<Pk, Ctx>> {
    fn as_node(&self) -> Tree<Self> {
        match self.node {
            Terminal::PkK(..)
            | Terminal::PkH(..)
            | Terminal::RawPkH(..)
            | Terminal::After(..)
            | Terminal::Older(..)
            | Terminal::Sha256(..)
            | Terminal::Hash256(..)
            | Terminal::Ripemd160(..)
            | Terminal::Hash160(..)
            | Terminal::True
            | Terminal::False
            | Terminal::Multi(..)
            | Terminal::MultiA(..) => Tree::Nullary,
            Terminal::Alt(ref sub)
            | Terminal::Swap(ref sub)
            | Terminal::Check(ref sub)
            | Terminal::DupIf(ref sub)
            | Terminal::Verify(ref sub)
            | Terminal::NonZero(ref sub)
            | Terminal::ZeroNotEqual(ref sub) => Tree::Unary(Arc::clone(sub)),
            Terminal::AndV(ref left, ref right)
            | Terminal::AndB(ref left, ref right)
            | Terminal::OrB(ref left, ref right)
            | Terminal::OrD(ref left, ref right)
            | Terminal::OrC(ref left, ref right)
            | Terminal::OrI(ref left, ref right) => {
                Tree::Binary(Arc::clone(left), Arc::clone(right))
            }
            Terminal::AndOr(ref a, ref b, ref c) => {
                Tree::Nary(Arc::from([Arc::clone(a), Arc::clone(b), Arc::clone(c)]))
            }
            Terminal::Thresh(_, ref subs) => Tree::Nary(subs.iter().map(Arc::clone).collect()),
        }
    }
}
