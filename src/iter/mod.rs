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
    type NaryChildren = &'a [Arc<Miniscript<Pk, Ctx>>];

    fn nary_len(tc: &Self::NaryChildren) -> usize { tc.len() }
    fn nary_index(tc: Self::NaryChildren, idx: usize) -> Self { Arc::as_ref(&tc[idx]) }

    fn as_node(&self) -> Tree<Self, Self::NaryChildren> {
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
            AndOr(ref a, ref b, ref c) => Tree::Ternary(a, b, c),
            Thresh(ref thresh) => Tree::Nary(thresh.data()),
        }
    }
}

impl<'a, Pk: MiniscriptKey, Ctx: ScriptContext> TreeLike for &'a Arc<Miniscript<Pk, Ctx>> {
    type NaryChildren = &'a [Arc<Miniscript<Pk, Ctx>>];

    fn nary_len(tc: &Self::NaryChildren) -> usize { tc.len() }
    fn nary_index(tc: Self::NaryChildren, idx: usize) -> Self { &tc[idx] }

    fn as_node(&self) -> Tree<Self, Self::NaryChildren> {
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
            AndOr(ref a, ref b, ref c) => Tree::Ternary(a, b, c),
            Thresh(ref thresh) => Tree::Nary(thresh.data()),
        }
    }
}

impl<'a, Pk: MiniscriptKey, Ctx: ScriptContext> TreeLike for &'a Terminal<Pk, Ctx> {
    type NaryChildren = &'a [Arc<Miniscript<Pk, Ctx>>];

    fn nary_len(tc: &Self::NaryChildren) -> usize { tc.len() }
    fn nary_index(tc: Self::NaryChildren, idx: usize) -> Self { tc[idx].as_inner() }

    fn as_node(&self) -> Tree<Self, Self::NaryChildren> {
        use Terminal::*;
        match self {
            PkK(..) | PkH(..) | RawPkH(..) | After(..) | Older(..) | Sha256(..) | Hash256(..)
            | Ripemd160(..) | Hash160(..) | True | False | Multi(..) | MultiA(..) => Tree::Nullary,
            Alt(ref sub)
            | Swap(ref sub)
            | Check(ref sub)
            | DupIf(ref sub)
            | Verify(ref sub)
            | NonZero(ref sub)
            | ZeroNotEqual(ref sub) => Tree::Unary(sub.as_inner()),
            AndV(ref left, ref right)
            | AndB(ref left, ref right)
            | OrB(ref left, ref right)
            | OrD(ref left, ref right)
            | OrC(ref left, ref right)
            | OrI(ref left, ref right) => Tree::Binary(left.as_inner(), right.as_inner()),
            AndOr(ref a, ref b, ref c) => Tree::Ternary(a.as_inner(), b.as_inner(), c.as_inner()),
            Thresh(ref thresh) => Tree::Nary(thresh.data()),
        }
    }
}
