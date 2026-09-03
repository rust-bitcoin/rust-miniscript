// SPDX-License-Identifier: CC0-1.0

//! Abstract Tree Iteration
//!
//! This module provides functionality to treat Miniscript objects abstractly
//! as trees, iterating over them in various orders. The iterators in this
//! module can be used to avoid explicitly recursive algorithms.
//!

mod tree;

#[cfg(all(not(feature = "std"), not(test)))]
use alloc::vec;
#[cfg(any(feature = "std", test))]
use std::vec;

pub use tree::{
    PostOrderIter, PostOrderIterItem, PreOrderIter, PreOrderIterItem, Tree, TreeLike,
    VerbosePreOrderIter,
};

use crate::prelude::*;
use crate::sync::Arc;
use crate::{Miniscript, MiniscriptKey, ScriptContext, Terminal, Threshold};

/// Extension trait for the stacks used by algorithms which reconstruct a tree
/// from a [`TreeLike::post_order_iter`].
///
/// Since a post-order iterator yields children left-to-right, the children of
/// a node appear in that same order at the top of the stack. These methods pop
/// them off and hand them back in that order, rather than reversed as a bare
/// sequence of [`Vec::pop`] calls would.
pub(crate) trait StackExt<T> {
    /// Pops the top two elements off of the stack and passes them, in
    /// left-to-right order, to `f`.
    fn pop2<R>(&mut self, f: impl FnOnce(T, T) -> R) -> R;

    /// Pops the top three elements off of the stack and passes them, in
    /// left-to-right order, to `f`.
    fn pop3<R>(&mut self, f: impl FnOnce(T, T, T) -> R) -> R;

    /// Pops the top `n` elements off of the stack, in left-to-right order.
    fn pop_n(&mut self, n: usize) -> vec::Drain<'_, T>;

    /// Pops the children of `thresh` off of the stack, in left-to-right order,
    /// and reassembles them into a threshold with the same `k`.
    fn pop_thresh<U, const MAX: usize>(&mut self, thresh: &Threshold<U, MAX>) -> Threshold<T, MAX>;
}

impl<T> StackExt<T> for Vec<T> {
    #[inline]
    fn pop2<R>(&mut self, f: impl FnOnce(T, T) -> R) -> R {
        let b = self.pop().unwrap();
        let a = self.pop().unwrap();
        f(a, b)
    }

    #[inline]
    fn pop3<R>(&mut self, f: impl FnOnce(T, T, T) -> R) -> R {
        let c = self.pop().unwrap();
        let b = self.pop().unwrap();
        let a = self.pop().unwrap();
        f(a, b, c)
    }

    #[inline]
    fn pop_n(&mut self, n: usize) -> vec::Drain<'_, T> {
        let start = self.len() - n;
        self.drain(start..)
    }

    #[inline]
    fn pop_thresh<U, const MAX: usize>(&mut self, thresh: &Threshold<U, MAX>) -> Threshold<T, MAX> {
        let mut children = self.pop_n(thresh.n());
        thresh.map_ref(|_| children.next().unwrap())
    }
}

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
