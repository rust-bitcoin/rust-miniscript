// Written in 2019 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Miniscript Types
//! Contains structures representing Miniscript types and utility functions
//! Contains all the type checking rules for correctness and malleability
//! Implemented as per rules on bitcoin.sipa.be/miniscript
pub mod correctness;
pub mod extra_props;
pub mod malleability;

use core::fmt;
#[cfg(feature = "std")]
use std::error;

use bitcoin::{absolute, Sequence};

pub use self::correctness::{Base, Correctness, Input};
pub use self::extra_props::ExtData;
pub use self::malleability::{Dissat, Malleability};
use super::ScriptContext;
use crate::{MiniscriptKey, Terminal};

/// None-returning function to help type inference when we need a
/// closure that simply returns `None`
fn return_none<T>(_: usize) -> Option<T> {
    None
}

/// Detailed type of a typechecker error
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum ErrorKind {
    /// Relative or absolute timelock had an invalid time value (either 0, or >=0x80000000)
    InvalidTime,
    /// Passed a `z` argument to a `d` wrapper when `z` was expected
    NonZeroDupIf,
    /// Multisignature or threshold policy had a `k` value of 0
    ZeroThreshold,
    /// Multisignature or threshold policy has a `k` value in
    /// excess of the number of subfragments
    OverThreshold(usize, usize),
    /// Attempted to construct a disjunction (or `andor`) for which
    /// none of the child nodes were strong. This means that a 3rd
    /// party could produce a satisfaction for any branch, meaning
    /// that no matter which one an honest signer chooses, it is
    /// possible to malleate the transaction.
    NoStrongChild,
    /// Many fragments (all disjunctions except `or_i` as well as
    /// `andor` require their left child be dissatisfiable.
    LeftNotDissatisfiable,
    /// `or_b` requires its right child be dissatisfiable
    RightNotDissatisfiable,
    /// Tried to use the `s:` modifier on a fragment that takes more
    /// than one input
    SwapNonOne,
    /// Tried to use the `j:` (`SIZE 0NOTEQUAL IF`) wrapper on something
    /// that may be satisfied by a 0 input
    NonZeroZero,
    /// Many fragments require their left child to be a unit. This
    /// was not the case.
    LeftNotUnit,
    /// Attempted to construct a wrapper, but the child had
    /// an invalid type
    ChildBase1(Base),
    /// Attempted to construct a conjunction or disjunction, but
    /// the fragments' children were of invalid types
    ChildBase2(Base, Base),
    /// Attempted to construct an `andor` but the fragments'
    /// children were of invalid types
    ChildBase3(Base, Base, Base),
    /// The nth child of a threshold fragment had an invalid type (the
    /// first must be `B` and the rest `W`s)
    ThresholdBase(usize, Base),
    /// The nth child of a threshold fragment did not have a unique
    /// satisfaction
    ThresholdDissat(usize),
    /// The nth child of a threshold fragment was not a unit
    ThresholdNonUnit(usize),
    /// Insufficiently many children of a threshold fragment were strong
    ThresholdNotStrong {
        /// Threshold parameter
        k: usize,
        /// Number of children
        n: usize,
        /// Number of strong children
        n_strong: usize,
    },
}

/// Error type for typechecking
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Error<Pk: MiniscriptKey, Ctx: ScriptContext> {
    /// The fragment that failed typecheck
    pub fragment: Terminal<Pk, Ctx>,
    /// The reason that typechecking failed
    pub error: ErrorKind,
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> fmt::Display for Error<Pk, Ctx> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.error {
            ErrorKind::InvalidTime => write!(
                f,
                "fragment «{}» represents a timelock which value is invalid (time must be in [1; 0x80000000])",
                self.fragment,
            ),
            ErrorKind::NonZeroDupIf => write!(
                f,
                "fragment «{}» represents needs to be `z`, needs to consume zero elements from the stack",
                self.fragment,
            ),
            ErrorKind::ZeroThreshold => write!(
                f,
                "fragment «{}» has a threshold value of 0",
                self.fragment,
            ),
            ErrorKind::OverThreshold(k, n) => write!(
                f,
                "fragment «{}» is a {}-of-{} threshold, which does not
                 make sense",
                self.fragment, k, n,
            ),
            ErrorKind::NoStrongChild => write!(
                f,
                "fragment «{}» requires at least one strong child \
                 (a 3rd party cannot create a witness without having \
                 seen one before) to prevent malleability",
                self.fragment,
            ),
            ErrorKind::LeftNotDissatisfiable => write!(
                f,
                "fragment «{}» requires its left child be dissatisfiable",
                self.fragment,
            ),
            ErrorKind::RightNotDissatisfiable => write!(
                f,
                "fragment «{}» requires its right child be dissatisfiable",
                self.fragment,
            ),
            ErrorKind::SwapNonOne => write!(
                f,
                "fragment «{}» attempts to use `SWAP` to prefix something
                 which does not take exactly one input",
                self.fragment,
            ),
            ErrorKind::NonZeroZero => write!(
                f,
                "fragment «{}» attempts to use use the `j:` wrapper around a
                 fragment which might be satisfied by an input of size zero",
                self.fragment,
            ),
            ErrorKind::LeftNotUnit => write!(
                f,
                "fragment «{}» requires its left child be a unit (outputs
                 exactly 1 given a satisfying input)",
                self.fragment,
            ),
            ErrorKind::ChildBase1(base) => write!(
                f,
                "fragment «{}» cannot wrap a fragment of type {:?}",
                self.fragment, base,
            ),
            ErrorKind::ChildBase2(base1, base2) => write!(
                f,
                "fragment «{}» cannot accept children of types {:?} and {:?}",
                self.fragment, base1, base2,
            ),
            ErrorKind::ChildBase3(base1, base2, base3) => write!(
                f,
                "fragment «{}» cannot accept children of types {:?}, {:?} and {:?}",
                self.fragment, base1, base2, base3,
            ),
            ErrorKind::ThresholdBase(idx, base) => write!(
                f,
                "fragment «{}» sub-fragment {} has type {:?} rather than {:?}",
                self.fragment,
                idx,
                base,
                if idx == 0 { Base::B } else { Base::W },
            ),
            ErrorKind::ThresholdDissat(idx) => write!(
                f,
                "fragment «{}» sub-fragment {} can not be dissatisfied \
                 and cannot be used in a threshold",
                self.fragment, idx,
            ),
            ErrorKind::ThresholdNonUnit(idx) => write!(
                f,
                "fragment «{}» sub-fragment {} is not a unit (does not put \
                 exactly 1 on the stack given a satisfying input)",
                self.fragment, idx,
            ),
            ErrorKind::ThresholdNotStrong { k, n, n_strong } => write!(
                f,
                "fragment «{}» is a {}-of-{} threshold, and needs {} of \
                 its children to be strong to prevent malleability; however \
                 only {} children were strong.",
                self.fragment,
                k,
                n,
                n - k,
                n_strong,
            ),
        }
    }
}

#[cfg(feature = "std")]
impl<Pk: MiniscriptKey, Ctx: ScriptContext> error::Error for Error<Pk, Ctx> {
    fn cause(&self) -> Option<&dyn error::Error> {
        None
    }
}

/// Structure representing the type of a Miniscript fragment, including all
/// properties relevant to the main codebase
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Type {
    /// Correctness/soundness properties
    pub corr: Correctness,
    /// Malleability properties
    pub mall: Malleability,
}

impl Type {
    /// Check whether the `self` is a subtype of `other` argument .
    /// This checks whether the argument `other` has attributes which are present
    /// in the given `Type`. This returns `true` on same arguments
    /// `a.is_subtype(a)` is `true`.
    pub fn is_subtype(&self, other: Self) -> bool {
        self.corr.is_subtype(other.corr) && self.mall.is_subtype(other.mall)
    }
}
/// Trait representing a type property, which defines how the property
/// propagates from terminals to the root of a Miniscript
pub trait Property: Sized {
    /// Any extra sanity checks/assertions that should be applied after
    /// typechecking
    fn sanity_checks(&self) {
        // no checks by default
    }

    /// Type property of the `True` fragment
    fn from_true() -> Self;

    /// Type property of the `False` fragment
    fn from_false() -> Self;

    /// Type property of the `PkK` fragment
    fn from_pk_k<Ctx: ScriptContext>() -> Self;

    /// Type property of the `PkH` fragment
    fn from_pk_h<Ctx: ScriptContext>() -> Self;

    /// Type property of a `Multi` fragment
    fn from_multi(k: usize, n: usize) -> Self;

    /// Type property of a `MultiA` fragment
    fn from_multi_a(k: usize, n: usize) -> Self;

    /// Type property of a hash fragment
    fn from_hash() -> Self;

    /// Type property of a `Sha256` hash. Default implementation simply
    /// passes through to `from_hash`
    fn from_sha256() -> Self {
        Self::from_hash()
    }

    /// Type property of a `Hash256` hash. Default implementation simply
    /// passes through to `from_hash`
    fn from_hash256() -> Self {
        Self::from_hash()
    }

    /// Type property of a `Ripemd160` hash. Default implementation simply
    /// passes through to `from_hash`
    fn from_ripemd160() -> Self {
        Self::from_hash()
    }

    /// Type property of a `Hash160` hash. Default implementation simply
    /// passes through to `from_hash`
    fn from_hash160() -> Self {
        Self::from_hash()
    }

    /// Type property of a timelock
    fn from_time(t: u32) -> Self;

    /// Type property of an absolute timelock. Default implementation simply
    /// passes through to `from_time`
    fn from_after(t: absolute::LockTime) -> Self {
        Self::from_time(t.to_consensus_u32())
    }

    /// Type property of a relative timelock. Default implementation simply
    /// passes through to `from_time`
    fn from_older(t: Sequence) -> Self {
        Self::from_time(t.to_consensus_u32())
    }

    /// Cast using the `Alt` wrapper
    fn cast_alt(self) -> Result<Self, ErrorKind>;

    /// Cast using the `Swap` wrapper
    fn cast_swap(self) -> Result<Self, ErrorKind>;

    /// Cast using the `Check` wrapper
    fn cast_check(self) -> Result<Self, ErrorKind>;

    /// Cast using the `DupIf` wrapper
    fn cast_dupif(self) -> Result<Self, ErrorKind>;

    /// Cast using the `Verify` wrapper
    fn cast_verify(self) -> Result<Self, ErrorKind>;

    /// Cast using the `NonZero` wrapper
    fn cast_nonzero(self) -> Result<Self, ErrorKind>;

    /// Cast using the `ZeroNotEqual` wrapper
    fn cast_zeronotequal(self) -> Result<Self, ErrorKind>;

    /// Cast by changing `[X]` to `AndV([X], True)`
    fn cast_true(self) -> Result<Self, ErrorKind> {
        Self::and_v(self, Self::from_true())
    }

    /// Cast by changing `[X]` to `or_i([X], 0)` or `or_i(0, [X])`
    fn cast_or_i_false(self) -> Result<Self, ErrorKind>;

    /// Cast by changing `[X]` to `or_i([X], 0)`. Default implementation
    /// simply passes through to `cast_or_i_false`
    fn cast_unlikely(self) -> Result<Self, ErrorKind> {
        Self::or_i(self, Self::from_false())
    }

    /// Cast by changing `[X]` to `or_i(0, [X])`. Default implementation
    /// simply passes through to `cast_or_i_false`
    fn cast_likely(self) -> Result<Self, ErrorKind> {
        Self::or_i(Self::from_false(), self)
    }

    /// Computes the type of an `AndB` fragment
    fn and_b(left: Self, right: Self) -> Result<Self, ErrorKind>;

    /// Computes the type of an `AndV` fragment
    fn and_v(left: Self, right: Self) -> Result<Self, ErrorKind>;

    /// Computes the type of an `AndN` fragment
    fn and_n(left: Self, right: Self) -> Result<Self, ErrorKind> {
        Self::and_or(left, right, Self::from_false())
    }

    /// Computes the type of an `OrB` fragment
    fn or_b(left: Self, right: Self) -> Result<Self, ErrorKind>;

    /// Computes the type of an `OrD` fragment
    fn or_d(left: Self, right: Self) -> Result<Self, ErrorKind>;

    /// Computes the type of an `OrC` fragment
    fn or_c(left: Self, right: Self) -> Result<Self, ErrorKind>;

    /// Computes the type of an `OrI` fragment
    fn or_i(left: Self, right: Self) -> Result<Self, ErrorKind>;

    /// Computes the type of an `AndOr` fragment
    fn and_or(a: Self, b: Self, c: Self) -> Result<Self, ErrorKind>;

    /// Computes the type of an `Thresh` fragment
    fn threshold<S>(k: usize, n: usize, sub_ck: S) -> Result<Self, ErrorKind>
    where
        S: FnMut(usize) -> Result<Self, ErrorKind>;

    /// Compute the type of a fragment, given a function to look up
    /// the types of its children, if available and relevant for the
    /// given fragment
    fn type_check<Pk, Ctx, C>(
        fragment: &Terminal<Pk, Ctx>,
        mut child: C,
    ) -> Result<Self, Error<Pk, Ctx>>
    where
        C: FnMut(usize) -> Option<Self>,
        Pk: MiniscriptKey,
        Ctx: ScriptContext,
    {
        let mut get_child = |sub, n| {
            child(n)
                .map(Ok)
                .unwrap_or_else(|| Self::type_check(sub, return_none))
        };
        let wrap_err = |result: Result<Self, ErrorKind>| {
            result.map_err(|kind| Error {
                fragment: fragment.clone(),
                error: kind,
            })
        };

        let ret = match *fragment {
            Terminal::True => Ok(Self::from_true()),
            Terminal::False => Ok(Self::from_false()),
            Terminal::PkK(..) => Ok(Self::from_pk_k::<Ctx>()),
            Terminal::PkH(..) | Terminal::RawPkH(..) => Ok(Self::from_pk_h::<Ctx>()),
            Terminal::Multi(k, ref pks) | Terminal::MultiA(k, ref pks) => {
                if k == 0 {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::ZeroThreshold,
                    });
                }
                if k > pks.len() {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::OverThreshold(k, pks.len()),
                    });
                }
                match *fragment {
                    Terminal::Multi(..) => Ok(Self::from_multi(k, pks.len())),
                    Terminal::MultiA(..) => Ok(Self::from_multi_a(k, pks.len())),
                    _ => unreachable!(),
                }
            }
            Terminal::After(t) => {
                // Note that for CLTV this is a limitation not of Bitcoin but Miniscript. The
                // number on the stack would be a 5 bytes signed integer but Miniscript's B type
                // only consumes 4 bytes from the stack.
                if t == absolute::LockTime::ZERO.into() {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::InvalidTime,
                    });
                }
                Ok(Self::from_after(t.into()))
            }
            Terminal::Older(t) => {
                if t == Sequence::ZERO || !t.is_relative_lock_time() {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::InvalidTime,
                    });
                }
                Ok(Self::from_older(t))
            }
            Terminal::Sha256(..) => Ok(Self::from_sha256()),
            Terminal::Hash256(..) => Ok(Self::from_hash256()),
            Terminal::Ripemd160(..) => Ok(Self::from_ripemd160()),
            Terminal::Hash160(..) => Ok(Self::from_hash160()),
            Terminal::Alt(ref sub) => wrap_err(Self::cast_alt(get_child(&sub.node, 0)?)),
            Terminal::Swap(ref sub) => wrap_err(Self::cast_swap(get_child(&sub.node, 0)?)),
            Terminal::Check(ref sub) => wrap_err(Self::cast_check(get_child(&sub.node, 0)?)),
            Terminal::DupIf(ref sub) => wrap_err(Self::cast_dupif(get_child(&sub.node, 0)?)),
            Terminal::Verify(ref sub) => wrap_err(Self::cast_verify(get_child(&sub.node, 0)?)),
            Terminal::NonZero(ref sub) => wrap_err(Self::cast_nonzero(get_child(&sub.node, 0)?)),
            Terminal::ZeroNotEqual(ref sub) => {
                wrap_err(Self::cast_zeronotequal(get_child(&sub.node, 0)?))
            }
            Terminal::AndB(ref l, ref r) => {
                let ltype = get_child(&l.node, 0)?;
                let rtype = get_child(&r.node, 1)?;
                wrap_err(Self::and_b(ltype, rtype))
            }
            Terminal::AndV(ref l, ref r) => {
                let ltype = get_child(&l.node, 0)?;
                let rtype = get_child(&r.node, 1)?;
                wrap_err(Self::and_v(ltype, rtype))
            }
            Terminal::OrB(ref l, ref r) => {
                let ltype = get_child(&l.node, 0)?;
                let rtype = get_child(&r.node, 1)?;
                wrap_err(Self::or_b(ltype, rtype))
            }
            Terminal::OrD(ref l, ref r) => {
                let ltype = get_child(&l.node, 0)?;
                let rtype = get_child(&r.node, 1)?;
                wrap_err(Self::or_d(ltype, rtype))
            }
            Terminal::OrC(ref l, ref r) => {
                let ltype = get_child(&l.node, 0)?;
                let rtype = get_child(&r.node, 1)?;
                wrap_err(Self::or_c(ltype, rtype))
            }
            Terminal::OrI(ref l, ref r) => {
                let ltype = get_child(&l.node, 0)?;
                let rtype = get_child(&r.node, 1)?;
                wrap_err(Self::or_i(ltype, rtype))
            }
            Terminal::AndOr(ref a, ref b, ref c) => {
                let atype = get_child(&a.node, 0)?;
                let btype = get_child(&b.node, 1)?;
                let ctype = get_child(&c.node, 2)?;
                wrap_err(Self::and_or(atype, btype, ctype))
            }
            Terminal::Thresh(k, ref subs) => {
                if k == 0 {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::ZeroThreshold,
                    });
                }
                if k > subs.len() {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::OverThreshold(k, subs.len()),
                    });
                }

                let mut last_err_frag = None;
                let res = Self::threshold(k, subs.len(), |n| match get_child(&subs[n].node, n) {
                    Ok(x) => Ok(x),
                    Err(e) => {
                        last_err_frag = Some(e.fragment);
                        Err(e.error)
                    }
                });

                res.map_err(|kind| Error {
                    fragment: last_err_frag.unwrap_or_else(|| fragment.clone()),
                    error: kind,
                })
            }
        };
        if let Ok(ref ret) = ret {
            ret.sanity_checks()
        }
        ret
    }
}

impl Property for Type {
    fn sanity_checks(&self) {
        debug_assert!(!self.corr.dissatisfiable || self.mall.dissat != Dissat::None);
        debug_assert!(self.mall.dissat == Dissat::None || self.corr.base != Base::V);
        debug_assert!(self.mall.safe || self.corr.base != Base::K);
        debug_assert!(self.mall.non_malleable || self.corr.input != Input::Zero);
    }

    fn from_true() -> Self {
        Type {
            corr: Property::from_true(),
            mall: Property::from_true(),
        }
    }

    fn from_false() -> Self {
        Type {
            corr: Property::from_false(),
            mall: Property::from_false(),
        }
    }

    fn from_pk_k<Ctx: ScriptContext>() -> Self {
        Type {
            corr: Property::from_pk_k::<Ctx>(),
            mall: Property::from_pk_k::<Ctx>(),
        }
    }

    fn from_pk_h<Ctx: ScriptContext>() -> Self {
        Type {
            corr: Property::from_pk_h::<Ctx>(),
            mall: Property::from_pk_h::<Ctx>(),
        }
    }

    fn from_multi(k: usize, n: usize) -> Self {
        Type {
            corr: Property::from_multi(k, n),
            mall: Property::from_multi(k, n),
        }
    }

    fn from_multi_a(k: usize, n: usize) -> Self {
        Type {
            corr: Property::from_multi_a(k, n),
            mall: Property::from_multi_a(k, n),
        }
    }

    fn from_hash() -> Self {
        Type {
            corr: Property::from_hash(),
            mall: Property::from_hash(),
        }
    }

    fn from_sha256() -> Self {
        Type {
            corr: Property::from_sha256(),
            mall: Property::from_sha256(),
        }
    }

    fn from_hash256() -> Self {
        Type {
            corr: Property::from_hash256(),
            mall: Property::from_hash256(),
        }
    }

    fn from_ripemd160() -> Self {
        Type {
            corr: Property::from_ripemd160(),
            mall: Property::from_ripemd160(),
        }
    }

    fn from_hash160() -> Self {
        Type {
            corr: Property::from_hash160(),
            mall: Property::from_hash160(),
        }
    }

    fn from_time(t: u32) -> Self {
        Type {
            corr: Property::from_time(t),
            mall: Property::from_time(t),
        }
    }

    fn from_after(t: absolute::LockTime) -> Self {
        Type {
            corr: Property::from_after(t),
            mall: Property::from_after(t),
        }
    }

    fn from_older(t: Sequence) -> Self {
        Type {
            corr: Property::from_older(t),
            mall: Property::from_older(t),
        }
    }

    fn cast_alt(self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Property::cast_alt(self.corr)?,
            mall: Property::cast_alt(self.mall)?,
        })
    }

    fn cast_swap(self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Property::cast_swap(self.corr)?,
            mall: Property::cast_swap(self.mall)?,
        })
    }

    fn cast_check(self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Property::cast_check(self.corr)?,
            mall: Property::cast_check(self.mall)?,
        })
    }

    fn cast_dupif(self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Property::cast_dupif(self.corr)?,
            mall: Property::cast_dupif(self.mall)?,
        })
    }

    fn cast_verify(self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Property::cast_verify(self.corr)?,
            mall: Property::cast_verify(self.mall)?,
        })
    }

    fn cast_nonzero(self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Property::cast_nonzero(self.corr)?,
            mall: Property::cast_nonzero(self.mall)?,
        })
    }

    fn cast_zeronotequal(self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Property::cast_zeronotequal(self.corr)?,
            mall: Property::cast_zeronotequal(self.mall)?,
        })
    }

    fn cast_true(self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Property::cast_true(self.corr)?,
            mall: Property::cast_true(self.mall)?,
        })
    }

    fn cast_or_i_false(self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Property::cast_or_i_false(self.corr)?,
            mall: Property::cast_or_i_false(self.mall)?,
        })
    }

    fn cast_unlikely(self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Property::cast_unlikely(self.corr)?,
            mall: Property::cast_unlikely(self.mall)?,
        })
    }

    fn cast_likely(self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Property::cast_likely(self.corr)?,
            mall: Property::cast_likely(self.mall)?,
        })
    }

    fn and_b(left: Self, right: Self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Property::and_b(left.corr, right.corr)?,
            mall: Property::and_b(left.mall, right.mall)?,
        })
    }

    fn and_v(left: Self, right: Self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Property::and_v(left.corr, right.corr)?,
            mall: Property::and_v(left.mall, right.mall)?,
        })
    }

    fn or_b(left: Self, right: Self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Property::or_b(left.corr, right.corr)?,
            mall: Property::or_b(left.mall, right.mall)?,
        })
    }

    fn or_d(left: Self, right: Self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Property::or_d(left.corr, right.corr)?,
            mall: Property::or_d(left.mall, right.mall)?,
        })
    }

    fn or_c(left: Self, right: Self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Property::or_c(left.corr, right.corr)?,
            mall: Property::or_c(left.mall, right.mall)?,
        })
    }

    fn or_i(left: Self, right: Self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Property::or_i(left.corr, right.corr)?,
            mall: Property::or_i(left.mall, right.mall)?,
        })
    }

    fn and_or(a: Self, b: Self, c: Self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Property::and_or(a.corr, b.corr, c.corr)?,
            mall: Property::and_or(a.mall, b.mall, c.mall)?,
        })
    }

    fn threshold<S>(k: usize, n: usize, mut sub_ck: S) -> Result<Self, ErrorKind>
    where
        S: FnMut(usize) -> Result<Self, ErrorKind>,
    {
        Ok(Type {
            corr: Property::threshold(k, n, |n| Ok(sub_ck(n)?.corr))?,
            mall: Property::threshold(k, n, |n| Ok(sub_ck(n)?.mall))?,
        })
    }

    /// Compute the type of a fragment assuming all the children of
    /// Miniscript have been computed already.
    fn type_check<Pk, Ctx, C>(
        fragment: &Terminal<Pk, Ctx>,
        _child: C,
    ) -> Result<Self, Error<Pk, Ctx>>
    where
        C: FnMut(usize) -> Option<Self>,
        Pk: MiniscriptKey,
        Ctx: ScriptContext,
    {
        let wrap_err = |result: Result<Self, ErrorKind>| {
            result.map_err(|kind| Error {
                fragment: fragment.clone(),
                error: kind,
            })
        };

        let ret = match *fragment {
            Terminal::True => Ok(Self::from_true()),
            Terminal::False => Ok(Self::from_false()),
            Terminal::PkK(..) => Ok(Self::from_pk_k::<Ctx>()),
            Terminal::PkH(..) | Terminal::RawPkH(..) => Ok(Self::from_pk_h::<Ctx>()),
            Terminal::Multi(k, ref pks) | Terminal::MultiA(k, ref pks) => {
                if k == 0 {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::ZeroThreshold,
                    });
                }
                if k > pks.len() {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::OverThreshold(k, pks.len()),
                    });
                }
                match *fragment {
                    Terminal::Multi(..) => Ok(Self::from_multi(k, pks.len())),
                    Terminal::MultiA(..) => Ok(Self::from_multi_a(k, pks.len())),
                    _ => unreachable!(),
                }
            }
            Terminal::After(t) => {
                // Note that for CLTV this is a limitation not of Bitcoin but Miniscript. The
                // number on the stack would be a 5 bytes signed integer but Miniscript's B type
                // only consumes 4 bytes from the stack.
                if t == absolute::LockTime::ZERO.into() {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::InvalidTime,
                    });
                }
                Ok(Self::from_after(t.into()))
            }
            Terminal::Older(t) => {
                if t == Sequence::ZERO || !t.is_relative_lock_time() {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::InvalidTime,
                    });
                }
                Ok(Self::from_older(t))
            }
            Terminal::Sha256(..) => Ok(Self::from_sha256()),
            Terminal::Hash256(..) => Ok(Self::from_hash256()),
            Terminal::Ripemd160(..) => Ok(Self::from_ripemd160()),
            Terminal::Hash160(..) => Ok(Self::from_hash160()),
            Terminal::Alt(ref sub) => wrap_err(Self::cast_alt(sub.ty)),
            Terminal::Swap(ref sub) => wrap_err(Self::cast_swap(sub.ty)),
            Terminal::Check(ref sub) => wrap_err(Self::cast_check(sub.ty)),
            Terminal::DupIf(ref sub) => wrap_err(Self::cast_dupif(sub.ty)),
            Terminal::Verify(ref sub) => wrap_err(Self::cast_verify(sub.ty)),
            Terminal::NonZero(ref sub) => wrap_err(Self::cast_nonzero(sub.ty)),
            Terminal::ZeroNotEqual(ref sub) => wrap_err(Self::cast_zeronotequal(sub.ty)),
            Terminal::AndB(ref l, ref r) => {
                let ltype = l.ty;
                let rtype = r.ty;
                wrap_err(Self::and_b(ltype, rtype))
            }
            Terminal::AndV(ref l, ref r) => {
                let ltype = l.ty;
                let rtype = r.ty;
                wrap_err(Self::and_v(ltype, rtype))
            }
            Terminal::OrB(ref l, ref r) => {
                let ltype = l.ty;
                let rtype = r.ty;
                wrap_err(Self::or_b(ltype, rtype))
            }
            Terminal::OrD(ref l, ref r) => {
                let ltype = l.ty;
                let rtype = r.ty;
                wrap_err(Self::or_d(ltype, rtype))
            }
            Terminal::OrC(ref l, ref r) => {
                let ltype = l.ty;
                let rtype = r.ty;
                wrap_err(Self::or_c(ltype, rtype))
            }
            Terminal::OrI(ref l, ref r) => {
                let ltype = l.ty;
                let rtype = r.ty;
                wrap_err(Self::or_i(ltype, rtype))
            }
            Terminal::AndOr(ref a, ref b, ref c) => {
                let atype = a.ty;
                let btype = b.ty;
                let ctype = c.ty;
                wrap_err(Self::and_or(atype, btype, ctype))
            }
            Terminal::Thresh(k, ref subs) => {
                if k == 0 {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::ZeroThreshold,
                    });
                }
                if k > subs.len() {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::OverThreshold(k, subs.len()),
                    });
                }

                let res = Self::threshold(k, subs.len(), |n| Ok(subs[n].ty));

                res.map_err(|kind| Error {
                    fragment: fragment.clone(),
                    error: kind,
                })
            }
        };
        if let Ok(ref ret) = ret {
            ret.sanity_checks()
        }
        ret
    }
}
