// SPDX-License-Identifier: CC0-1.0

//! Miniscript Types
//! Contains structures representing Miniscript types and utility functions
//! Contains all the type checking rules for correctness and malleability
//! Implemented as per rules on bitcoin.sipa.be/miniscript
pub mod correctness;
pub mod extra_props;
pub mod malleability;

#[cfg(all(not(feature = "std"), not(test)))]
use alloc::string::{String, ToString};
use core::fmt;
#[cfg(feature = "std")]
use std::error;

use bitcoin::{absolute, Sequence};

pub use self::correctness::{Base, Correctness, Input};
pub use self::extra_props::ExtData;
pub use self::malleability::{Dissat, Malleability};
use super::ScriptContext;
use crate::{MiniscriptKey, Terminal};

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
pub struct Error {
    /// The fragment that failed typecheck
    pub fragment_string: String,
    /// The reason that typechecking failed
    pub error: ErrorKind,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.error {
            ErrorKind::InvalidTime => write!(
                f,
                "fragment «{}» represents a timelock which value is invalid (time must be in [1; 0x80000000])",
                self.fragment_string,
            ),
            ErrorKind::NonZeroDupIf => write!(
                f,
                "fragment «{}» represents needs to be `z`, needs to consume zero elements from the stack",
                self.fragment_string,
            ),
            ErrorKind::ZeroThreshold => write!(
                f,
                "fragment «{}» has a threshold value of 0",
                self.fragment_string,
            ),
            ErrorKind::OverThreshold(k, n) => write!(
                f,
                "fragment «{}» is a {}-of-{} threshold, which does not
                 make sense",
                self.fragment_string, k, n,
            ),
            ErrorKind::NoStrongChild => write!(
                f,
                "fragment «{}» requires at least one strong child \
                 (a 3rd party cannot create a witness without having \
                 seen one before) to prevent malleability",
                self.fragment_string,
            ),
            ErrorKind::LeftNotDissatisfiable => write!(
                f,
                "fragment «{}» requires its left child be dissatisfiable",
                self.fragment_string,
            ),
            ErrorKind::RightNotDissatisfiable => write!(
                f,
                "fragment «{}» requires its right child be dissatisfiable",
                self.fragment_string,
            ),
            ErrorKind::SwapNonOne => write!(
                f,
                "fragment «{}» attempts to use `SWAP` to prefix something
                 which does not take exactly one input",
                self.fragment_string,
            ),
            ErrorKind::NonZeroZero => write!(
                f,
                "fragment «{}» attempts to use use the `j:` wrapper around a
                 fragment which might be satisfied by an input of size zero",
                self.fragment_string,
            ),
            ErrorKind::LeftNotUnit => write!(
                f,
                "fragment «{}» requires its left child be a unit (outputs
                 exactly 1 given a satisfying input)",
                self.fragment_string,
            ),
            ErrorKind::ChildBase1(base) => write!(
                f,
                "fragment «{}» cannot wrap a fragment of type {:?}",
                self.fragment_string, base,
            ),
            ErrorKind::ChildBase2(base1, base2) => write!(
                f,
                "fragment «{}» cannot accept children of types {:?} and {:?}",
                self.fragment_string, base1, base2,
            ),
            ErrorKind::ChildBase3(base1, base2, base3) => write!(
                f,
                "fragment «{}» cannot accept children of types {:?}, {:?} and {:?}",
                self.fragment_string, base1, base2, base3,
            ),
            ErrorKind::ThresholdBase(idx, base) => write!(
                f,
                "fragment «{}» sub-fragment {} has type {:?} rather than {:?}",
                self.fragment_string,
                idx,
                base,
                if idx == 0 { Base::B } else { Base::W },
            ),
            ErrorKind::ThresholdDissat(idx) => write!(
                f,
                "fragment «{}» sub-fragment {} can not be dissatisfied \
                 and cannot be used in a threshold",
                self.fragment_string, idx,
            ),
            ErrorKind::ThresholdNonUnit(idx) => write!(
                f,
                "fragment «{}» sub-fragment {} is not a unit (does not put \
                 exactly 1 on the stack given a satisfying input)",
                self.fragment_string, idx,
            ),
            ErrorKind::ThresholdNotStrong { k, n, n_strong } => write!(
                f,
                "fragment «{}» is a {}-of-{} threshold, and needs {} of \
                 its children to be strong to prevent malleability; however \
                 only {} children were strong.",
                self.fragment_string,
                k,
                n,
                n - k,
                n_strong,
            ),
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> { None }
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
    /// Type of the `0` combinator
    pub const TRUE: Self = Type { corr: Correctness::TRUE, mall: Malleability::TRUE };

    /// Type of the `0` combinator
    pub const FALSE: Self = Type { corr: Correctness::FALSE, mall: Malleability::FALSE };

    /// Check whether the `self` is a subtype of `other` argument .
    /// This checks whether the argument `other` has attributes which are present
    /// in the given `Type`. This returns `true` on same arguments
    /// `a.is_subtype(a)` is `true`.
    pub fn is_subtype(&self, other: Self) -> bool {
        self.corr.is_subtype(other.corr) && self.mall.is_subtype(other.mall)
    }

    /// Confirm invariants of the type checker.
    pub fn sanity_checks(&self) {
        debug_assert!(!self.corr.dissatisfiable || self.mall.dissat != Dissat::None);
        debug_assert!(self.mall.dissat == Dissat::None || self.corr.base != Base::V);
        debug_assert!(self.mall.safe || self.corr.base != Base::K);
        debug_assert!(self.mall.non_malleable || self.corr.input != Input::Zero);
    }

    /// Constructor for the type of the `pk_k` fragment.
    pub const fn pk_k() -> Self { Type { corr: Correctness::pk_k(), mall: Malleability::pk_k() } }

    /// Constructor for the type of the `pk_h` fragment.
    pub const fn pk_h() -> Self { Type { corr: Correctness::pk_h(), mall: Malleability::pk_h() } }

    /// Constructor for the type of the `multi` fragment.
    pub const fn multi() -> Self {
        Type { corr: Correctness::multi(), mall: Malleability::multi() }
    }

    /// Constructor for the type of the `multi_a` fragment.
    pub const fn multi_a() -> Self {
        Type { corr: Correctness::multi_a(), mall: Malleability::multi_a() }
    }

    /// Constructor for the type of all the hash fragments.
    pub const fn hash() -> Self { Type { corr: Correctness::hash(), mall: Malleability::hash() } }

    /// Constructor for the type of the `after` and `older` fragments.
    pub const fn time() -> Self { Type { corr: Correctness::time(), mall: Malleability::time() } }

    /// Constructor for the type of the `a:` fragment.
    pub fn cast_alt(self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Correctness::cast_alt(self.corr)?,
            mall: Malleability::cast_alt(self.mall),
        })
    }

    /// Constructor for the type of the `s:` fragment.
    pub fn cast_swap(self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Correctness::cast_swap(self.corr)?,
            mall: Malleability::cast_swap(self.mall),
        })
    }

    /// Constructor for the type of the `c:` fragment.
    pub fn cast_check(self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Correctness::cast_check(self.corr)?,
            mall: Malleability::cast_check(self.mall),
        })
    }

    /// Constructor for the type of the `d:` fragment.
    pub fn cast_dupif(self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Correctness::cast_dupif(self.corr)?,
            mall: Malleability::cast_dupif(self.mall),
        })
    }

    /// Constructor for the type of the `v:` fragment.
    pub fn cast_verify(self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Correctness::cast_verify(self.corr)?,
            mall: Malleability::cast_verify(self.mall),
        })
    }

    /// Constructor for the type of the `j:` fragment.
    pub fn cast_nonzero(self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Correctness::cast_nonzero(self.corr)?,
            mall: Malleability::cast_nonzero(self.mall),
        })
    }

    /// Constructor for the type of the `n:` fragment.
    pub fn cast_zeronotequal(self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Correctness::cast_zeronotequal(self.corr)?,
            mall: Malleability::cast_zeronotequal(self.mall),
        })
    }

    /// Constructor for the type of the `t:` fragment.
    pub fn cast_true(self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Correctness::cast_true(self.corr)?,
            mall: Malleability::cast_true(self.mall),
        })
    }

    /// Constructor for the type of the `u:` fragment.
    pub fn cast_unlikely(self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Correctness::cast_or_i_false(self.corr)?,
            mall: Malleability::cast_or_i_false(self.mall),
        })
    }

    /// Constructor for the type of the `l:` fragment.
    pub fn cast_likely(self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Correctness::cast_or_i_false(self.corr)?,
            mall: Malleability::cast_or_i_false(self.mall),
        })
    }

    /// Constructor for the type of the `and_b` fragment.
    pub fn and_b(left: Self, right: Self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Correctness::and_b(left.corr, right.corr)?,
            mall: Malleability::and_b(left.mall, right.mall),
        })
    }

    /// Constructor for the type of the `and_v` fragment.
    pub fn and_v(left: Self, right: Self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Correctness::and_v(left.corr, right.corr)?,
            mall: Malleability::and_v(left.mall, right.mall),
        })
    }

    /// Constructor for the type of the `or_b` fragment.
    pub fn or_b(left: Self, right: Self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Correctness::or_b(left.corr, right.corr)?,
            mall: Malleability::or_b(left.mall, right.mall),
        })
    }

    /// Constructor for the type of the `or_b` fragment.
    pub fn or_d(left: Self, right: Self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Correctness::or_d(left.corr, right.corr)?,
            mall: Malleability::or_d(left.mall, right.mall),
        })
    }

    /// Constructor for the type of the `or_c` fragment.
    pub fn or_c(left: Self, right: Self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Correctness::or_c(left.corr, right.corr)?,
            mall: Malleability::or_c(left.mall, right.mall),
        })
    }

    /// Constructor for the type of the `or_i` fragment.
    pub fn or_i(left: Self, right: Self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Correctness::or_i(left.corr, right.corr)?,
            mall: Malleability::or_i(left.mall, right.mall),
        })
    }

    /// Constructor for the type of the `and_or` fragment.
    pub fn and_or(a: Self, b: Self, c: Self) -> Result<Self, ErrorKind> {
        Ok(Type {
            corr: Correctness::and_or(a.corr, b.corr, c.corr)?,
            mall: Malleability::and_or(a.mall, b.mall, c.mall),
        })
    }

    /// Constructor for the type of the `thresh` fragment.
    pub fn threshold<S>(k: usize, n: usize, mut sub_ck: S) -> Result<Self, ErrorKind>
    where
        S: FnMut(usize) -> Result<Self, ErrorKind>,
    {
        Ok(Type {
            corr: Correctness::threshold(k, n, |n| Ok(sub_ck(n)?.corr))?,
            mall: Malleability::threshold(k, n, |n| Ok(sub_ck(n)?.mall))?,
        })
    }
}

impl Type {
    /// Compute the type of a fragment assuming all the children of
    /// Miniscript have been computed already.
    pub fn type_check<Pk, Ctx>(fragment: &Terminal<Pk, Ctx>) -> Result<Self, Error>
    where
        Pk: MiniscriptKey,
        Ctx: ScriptContext,
    {
        let wrap_err = |result: Result<Self, ErrorKind>| {
            result.map_err(|kind| Error { fragment_string: fragment.to_string(), error: kind })
        };

        let ret = match *fragment {
            Terminal::True => Ok(Self::TRUE),
            Terminal::False => Ok(Self::FALSE),
            Terminal::PkK(..) => Ok(Self::pk_k()),
            Terminal::PkH(..) | Terminal::RawPkH(..) => Ok(Self::pk_h()),
            Terminal::Multi(k, ref pks) | Terminal::MultiA(k, ref pks) => {
                if k == 0 {
                    return Err(Error {
                        fragment_string: fragment.to_string(),
                        error: ErrorKind::ZeroThreshold,
                    });
                }
                if k > pks.len() {
                    return Err(Error {
                        fragment_string: fragment.to_string(),
                        error: ErrorKind::OverThreshold(k, pks.len()),
                    });
                }
                match *fragment {
                    Terminal::Multi(..) => Ok(Self::multi()),
                    Terminal::MultiA(..) => Ok(Self::multi_a()),
                    _ => unreachable!(),
                }
            }
            Terminal::After(t) => {
                // Note that for CLTV this is a limitation not of Bitcoin but Miniscript. The
                // number on the stack would be a 5 bytes signed integer but Miniscript's B type
                // only consumes 4 bytes from the stack.
                if t == absolute::LockTime::ZERO.into() {
                    return Err(Error {
                        fragment_string: fragment.to_string(),
                        error: ErrorKind::InvalidTime,
                    });
                }
                Ok(Self::time())
            }
            Terminal::Older(t) => {
                if t == Sequence::ZERO || !t.is_relative_lock_time() {
                    return Err(Error {
                        fragment_string: fragment.to_string(),
                        error: ErrorKind::InvalidTime,
                    });
                }
                Ok(Self::time())
            }
            Terminal::Sha256(..) => Ok(Self::hash()),
            Terminal::Hash256(..) => Ok(Self::hash()),
            Terminal::Ripemd160(..) => Ok(Self::hash()),
            Terminal::Hash160(..) => Ok(Self::hash()),
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
                        fragment_string: fragment.to_string(),
                        error: ErrorKind::ZeroThreshold,
                    });
                }
                if k > subs.len() {
                    return Err(Error {
                        fragment_string: fragment.to_string(),
                        error: ErrorKind::OverThreshold(k, subs.len()),
                    });
                }

                let res = Self::threshold(k, subs.len(), |n| Ok(subs[n].ty));

                res.map_err(|kind| Error { fragment_string: fragment.to_string(), error: kind })
            }
        };
        if let Ok(ref ret) = ret {
            ret.sanity_checks()
        }
        ret
    }
}
