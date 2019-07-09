// Miniscript
// Written in 2019 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

pub mod correctness;
pub mod malleability;

use std::{error, fmt};

use miniscript::astelem::AstElem;
pub use self::correctness::{Correctness, Base, Input};
pub use self::malleability::{Dissat, Malleability};

/// None-returning function to help type inference when we need a
/// closure that simply returns `None`
fn return_none<T>(_: usize) -> Option<T> { None }

/// Detailed type of a typechecker error
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum ErrorKind {
    /// Relative or absolute timelock had a time value of 0
    ZeroTime,
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
        k: usize,
        n: usize,
        n_strong: usize,
    },
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Error<Pk: Clone, Pkh: Clone> {
    /// The fragment that failed typecheck
    pub fragment: AstElem<Pk, Pkh>,
    /// The reason that typechecking failed
    pub error: ErrorKind,
}

impl<Pk, Pkh> error::Error for Error<Pk, Pkh>
where
    Pk: Clone + fmt::Debug + fmt::Display,
    Pkh: Clone + fmt::Debug + fmt::Display,
{
    fn cause(&self) -> Option<&error::Error> { None }

    fn description(&self) -> &str {
        "description() is deprecated; use Display"
    }
}

impl<Pk, Pkh> fmt::Display for Error<Pk, Pkh>
where
    Pk: Clone + fmt::Display,
    Pkh: Clone + fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.error {
            ErrorKind::ZeroTime => write!(
                f,
                "fragment «{}» represents a 0-valued timelock (use `1` instead)",
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
                self.fragment,
                k,
                n,
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
                self.fragment,
                base,
            ),
            ErrorKind::ChildBase2(base1, base2) => write!(
                f,
                "fragment «{}» cannot accept children of types {:?} and {:?}",
                self.fragment,
                base1,
                base2,
            ),
            ErrorKind::ChildBase3(base1, base2, base3) => write!(
                f,
                "fragment «{}» cannot accept children of types {:?}, {:?} and {:?}",
                self.fragment,
                base1,
                base2,
                base3,
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
                 and cannod be used in a threshold",
                self.fragment,
                idx,
            ),
            ErrorKind::ThresholdNonUnit(idx) => write!(
                f,
                "fragment «{}» sub-fragment {} is not a unit (does not put \
                 exactly 1 on the stack given a satisfying input)",
                self.fragment,
                idx,
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

/// Whether a fragment is OK to be used in non-segwit scripts
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum LegacySafe {
    /// The fragment can be used in pre-segwit contexts without concern
    /// about malleability attacks/unbounded 3rd-party fee stuffing. This
    /// means it has no `pk_h` constructions (cannot estimate public key
    /// size from a hash) and no `d:`/`or_i` constructions (cannot control
    /// the size of the switch input to `OP_IF`)
    LegacySafe,
    /// This fragment can only be safely used with Segwit
    SegwitOnly,
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

    /// Type property of the `Pk` fragment
    fn from_pk() -> Self;

    /// Type property of the `PkH` fragment
    fn from_pk_h() -> Self;

    /// Type property of a `ThreshM` fragment
    fn from_multi(k: usize, n: usize) -> Self;

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

    /// Type property of a relative timelock. Default implementation simply
    /// passes through to `from_time`
    fn from_after(t: u32) -> Self {
        Self::from_time(t)
    }

    /// Type property of an absolute timelock. Default implementation simply
    /// passes through to `from_time`
    fn from_older(t: u32) -> Self {
        Self::from_time(t)
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
    fn cast_true(self) -> Result<Self, ErrorKind>;

    /// Cast by changing `[X]` to `or_i([X], 0)` or `or_i(0, [X])`
    fn cast_or_i_false(self) -> Result<Self, ErrorKind>;

    /// Cast by changing `[X]` to `or_i([X], 0)`. Default implementation
    /// simply passes through to `cast_or_i_false`
    fn cast_unlikely(self) -> Result<Self, ErrorKind> {
        self.cast_or_i_false()
    }

    /// Cast by changing `[X]` to `or_i(0, [X])`. Default implementation
    /// simply passes through to `cast_or_i_false`
    fn cast_likely(self) -> Result<Self, ErrorKind> {
        self.cast_or_i_false()
    }

    /// Computes the type of an `AndB` fragment
    fn and_b(left: Self, right: Self) -> Result<Self, ErrorKind>;

    /// Computes the type of an `AndV` fragment
    fn and_v(left: Self, right: Self) -> Result<Self, ErrorKind>;

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

    fn threshold<S>(k: usize, n: usize, sub_ck: S) -> Result<Self, ErrorKind>
    where S: FnMut(usize) -> Result<Self, ErrorKind>;

    /// Compute the type of a fragment, given a function to look up
    /// the types of its children, if available and relevant for the
    /// given fragment
    fn type_check<Pk, Pkh, C>(
        fragment: &AstElem<Pk, Pkh>,
        mut child: C,
    ) -> Result<Self, Error<Pk, Pkh>>
    where
        C: FnMut(usize) -> Option<Self>,
        Pk: Clone,
        Pkh: Clone,
    {
        let mut get_child = |sub, n| child(n)
            .map(Ok)
            .unwrap_or_else(|| Self::type_check(sub, return_none));
        let wrap_err = |result: Result<Self, ErrorKind>| result
            .map_err(|kind| Error {
                fragment: fragment.clone(),
                error: kind,
            });

        let ret = match *fragment {
            AstElem::True => Ok(Self::from_true()),
            AstElem::False => Ok(Self::from_false()),
            AstElem::Pk(..) => Ok(Self::from_pk()),
            AstElem::PkH(..) => Ok(Self::from_pk_h()),
            AstElem::ThreshM(k, ref pks) => {
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
                Ok(Self::from_multi(k, pks.len()))
            },
            AstElem::After(t) => {
                if t == 0 {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::ZeroTime,
                    });
                }
                Ok(Self::from_after(t))
            },
            AstElem::Older(t) => {
                // FIXME check if t > 2^31 - 1
                if t == 0 {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::ZeroTime,
                    });
                }
                Ok(Self::from_older(t))
            },
            AstElem::Sha256(..) => Ok(Self::from_sha256()),
            AstElem::Hash256(..) => Ok(Self::from_hash256()),
            AstElem::Ripemd160(..) => Ok(Self::from_ripemd160()),
            AstElem::Hash160(..) => Ok(Self::from_hash160()),
            AstElem::Alt(ref sub)
                => wrap_err(Self::cast_alt(get_child(sub, 0)?)),
            AstElem::Swap(ref sub)
                => wrap_err(Self::cast_swap(get_child(sub, 0)?)),
            AstElem::Check(ref sub)
                => wrap_err(Self::cast_check(get_child(sub, 0)?)),
            AstElem::DupIf(ref sub)
                => wrap_err(Self::cast_dupif(get_child(sub, 0)?)),
            AstElem::Verify(ref sub)
                => wrap_err(Self::cast_verify(get_child(sub, 0)?)),
            AstElem::NonZero(ref sub)
                => wrap_err(Self::cast_nonzero(get_child(sub, 0)?)),
            AstElem::ZeroNotEqual(ref sub)
                => wrap_err(Self::cast_zeronotequal(get_child(sub, 0)?)),
            AstElem::AndB(ref l, ref r) => {
                let ltype = get_child(l, 0)?;
                let rtype = get_child(r, 1)?;
                wrap_err(Self::and_b(ltype, rtype))
            },
            AstElem::AndV(ref l, ref r) => {
                let ltype = get_child(l, 0)?;
                let rtype = get_child(r, 1)?;
                wrap_err(Self::and_v(ltype, rtype))
            },
            AstElem::OrB(ref l, ref r) => {
                let ltype = get_child(l, 0)?;
                let rtype = get_child(r, 1)?;
                wrap_err(Self::or_b(ltype, rtype))
            },
            AstElem::OrD(ref l, ref r) => {
                let ltype = get_child(l, 0)?;
                let rtype = get_child(r, 1)?;
                wrap_err(Self::or_d(ltype, rtype))
            },
            AstElem::OrC(ref l, ref r) => {
                let ltype = get_child(l, 0)?;
                let rtype = get_child(r, 1)?;
                wrap_err(Self::or_c(ltype, rtype))
            },
            AstElem::OrI(ref l, ref r) => {
                let ltype = get_child(l, 0)?;
                let rtype = get_child(r, 1)?;
                wrap_err(Self::or_i(ltype, rtype))
            },
            AstElem::AndOr(ref a, ref b, ref c) => {
                let atype = get_child(a, 0)?;
                let btype = get_child(b, 1)?;
                let ctype = get_child(c, 1)?;
                wrap_err(Self::and_or(atype, btype, ctype))
            },
            AstElem::Thresh(k, ref subs) => {
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
                let res = Self::threshold(
                    k,
                    subs.len(),
                    |n| match get_child(&subs[n], n) {
                        Ok(x) => Ok(x),
                        Err(e) => {
                            last_err_frag = Some(e.fragment);
                            Err(e.error)
                        },
                    },
                );

                res.map_err(|kind| Error {
                    fragment: last_err_frag.unwrap_or(fragment.clone()),
                    error: kind,
                })
            },
        };
        if let Ok(ref ret) = ret {
            ret.sanity_checks()
        }
        ret
    }
}

impl Property for Type {
    fn sanity_checks(&self) {
        debug_assert!(
            !self.corr.dissatisfiable
                || self.mall.dissat != Dissat::None
        );
        debug_assert!(
            self.mall.dissat == Dissat::None
                || self.corr.base != Base::V
        );
        debug_assert!(
            self.mall.safe
                || self.corr.base != Base::K
        );
        debug_assert!(
            self.mall.non_malleable
                || self.corr.input != Input::Zero
        );
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

    fn from_pk() -> Self {
        Type {
            corr: Property::from_pk(),
            mall: Property::from_pk(),
        }
    }

    fn from_pk_h() -> Self {
        Type {
            corr: Property::from_pk_h(),
            mall: Property::from_pk_h(),
        }
    }

    fn from_multi(k: usize, n: usize) -> Self {
        Type {
            corr: Property::from_multi(k, n),
            mall: Property::from_multi(k, n),
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

    fn from_after(t: u32) -> Self {
        Type {
            corr: Property::from_after(t),
            mall: Property::from_after(t),
        }
    }

    fn from_older(t: u32) -> Self {
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

    fn threshold<S>(
        k: usize,
        n: usize,
        mut sub_ck: S,
    )-> Result<Self, ErrorKind>
    where S: FnMut(usize) -> Result<Self, ErrorKind>
    {
        Ok(Type {
            corr: Property::threshold(k, n, |n| Ok(sub_ck(n)?.corr))?,
            mall: Property::threshold(k, n, |n| Ok(sub_ck(n)?.mall))?,
        })
    }
}
