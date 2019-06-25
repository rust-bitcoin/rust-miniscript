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

//! Types and Typing Rules

use std::{error, fmt};

use miniscript::astelem::AstElem;

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
    /// `andor` require their left child be uniquely dissatisfiable.
    /// This was not the case.
    LeftDissatNonUnique,
    /// `or_b` requires its right child be uniquely dissatisfiable
    RightDissatNonUnique,
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

/// Typechecker error
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
            ErrorKind::LeftDissatNonUnique => write!(
                f,
                "fragment «{}» requires its left child be uniquely
                 dissatisfiable",
                self.fragment,
            ),
            ErrorKind::RightDissatNonUnique => write!(
                f,
                "fragment «{}» requires its right child be uniquely
                 dissatisfiable",
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
                "fragment «{}» sub-fragment {} can not be uniquely
                 dissatisfied, so is unsafe to use in a threshold",
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

/// Basic type representing where the fragment can go
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Base {
    /// Takes its inputs from the top of the stack. Pushes
    /// nonzero if the condition is satisfied. If not, if it
    /// does not abort, then 0 is pushed.
    B,
    /// Takes its inputs from the top of the stack. Pushes a
    /// public key, regardless of satisfaction, onto the stack.
    /// Must be wrapped in `c:` to turn into any other type.
    K,
    /// Takes its inputs from the top of the stack, which
    /// must satisfy the condition (will abort otherwise).
    /// Does not push anything onto the stack.
    V,
    /// Takes from the stack its inputs + element X at the top.
    /// If the inputs satisfy the condition, [nonzero X] or
    /// [X nonzero] is pushed. If not, if it does not abort,
    /// then [0 X] or [X 0] is pushed.
    W,
}

/// Type property representing expectations about how many inputs
/// the fragment accepts, and assumptions about that
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Input {
    /// Consumes no stack elements under any circumstances
    Zero,
    /// Consumes exactly one stack element under all circumstances
    One,
    /// Consumes any number of stack elements
    Any,
    /// Consumes exactly one stack element. If the fragment is
    /// satisfied, this element must be nonzero.
    OneNonZero,
    /// Consumes 1 or more stack elements. If the fragemnt is
    /// satisfied, the top element must be nonzero. (This property
    /// cannot be applied to any type with a `W` base.)
    AnyNonZero,
}

/// Whether the fragment has a dissatisfaction, and if so, whether
/// it is unique. Affects both correctness and malleability-freeness,
/// since we assume 3rd parties are able to produce dissatisfactions
/// for all fragments.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Dissat {
    /// Fragment has no dissatisfactions and will abort given non-satisfying
    /// input.
    None,
    /// Fragment has a unique dissatisfaction, which is always available,
    /// and will push 0 given this dissatisfaction as input. The combination
    /// of `Dissat::Unique` and `Input::Zero` implies that a fragment is
    /// impossible to satisfy (is a `0` or equivalent).
    Unique,
    /// No assumptions may be made about dissatisfying this fragment. This
    /// does not necessarily mean that there are multiple dissatisfactions;
    /// there may be none, or none that are always available (e.g. for a
    /// `pk_h` the key preimage may not be available).
    Unknown,
}

/// Structure representing the type of a fragment with all
/// properties
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Type {
    /// The base type
    pub base: Base,
    /// Proprties of the inputs
    pub input: Input,
    /// Whether the fragment can be dissatisfied
    pub dissat: Dissat,
    /// Whether the fragment's "nonzero" output on satisfaction is
    /// always the constant 1. (This is always true for `W` base.)
    pub unit: bool,
    /// `true` if satisfactions cannot be created by any 3rd party
    /// who has not yet seen a satisfaction. (Hash preimages and
    /// signature checks are strong; timelocks are not.) Affects
    /// malleability.
    pub strong: bool,
    /// Pseudo-type-property representing whether this fragment ends
    /// in an opcode such as `OP_CHECKSIG` which has a `-VERIFY` form
    /// which can be used for no extra cost. Needed for size/cost
    /// estimation in various contexts
    pub has_verify_form: bool,
    /// Pseudo-type-property representing whether this fragment can
    /// be used in non-Segwit transactions. Any fragment containing
    /// `or_i` or `d:` or `pk_h` is not legacy-safe because we cannot
    /// control the size of witness-provided `OP_IF` inputs nor can
    /// we predict the size of keyhash preimages.
    pub legacy_safe: bool,
}

impl Type {
    /// Cast using the `Alt` wrapper
    pub fn cast_alt(&self) -> Result<Type, ErrorKind> {
        Ok(Type {
            base: match self.base {
                Base::B => Base::W,
                x => return Err(ErrorKind::ChildBase1(x)),
            },
            input: Input::Any,
            dissat: self.dissat,
            unit: self.unit,
            strong: self.strong,
            has_verify_form: false,
            legacy_safe: self.legacy_safe,
        })
    }

    /// Cast using the `Swap` wrapper
    pub fn cast_swap(&self) -> Result<Type, ErrorKind> {
        if self.input != Input::One && self.input != Input::OneNonZero {
            return Err(ErrorKind::SwapNonOne);
        }
        Ok(Type {
            base: match self.base {
                Base::B => Base::W,
                x => return Err(ErrorKind::ChildBase1(x)),
            },
            input: Input::Any,
            dissat: self.dissat,
            unit: self.unit,
            strong: self.strong,
            has_verify_form: self.has_verify_form,
            legacy_safe: self.legacy_safe,
        })
    }

    /// Cast using the `Check` wrapper
    pub fn cast_check(&self) -> Result<Type, ErrorKind> {
        Ok(Type {
            base: match self.base {
                Base::K => Base::B,
                x => return Err(ErrorKind::ChildBase1(x)),
            },
            input: self.input,
            dissat: self.dissat,
            unit: self.unit,
            strong: self.strong,
            has_verify_form: true,
            legacy_safe: self.legacy_safe
        })
    }

    /// Cast using the `DupIf` wrapper
    pub fn cast_dupif(&self) -> Result<Type, ErrorKind> {
        Ok(Type {
            base: match self.base {
                Base::V => Base::B,
                x => return Err(ErrorKind::ChildBase1(x)),
            },
            input: match self.input {
                Input::Zero => Input::OneNonZero,
                _ => Input::AnyNonZero,
            },
            dissat: Dissat::Unique,
            unit: true,
            strong: self.strong,
            has_verify_form: false,
            legacy_safe: self.legacy_safe,
        })
    }

    /// Cast using the `Verify` wrapper
    pub fn cast_verify(&self) -> Result<Type, ErrorKind> {
        Ok(Type {
            base: match self.base {
                Base::B => Base::V,
                x => return Err(ErrorKind::ChildBase1(x)),
            },
            input: self.input,
            dissat: Dissat::None,
            unit: false,
            strong: self.strong,
            has_verify_form: false,
            legacy_safe: self.legacy_safe,
        })
    }

    /// Cast using the `NonZero` wrapper
    pub fn cast_nonzero(&self) -> Result<Type, ErrorKind> {
        if self.input != Input::OneNonZero && self.input != Input::AnyNonZero {
            return Err(ErrorKind::NonZeroZero);
        }
        Ok(Type {
            base: match self.base {
                Base::B => Base::B,
                x => return Err(ErrorKind::ChildBase1(x)),
            },
            input: self.input,
            dissat: match self.dissat {
                Dissat::None => Dissat::Unique,
                _ => Dissat::Unknown,
            },
            unit: self.unit,
            strong: self.strong,
            has_verify_form: false,
            legacy_safe: self.legacy_safe,
        })
    }

    /// Cast using the `ZeroNotEqual` wrapper
    pub fn cast_zeronotequal(&self) -> Result<Type, ErrorKind> {
        Ok(Type {
            base: match self.base {
                Base::B => Base::B,
                x => return Err(ErrorKind::ChildBase1(x)),
            },
            input: self.input,
            dissat: self.dissat,
            unit: true,
            strong: self.strong,
            has_verify_form: false,
            legacy_safe: self.legacy_safe,
        })
    }

    /// Cast by changing `[X]` to `AndV([X], True)`
    pub fn cast_true(&self) -> Result<Type, ErrorKind> {
        Ok(Type {
            base: match self.base {
                Base::V => Base::B,
                x => return Err(ErrorKind::ChildBase1(x)),
            },
            input: self.input,
            dissat: Dissat::None,
            unit: true,
            strong: self.strong,
            has_verify_form: false,
            legacy_safe: self.legacy_safe,
        })
    }

    /// Cast by changing `[X]` to `or_i([X], 0)` or `or_i(0, [X])`
    pub fn cast_or_i_false(&self) -> Result<Type, ErrorKind> {
        Ok(Type {
            base: match self.base {
                Base::B => Base::B,
                x => return Err(ErrorKind::ChildBase1(x)),
            },
            input: match self.input {
                // could by `Input::OneNonZero` but the type system
                // isn't strong enough to capture that `0` is unsatisfiable
                Input::Zero => Input::One,
                _ => Input::Any,
            },
            dissat: match self.dissat {
                Dissat::None => Dissat::Unique,
                _ => Dissat::Unknown,
            },
            unit: self.unit,
            strong: self.strong,
            has_verify_form: false,
            legacy_safe: self.legacy_safe,
        })
    }

    /// Computes the type of a fragment, optionally taking a list
    /// of known types for all child nodes to avoid recomputation.
    /// If a list is provided, all child types must be given or
    /// else the function will panic with an "array index out of
    /// bounds" error.
    pub fn from_fragment<'a, C, Pk, Pkh>(
        fragment: &AstElem<Pk, Pkh>,
        child_types: C,
    ) -> Result<Type, Error<Pk, Pkh>>
    where
        C: Copy + Into<Option<&'a [Type]>>,
        Pk: Clone,
        Pkh: Clone,
    {
        let ret = match *fragment {
            AstElem::True => Type {
                base: Base::B,
                input: Input::Zero,
                dissat: Dissat::None,
                unit: true,
                strong: false,
                has_verify_form: false,
                legacy_safe: true,
            },
            AstElem::False => Type {
                base: Base::B,
                input: Input::Zero,
                dissat: Dissat::Unique,
                unit: true,
                strong: true,
                has_verify_form: false,
                legacy_safe: true,
            },
            AstElem::Pk(..) => Type {
                base: Base::K,
                input: Input::OneNonZero,
                dissat: Dissat::Unique,
                unit: true,
                strong: true,
                has_verify_form: false,
                legacy_safe: true,
            },
            AstElem::PkH(..) => Type {
                base: Base::K,
                input: Input::AnyNonZero,
                dissat: Dissat::Unknown,
                unit: true,
                strong: true,
                has_verify_form: false,
                legacy_safe: false,
            },
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
                Type {
                    base: Base::B,
                    input: Input::AnyNonZero,
                    dissat: Dissat::Unique,
                    unit: true,
                    strong: true,
                    has_verify_form: true,
                    legacy_safe: true,
                }
            },
            AstElem::After(t) | AstElem::Older(t) => {
                if t == 0 {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::ZeroTime,
                    });
                }
                Type {
                    base: Base::B,
                    input: Input::Zero,
                    dissat: Dissat::None,
                    unit: false,
                    strong: false,
                    has_verify_form: false,
                    legacy_safe: true,
                }
            },
            AstElem::Sha256(..)
                | AstElem::Hash256(..)
                | AstElem::Ripemd160(..)
                | AstElem::Hash160(..) => Type {
                    base: Base::B,
                    input: Input::OneNonZero,
                    dissat: Dissat::Unknown,
                    unit: true,
                    strong: true,
                    has_verify_form: true,
                    legacy_safe: true,
                },
            AstElem::AndV(ref l, ref r) => {
                let ltype = child_types
                    .into()
                    .map(|arr| arr[0])
                    .unwrap_or(Type::from_fragment(l, None)?);
                let rtype = child_types
                    .into()
                    .map(|arr| arr[1])
                    .unwrap_or(Type::from_fragment(r, None)?);
                Type {
                    base: match (ltype.base, rtype.base) {
                        (Base::V, Base::B) => Base::B,
                        (Base::V, Base::K) => Base::K,
                        (Base::V, Base::V) => Base::V,
                        (x, y) => return Err(Error {
                            fragment: fragment.clone(),
                            error: ErrorKind::ChildBase2(x, y),
                        }),
                    },
                    input: match (ltype.input, rtype.input) {
                        (Input::Zero, Input::Zero) => Input::Zero,
                        (Input::Zero, Input::One)
                            | (Input::One, Input::Zero) => Input::One,
                        (Input::Zero, Input::OneNonZero)
                            | (Input::OneNonZero, Input::Zero) => Input::OneNonZero,
                        (Input::AnyNonZero, _)
                            | (Input::Zero, Input::AnyNonZero) => Input::AnyNonZero,
                        _ => Input::Any,
                    },
                    dissat: match (ltype.dissat, rtype.dissat) {
                        (Dissat::None, Dissat::None) => Dissat::None,
                        _ => Dissat::Unknown,
                    },
                    unit: rtype.unit,
                    strong: ltype.strong || rtype.strong,
                    has_verify_form: rtype.has_verify_form,
                    legacy_safe: ltype.legacy_safe && rtype.legacy_safe,
                }
            },
            AstElem::AndB(ref l, ref r) => {
                let ltype = child_types
                    .into()
                    .map(|arr| arr[0])
                    .unwrap_or(Type::from_fragment(l, None)?);
                let rtype = child_types
                    .into()
                    .map(|arr| arr[1])
                    .unwrap_or(Type::from_fragment(r, None)?);
                Type {
                    base: match (ltype.base, rtype.base) {
                        (Base::B, Base::W) => Base::B,
                        (x, y) => return Err(Error {
                            fragment: fragment.clone(),
                            error: ErrorKind::ChildBase2(x, y),
                        }),
                    },
                    input: match (ltype.input, rtype.input) {
                        (Input::Zero, Input::Zero) => Input::Zero,
                        (Input::Zero, Input::One)
                            | (Input::One, Input::Zero) => Input::One,
                        (Input::Zero, Input::OneNonZero)
                            | (Input::OneNonZero, Input::Zero) => Input::OneNonZero,
                        (Input::AnyNonZero, _)
                            | (Input::Zero, Input::AnyNonZero) => Input::AnyNonZero,
                        _ => Input::Any,
                    },
                    dissat: match (ltype.dissat, rtype.dissat) {
                        (Dissat::None, Dissat::None) => Dissat::None,
                        (Dissat::Unique, Dissat::Unique) => {
                            if ltype.strong && rtype.strong {
                                Dissat::Unique
                            } else {
                                Dissat::Unknown
                            }
                        }
                        _ => Dissat::Unknown,
                    },
                    unit: true,
                    strong: ltype.strong || rtype.strong,
                    has_verify_form: false,
                    legacy_safe: ltype.legacy_safe && rtype.legacy_safe,
                }
            },
            AstElem::OrB(ref l, ref r) => {
                let ltype = child_types
                    .into()
                    .map(|arr| arr[0])
                    .unwrap_or(Type::from_fragment(l, None)?);
                let rtype = child_types
                    .into()
                    .map(|arr| arr[1])
                    .unwrap_or(Type::from_fragment(r, None)?);
                if ltype.dissat != Dissat::Unique {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::LeftDissatNonUnique,
                    });
                }
                if rtype.dissat != Dissat::Unique {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::RightDissatNonUnique,
                    });
                }
                if !ltype.strong && !rtype.strong {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::NoStrongChild,
                    });
                }
                Type {
                    base: match (ltype.base, rtype.base) {
                        (Base::B, Base::W) => Base::B,
                        (x, y) => return Err(Error {
                            fragment: fragment.clone(),
                            error: ErrorKind::ChildBase2(x, y),
                        }),
                    },
                    input: match (ltype.input, rtype.input) {
                        (Input::Zero, Input::Zero) => Input::Zero,
                        (Input::Zero, Input::One)
                            | (Input::One, Input::Zero)
                            | (Input::Zero, Input::OneNonZero)
                            | (Input::OneNonZero, Input::Zero) => Input::One,
                        _ => Input::Any,
                    },
                    // Assumes both inputs have `Dissat::Unique` (checked above)
                    dissat: Dissat::Unique,
                    unit: true,
                    strong: ltype.strong && rtype.strong,
                    has_verify_form: false,
                    legacy_safe: ltype.legacy_safe && rtype.legacy_safe,
                }
            },
            AstElem::OrD(ref l, ref r) => {
                let ltype = child_types
                    .into()
                    .map(|arr| arr[0])
                    .unwrap_or(Type::from_fragment(l, None)?);
                let rtype = child_types
                    .into()
                    .map(|arr| arr[1])
                    .unwrap_or(Type::from_fragment(r, None)?);
                if !ltype.unit {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::LeftNotUnit,
                    });
                }
                if ltype.dissat != Dissat::Unique {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::LeftDissatNonUnique,
                    });
                }
                if !ltype.strong && !rtype.strong {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::NoStrongChild,
                    });
                }
                Type {
                    base: match (ltype.base, rtype.base) {
                        (Base::B, Base::B) => Base::B,
                        (x, y) => return Err(Error {
                            fragment: fragment.clone(),
                            error: ErrorKind::ChildBase2(x, y),
                        }),
                    },
                    input: match (ltype.input, rtype.input) {
                        (Input::Zero, Input::Zero) => Input::Zero,
                        (Input::One, Input::Zero)
                            | (Input::OneNonZero, Input::Zero) => Input::One,
                        _ => Input::Any,
                    },
                    // Assumes left input has `Dissat::Unique` (checked above)
                    dissat: rtype.dissat,
                    unit: rtype.unit,
                    strong: ltype.strong && rtype.strong,
                    has_verify_form: false,
                    legacy_safe: ltype.legacy_safe && rtype.legacy_safe,
                }
            },
            AstElem::OrC(ref l, ref r) => {
                let ltype = child_types
                    .into()
                    .map(|arr| arr[0])
                    .unwrap_or(Type::from_fragment(l, None)?);
                let rtype = child_types
                    .into()
                    .map(|arr| arr[1])
                    .unwrap_or(Type::from_fragment(r, None)?);
                if ltype.dissat != Dissat::Unique {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::LeftDissatNonUnique,
                    });
                }
                if !ltype.unit {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::LeftNotUnit,
                    });
                }
                if !ltype.strong && !rtype.strong {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::NoStrongChild,
                    });
                }
                Type {
                    base: match (ltype.base, rtype.base) {
                        (Base::B, Base::V) => Base::V,
                        (x, y) => return Err(Error {
                            fragment: fragment.clone(),
                            error: ErrorKind::ChildBase2(x, y),
                        }),
                    },
                    input: match (ltype.input, rtype.input) {
                        (Input::Zero, Input::Zero) => Input::Zero,
                        (Input::One, Input::Zero)
                            | (Input::OneNonZero, Input::Zero) => Input::One,
                        _ => Input::Any,
                    },
                    // Implied by being a `V`
                    dissat: Dissat::None,
                    unit: false,
                    strong: ltype.strong && rtype.strong,
                    has_verify_form: false,
                    legacy_safe: ltype.legacy_safe && rtype.legacy_safe,
                }
            },
            AstElem::OrI(ref l, ref r) => {
                let ltype = child_types
                    .into()
                    .map(|arr| arr[0])
                    .unwrap_or(Type::from_fragment(l, None)?);
                let rtype = child_types
                    .into()
                    .map(|arr| arr[1])
                    .unwrap_or(Type::from_fragment(r, None)?);
                if !ltype.strong && !rtype.strong {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::NoStrongChild,
                    });
                }
                Type {
                    base: match (ltype.base, rtype.base) {
                        (Base::B, Base::B) => Base::B,
                        (Base::V, Base::V) => Base::V,
                        (Base::K, Base::K) => Base::K,
                        (x, y) => return Err(Error {
                            fragment: fragment.clone(),
                            error: ErrorKind::ChildBase2(x, y),
                        }),
                    },
                    input: match (ltype.input, rtype.input) {
                        (Input::Zero, Input::Zero) => Input::One,
                        _ => Input::Any,
                    },
                    dissat: match (ltype.dissat, rtype.dissat) {
                        (Dissat::None, Dissat::Unique) => Dissat::Unique,
                        (Dissat::Unique, Dissat::None) => Dissat::Unique,
                        (Dissat::None, Dissat::None) => Dissat::None,
                        _ => Dissat::Unknown,
                    },
                    unit: ltype.unit && rtype.unit,
                    strong: ltype.strong && rtype.strong,
                    has_verify_form: false,
                    legacy_safe: ltype.legacy_safe && rtype.legacy_safe,
                }
            },
            AstElem::AndOr(ref a, ref b, ref c) => {
                let atype = child_types
                    .into()
                    .map(|arr| arr[0])
                    .unwrap_or(Type::from_fragment(a, None)?);
                let btype = child_types
                    .into()
                    .map(|arr| arr[1])
                    .unwrap_or(Type::from_fragment(b, None)?);
                let ctype = child_types
                    .into()
                    .map(|arr| arr[2])
                    .unwrap_or(Type::from_fragment(c, None)?);
                if atype.dissat != Dissat::Unique {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::LeftDissatNonUnique,
                    });
                }
                if !atype.unit {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::LeftNotUnit,
                    });
                }
                if !atype.strong && !btype.strong && !ctype.strong {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::NoStrongChild,
                    });
                }
                Type {
                    base: match (atype.base, btype.base, ctype.base) {
                        (Base::B, Base::B, Base::B) => Base::B,
                        (Base::B, Base::K, Base::K) => Base::K,
                        (Base::B, Base::V, Base::V) => Base::V,
                        (x, y, z) => return Err(Error {
                            fragment: fragment.clone(),
                            error: ErrorKind::ChildBase3(x, y, z),
                        }),
                    },
                    input: match (atype.input, btype.input, ctype.input) {
                        (Input::Zero, Input::Zero, Input::Zero) => Input::Zero,
                        (Input::Zero, Input::One, Input::One)
                            | (Input::Zero, Input::One, Input::OneNonZero)
                            | (Input::Zero, Input::OneNonZero, Input::One)
                            | (Input::Zero, Input::OneNonZero, Input::OneNonZero)
                            | (Input::One, Input::Zero, Input::Zero)
                            | (Input::OneNonZero, Input::Zero, Input::Zero) => Input::One,
                        _ => Input::Any,
                    },
                    dissat: match (atype.strong, btype.dissat, ctype.dissat) {
                        (_, Dissat::None, Dissat::Unique) => Dissat::Unique,
                        (true, _, Dissat::Unique) => Dissat::Unique,
                        (_, Dissat::None, Dissat::None) => Dissat::None,
                        _ => Dissat::Unknown,
                    },
                    unit: btype.unit && ctype.unit,
                    strong: (atype.strong || btype.strong) && ctype.strong,
                    has_verify_form: false,
                    legacy_safe: atype.legacy_safe
                        && btype.legacy_safe
                        && ctype.legacy_safe,
                }
            },
            AstElem::Alt(ref sub) => {
                let subtype = child_types
                    .into()
                    .map(|arr| arr[0])
                    .unwrap_or(Type::from_fragment(sub, None)?);
                match subtype.cast_alt() {
                    Ok(t) => t,
                    Err(kind) => return Err(Error {
                        fragment: fragment.clone(),
                        error: kind,
                    }),
                }
            },
            AstElem::Swap(ref sub) => {
                let subtype = child_types
                    .into()
                    .map(|arr| arr[0])
                    .unwrap_or(Type::from_fragment(sub, None)?);
                match subtype.cast_swap() {
                    Ok(t) => t,
                    Err(kind) => return Err(Error {
                        fragment: fragment.clone(),
                        error: kind,
                    }),
                }
            },
            AstElem::Check(ref sub) => {
                let subtype = child_types
                    .into()
                    .map(|arr| arr[0])
                    .unwrap_or(Type::from_fragment(sub, None)?);
                match subtype.cast_check() {
                    Ok(t) => t,
                    Err(kind) => return Err(Error {
                        fragment: fragment.clone(),
                        error: kind,
                    }),
                }
            },
            AstElem::DupIf(ref sub) => {
                let subtype = child_types
                    .into()
                    .map(|arr| arr[0])
                    .unwrap_or(Type::from_fragment(sub, None)?);
                match subtype.cast_dupif() {
                    Ok(t) => t,
                    Err(kind) => return Err(Error {
                        fragment: fragment.clone(),
                        error: kind,
                    }),
                }
            },
            AstElem::Verify(ref sub) => {
                let subtype = child_types
                    .into()
                    .map(|arr| arr[0])
                    .unwrap_or(Type::from_fragment(sub, None)?);
                match subtype.cast_verify() {
                    Ok(t) => t,
                    Err(kind) => return Err(Error {
                        fragment: fragment.clone(),
                        error: kind,
                    }),
                }
            },
            AstElem::NonZero(ref sub) => {
                let subtype = child_types
                    .into()
                    .map(|arr| arr[0])
                    .unwrap_or(Type::from_fragment(sub, None)?);
                match subtype.cast_nonzero() {
                    Ok(t) => t,
                    Err(kind) => return Err(Error {
                        fragment: fragment.clone(),
                        error: kind,
                    }),
                }
            },
            AstElem::ZeroNotEqual(ref sub) => {
                let subtype = child_types
                    .into()
                    .map(|arr| arr[0])
                    .unwrap_or(Type::from_fragment(sub, None)?);
                match subtype.cast_zeronotequal() {
                    Ok(t) => t,
                    Err(kind) => return Err(Error {
                        fragment: fragment.clone(),
                        error: kind,
                    }),
                }
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

                let mut is_n = k == subs.len();
                let mut strong_count = 0;
                let mut legacy_safe = true;
                for (n, sub) in subs.iter().enumerate() {
                    let subtype = child_types
                        .into()
                        .map(|arr| arr[n])
                        .unwrap_or(Type::from_fragment(sub, None)?);
                    if n == 0 {
                        is_n &= subtype.input == Input::OneNonZero
                            || subtype.input == Input::AnyNonZero;
                        if subtype.base != Base::B {
                            return Err(Error {
                                fragment: fragment.clone(),
                                error: ErrorKind::ThresholdBase(
                                    n,
                                    subtype.base,
                                ),
                            });
                        }
                    } else {
                        if subtype.base != Base::W {
                            return Err(Error {
                                fragment: fragment.clone(),
                                error: ErrorKind::ThresholdBase(
                                    n,
                                    subtype.base,
                                ),
                            });
                        }
                    }
                    legacy_safe &= subtype.legacy_safe;
                    if subtype.strong {
                        strong_count += 1;
                    }
                    if !subtype.unit {
                        return Err(Error {
                            fragment: fragment.clone(),
                            error: ErrorKind::ThresholdNonUnit(n),
                        });
                    }
                    if subtype.dissat != Dissat::Unique {
                        return Err(Error {
                            fragment: fragment.clone(),
                            error: ErrorKind::ThresholdDissat(n),
                        });
                    }
                }
                if strong_count < subs.len() - k {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::ThresholdNotStrong {
                            k: k,
                            n: subs.len(),
                            n_strong: strong_count,
                        },
                    });
                }
                Type {
                    base: Base::B,
                    input: if is_n { Input::AnyNonZero } else { Input::Any },
                    dissat: Dissat::Unique,
                    unit: true,
                    strong: strong_count >= subs.len() - k + 1,
                    has_verify_form: true,
                    legacy_safe: legacy_safe
                }
            },
        };
        // Sanity checks
        match ret.base {
            Base::B => {},
            Base::K => {
                debug_assert!(ret.unit);
                debug_assert!(ret.strong);
                debug_assert!(ret.dissat != Dissat::None);
            },
            Base::V => {
                debug_assert!(!ret.unit);
                debug_assert!(ret.dissat == Dissat::None);
            },
            Base::W => {
                debug_assert!(ret.input != Input::OneNonZero);
                debug_assert!(ret.input != Input::AnyNonZero);
            },
        }
        // Return
        Ok(ret)
    }
}
