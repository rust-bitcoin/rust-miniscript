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

//! Correctness/Soundness type properties

use super::{ErrorKind, Property};

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
    /// Consumes 1 or more stack elements. If the fragment is
    /// satisfied, the top element must be nonzero. (This property
    /// cannot be applied to any type with a `W` base.)
    AnyNonZero,
}

impl Input {
    /// Check whether given `Input` is a subtype of `other`. That is,
    /// if some Input is `OneNonZero` then it must be `One`, hence `OneNonZero` is
    /// a subtype if `One`. Returns `true` for `a.is_subtype(a)`.
    fn is_subtype(&self, other: Self) -> bool {
        match (*self, other) {
            (x, y) if x == y => true,
            (Input::OneNonZero, Input::One)
            | (Input::OneNonZero, Input::AnyNonZero)
            | (_, Input::Any) => true,
            _ => false,
        }
    }
}

/// Structure representing the type properties of a fragment which are
/// relevant to completeness (are all expected branches actually accessible,
/// given some valid witness) and soundness (is it possible to satisfy the
/// Script without satisfying one of the Miniscript branches).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Correctness {
    /// The base type
    pub base: Base,
    /// Properties of the inputs
    pub input: Input,
    /// Whether it is definitely possible to dissatisfy the expression.
    /// If this is false, it does not necessarily mean that dissatisfaction
    /// is impossible (see `Dissat::None` for this property); it only means
    /// that we cannot depend on having a dissatisfaction when reasoning
    /// about completeness.
    pub dissatisfiable: bool,
    /// Whether the fragment's "nonzero" output on satisfaction is
    /// always the constant 1.
    pub unit: bool,
}

impl Correctness {
    /// Check whether the `self` is a subtype of `other` argument .
    /// This checks whether the argument `other` has attributes which are present
    /// in the given `Type`. This returns `true` on same arguments
    /// `a.is_subtype(a)` is `true`.
    pub fn is_subtype(&self, other: Self) -> bool {
        if self.base == other.base
            && self.input.is_subtype(other.input)
            && self.dissatisfiable >= other.dissatisfiable
            && self.unit >= other.unit
        {
            return true;
        }
        return false;
    }
}

impl Property for Correctness {
    fn sanity_checks(&self) {
        match self.base {
            Base::B => {}
            Base::K => {
                debug_assert!(self.unit);
            }
            Base::V => {
                debug_assert!(!self.unit);
                debug_assert!(!self.dissatisfiable);
            }
            Base::W => {
                debug_assert!(self.input != Input::OneNonZero);
                debug_assert!(self.input != Input::AnyNonZero);
            }
        }
    }

    fn from_true() -> Self {
        Correctness {
            base: Base::B,
            input: Input::Zero,
            dissatisfiable: false,
            unit: true,
        }
    }

    fn from_false() -> Self {
        Correctness {
            base: Base::B,
            input: Input::Zero,
            dissatisfiable: true,
            unit: true,
        }
    }

    fn from_pk_k() -> Self {
        Correctness {
            base: Base::K,
            input: Input::OneNonZero,
            dissatisfiable: true,
            unit: true,
        }
    }

    fn from_pk_h() -> Self {
        Correctness {
            base: Base::K,
            input: Input::AnyNonZero,
            dissatisfiable: true, // FIXME check with sipa
            unit: true,
        }
    }

    fn from_multi(_: usize, _: usize) -> Self {
        Correctness {
            base: Base::B,
            input: Input::AnyNonZero,
            dissatisfiable: true,
            unit: true,
        }
    }

    fn from_hash() -> Self {
        Correctness {
            base: Base::B,
            input: Input::OneNonZero,
            dissatisfiable: true,
            unit: true,
        }
    }

    fn from_time(_: u32) -> Self {
        Correctness {
            base: Base::B,
            input: Input::Zero,
            dissatisfiable: false,
            unit: false,
        }
    }

    fn from_txtemplate() -> Self {
        Correctness {
            base: Base::V,
            input: Input::Zero,
            dissatisfiable: false,
            unit: false,
        }
    }

    fn cast_alt(self) -> Result<Self, ErrorKind> {
        Ok(Correctness {
            base: match self.base {
                Base::B => Base::W,
                x => return Err(ErrorKind::ChildBase1(x)),
            },
            input: Input::Any,
            dissatisfiable: self.dissatisfiable,
            unit: self.unit,
        })
    }

    fn cast_swap(self) -> Result<Self, ErrorKind> {
        Ok(Correctness {
            base: match self.base {
                Base::B => Base::W,
                x => return Err(ErrorKind::ChildBase1(x)),
            },
            input: match self.input {
                Input::One | Input::OneNonZero => Input::Any,
                _ => return Err(ErrorKind::SwapNonOne),
            },
            dissatisfiable: self.dissatisfiable,
            unit: self.unit,
        })
    }

    fn cast_check(self) -> Result<Self, ErrorKind> {
        Ok(Correctness {
            base: match self.base {
                Base::K => Base::B,
                x => return Err(ErrorKind::ChildBase1(x)),
            },
            input: self.input,
            dissatisfiable: self.dissatisfiable,
            unit: true,
        })
    }

    fn cast_dupif(self) -> Result<Self, ErrorKind> {
        Ok(Correctness {
            base: match self.base {
                Base::V => Base::B,
                x => return Err(ErrorKind::ChildBase1(x)),
            },
            input: match self.input {
                Input::Zero => Input::OneNonZero,
                _ => return Err(ErrorKind::NonZeroDupIf),
            },
            dissatisfiable: true,
            unit: true,
        })
    }

    fn cast_verify(self) -> Result<Self, ErrorKind> {
        Ok(Correctness {
            base: match self.base {
                Base::B => Base::V,
                x => return Err(ErrorKind::ChildBase1(x)),
            },
            input: self.input,
            dissatisfiable: false,
            unit: false,
        })
    }

    fn cast_nonzero(self) -> Result<Self, ErrorKind> {
        if self.input != Input::OneNonZero && self.input != Input::AnyNonZero {
            return Err(ErrorKind::NonZeroZero);
        }
        Ok(Correctness {
            base: match self.base {
                Base::B => Base::B,
                x => return Err(ErrorKind::ChildBase1(x)),
            },
            input: self.input,
            dissatisfiable: true,
            unit: self.unit,
        })
    }

    fn cast_zeronotequal(self) -> Result<Self, ErrorKind> {
        Ok(Correctness {
            base: match self.base {
                Base::B => Base::B,
                x => return Err(ErrorKind::ChildBase1(x)),
            },
            input: self.input,
            dissatisfiable: self.dissatisfiable,
            unit: true,
        })
    }

    fn cast_true(self) -> Result<Self, ErrorKind> {
        Ok(Correctness {
            base: match self.base {
                Base::V => Base::B,
                x => return Err(ErrorKind::ChildBase1(x)),
            },
            input: self.input,
            dissatisfiable: false,
            unit: true,
        })
    }

    fn cast_or_i_false(self) -> Result<Self, ErrorKind> {
        Ok(Correctness {
            base: match self.base {
                Base::B => Base::B,
                x => return Err(ErrorKind::ChildBase1(x)),
            },
            input: match self.input {
                // could by `Input::OneNonZero` but the type system
                // isn't safe enough to capture that `0` is unsatisfiable
                Input::Zero => Input::One,
                _ => Input::Any,
            },
            dissatisfiable: true,
            unit: self.unit,
        })
    }

    fn and_b(left: Self, right: Self) -> Result<Self, ErrorKind> {
        Ok(Correctness {
            base: match (left.base, right.base) {
                (Base::B, Base::W) => Base::B,
                (x, y) => return Err(ErrorKind::ChildBase2(x, y)),
            },
            input: match (left.input, right.input) {
                (Input::Zero, Input::Zero) => Input::Zero,
                (Input::Zero, Input::One) | (Input::One, Input::Zero) => Input::One,
                (Input::Zero, Input::OneNonZero) | (Input::OneNonZero, Input::Zero) => {
                    Input::OneNonZero
                }
                (Input::OneNonZero, _)
                | (Input::AnyNonZero, _)
                | (Input::Zero, Input::AnyNonZero) => Input::AnyNonZero,
                _ => Input::Any,
            },
            dissatisfiable: left.dissatisfiable && right.dissatisfiable,
            unit: true,
        })
    }

    fn and_v(left: Self, right: Self) -> Result<Self, ErrorKind> {
        Ok(Correctness {
            base: match (left.base, right.base) {
                (Base::V, Base::B) => Base::B,
                (Base::V, Base::K) => Base::K,
                (Base::V, Base::V) => Base::V,
                (x, y) => return Err(ErrorKind::ChildBase2(x, y)),
            },
            input: match (left.input, right.input) {
                (Input::Zero, Input::Zero) => Input::Zero,
                (Input::Zero, Input::One) | (Input::One, Input::Zero) => Input::One,
                (Input::Zero, Input::OneNonZero) | (Input::OneNonZero, Input::Zero) => {
                    Input::OneNonZero
                }
                (Input::OneNonZero, _)
                | (Input::AnyNonZero, _)
                | (Input::Zero, Input::AnyNonZero) => Input::AnyNonZero,
                _ => Input::Any,
            },
            dissatisfiable: false,
            unit: right.unit,
        })
    }

    fn or_b(left: Self, right: Self) -> Result<Self, ErrorKind> {
        if !left.dissatisfiable {
            return Err(ErrorKind::LeftNotDissatisfiable);
        }
        if !right.dissatisfiable {
            return Err(ErrorKind::RightNotDissatisfiable);
        }
        Ok(Correctness {
            base: match (left.base, right.base) {
                (Base::B, Base::W) => Base::B,
                (x, y) => return Err(ErrorKind::ChildBase2(x, y)),
            },
            input: match (left.input, right.input) {
                (Input::Zero, Input::Zero) => Input::Zero,
                (Input::Zero, Input::One)
                | (Input::One, Input::Zero)
                | (Input::Zero, Input::OneNonZero)
                | (Input::OneNonZero, Input::Zero) => Input::One,
                _ => Input::Any,
            },
            dissatisfiable: true,
            unit: true,
        })
    }

    fn or_d(left: Self, right: Self) -> Result<Self, ErrorKind> {
        if !left.dissatisfiable {
            return Err(ErrorKind::LeftNotDissatisfiable);
        }
        if !left.unit {
            return Err(ErrorKind::LeftNotUnit);
        }
        Ok(Correctness {
            base: match (left.base, right.base) {
                (Base::B, Base::B) => Base::B,
                (x, y) => return Err(ErrorKind::ChildBase2(x, y)),
            },
            input: match (left.input, right.input) {
                (Input::Zero, Input::Zero) => Input::Zero,
                (Input::One, Input::Zero) | (Input::OneNonZero, Input::Zero) => Input::One,
                _ => Input::Any,
            },
            dissatisfiable: right.dissatisfiable,
            unit: right.unit,
        })
    }

    fn or_c(left: Self, right: Self) -> Result<Self, ErrorKind> {
        if !left.dissatisfiable {
            return Err(ErrorKind::LeftNotDissatisfiable);
        }
        if !left.unit {
            return Err(ErrorKind::LeftNotUnit);
        }
        Ok(Correctness {
            base: match (left.base, right.base) {
                (Base::B, Base::V) => Base::V,
                (x, y) => return Err(ErrorKind::ChildBase2(x, y)),
            },
            input: match (left.input, right.input) {
                (Input::Zero, Input::Zero) => Input::Zero,
                (Input::One, Input::Zero) | (Input::OneNonZero, Input::Zero) => Input::One,
                _ => Input::Any,
            },
            dissatisfiable: false,
            unit: false,
        })
    }

    fn or_i(left: Self, right: Self) -> Result<Self, ErrorKind> {
        Ok(Correctness {
            base: match (left.base, right.base) {
                (Base::B, Base::B) => Base::B,
                (Base::V, Base::V) => Base::V,
                (Base::K, Base::K) => Base::K,
                (x, y) => return Err(ErrorKind::ChildBase2(x, y)),
            },
            input: match (left.input, right.input) {
                (Input::Zero, Input::Zero) => Input::One,
                _ => Input::Any,
            },
            dissatisfiable: left.dissatisfiable || right.dissatisfiable,
            unit: left.unit && right.unit,
        })
    }

    fn and_or(a: Self, b: Self, c: Self) -> Result<Self, ErrorKind> {
        if !a.dissatisfiable {
            return Err(ErrorKind::LeftNotDissatisfiable);
        }
        if !a.unit {
            return Err(ErrorKind::LeftNotUnit);
        }
        Ok(Correctness {
            base: match (a.base, b.base, c.base) {
                (Base::B, Base::B, Base::B) => Base::B,
                (Base::B, Base::K, Base::K) => Base::K,
                (Base::B, Base::V, Base::V) => Base::V,
                (x, y, z) => return Err(ErrorKind::ChildBase3(x, y, z)),
            },
            input: match (a.input, b.input, c.input) {
                (Input::Zero, Input::Zero, Input::Zero) => Input::Zero,
                (Input::Zero, Input::One, Input::One)
                | (Input::Zero, Input::One, Input::OneNonZero)
                | (Input::Zero, Input::OneNonZero, Input::One)
                | (Input::Zero, Input::OneNonZero, Input::OneNonZero)
                | (Input::One, Input::Zero, Input::Zero)
                | (Input::OneNonZero, Input::Zero, Input::Zero) => Input::One,
                _ => Input::Any,
            },
            dissatisfiable: c.dissatisfiable,
            unit: b.unit && c.unit,
        })
    }

    fn threshold<S>(k: usize, n: usize, mut sub_ck: S) -> Result<Self, ErrorKind>
    where
        S: FnMut(usize) -> Result<Self, ErrorKind>,
    {
        let mut is_n = k == n;
        for i in 0..n {
            let subtype = sub_ck(i)?;
            if i == 0 {
                is_n &= subtype.input == Input::OneNonZero || subtype.input == Input::AnyNonZero;
                if subtype.base != Base::B {
                    return Err(ErrorKind::ThresholdBase(i, subtype.base));
                }
            } else {
                if subtype.base != Base::W {
                    return Err(ErrorKind::ThresholdBase(i, subtype.base));
                }
            }
            if !subtype.unit {
                return Err(ErrorKind::ThresholdNonUnit(i));
            }
            if !subtype.dissatisfiable {
                return Err(ErrorKind::ThresholdDissat(i));
            }
        }

        Ok(Correctness {
            base: Base::B,
            input: if is_n { Input::AnyNonZero } else { Input::Any },
            dissatisfiable: true,
            unit: true,
        })
    }
}
