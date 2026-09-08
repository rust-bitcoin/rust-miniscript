// SPDX-License-Identifier: CC0-1.0

//! Malleability-related Type properties

/// Whether the fragment has a dissatisfaction, and if so, whether
/// it is unique.
///
/// Affects both correctness and malleability-freeness,
/// since we assume 3rd parties are able to produce dissatisfactions
/// for all fragments.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Dissat {
    /// Fragment has no dissatisfactions and will abort given non-satisfying
    /// input.
    None,
    /// Fragment has a unique dissatisfaction, which is always available,
    /// and will push 0 given this dissatisfaction as input.
    ///
    /// The combination
    /// of `Dissat::Unique` and `Input::Zero` implies that a fragment is
    /// impossible to satisfy (is a `0` or equivalent).
    Unique,
    /// No assumptions may be made about dissatisfying this fragment.
    ///
    /// This
    /// does not necessarily mean that there are multiple dissatisfactions;
    /// there may be none, or none that are always available (e.g. for a
    /// `pk_h` the key preimage may not be available).
    Unknown,
}

impl Dissat {
    // FIXME rustc should eventually support derived == on enums in constfns
    const fn constfn_eq(self, other: Self) -> bool {
        matches!(
            (self, other),
            (Self::None, Self::None)
                | (Self::Unique, Self::Unique)
                | (Self::Unknown, Self::Unknown)
        )
    }

    /// Check whether given `Dissat` is a subtype of `other`. That is,
    /// if some Dissat is `Unique` then it must be `Unknown`.
    const fn is_subtype(&self, other: Self) -> bool {
        match (*self, other) {
            (x, y) if x.constfn_eq(y) => true,
            (_, Self::Unknown) => true,
            _ => false,
        }
    }
}

/// The malleability properties of a fragment.
///
/// The "s", "f" and "e" properties of a fragment only describe its
/// satisfactions and dissatisfactions if the fragment meets the
/// non-malleability requirement of every fragment it is built from. Once a
/// fragment is malleable, so is every fragment containing it, and nothing can
/// be concluded from those three properties about any of them. They are
/// therefore only carried for a fragment that is known to be non-malleable.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Malleability {
    /// The fragment has no guaranteed non-malleable satisfaction, so nothing
    /// is known about its dissatisfactions or about whether satisfying it
    /// requires a signature.
    Malleable,
    /// The fragment is guaranteed to have a non-malleable satisfaction if it
    /// has a satisfaction at all.
    NonMalleable {
        /// Properties of dissatisfying inputs.
        dissat: Dissat,
        /// `true` if every satisfaction requires a signature. `false` for
        /// hash preimages and timelocks, since they can be satisfied without
        /// a signature.
        signed: bool,
    },
}

impl Malleability {
    /// Malleability data for the `1` combinator
    pub const TRUE: Self = Self::NonMalleable { dissat: Dissat::None, signed: false };

    /// Malleability data for the `0` combinator
    pub const FALSE: Self = Self::NonMalleable { dissat: Dissat::Unique, signed: true };

    /// Whether the fragment is guaranteed to have a non-malleable
    /// satisfaction, if it has a satisfaction at all.
    pub const fn is_non_malleable(&self) -> bool { matches!(self, Self::NonMalleable { .. }) }

    /// The dissatisfaction properties of the fragment, or `None` for a
    /// malleable fragment, about which nothing is known.
    pub const fn dissat(&self) -> Option<Dissat> {
        match self {
            Self::Malleable => None,
            Self::NonMalleable { dissat, .. } => Some(*dissat),
        }
    }

    /// Whether every satisfaction of the fragment requires a signature, or
    /// `None` for a malleable fragment, about which nothing is known.
    pub const fn signed(&self) -> Option<bool> {
        match self {
            Self::Malleable => None,
            Self::NonMalleable { signed, .. } => Some(*signed),
        }
    }

    /// Check whether the `self` is a subtype of `other` argument.
    ///
    /// This checks whether the argument `other` has attributes which are present
    /// in the given `Type`. This returns `true` on same arguments
    /// `a.is_subtype(a)` is `true`.
    pub const fn is_subtype(&self, other: Self) -> bool {
        match (self, other) {
            // A malleable fragment promises nothing, so everything is a
            // subtype of it, and it is a subtype of nothing else.
            (_, Self::Malleable) => true,
            (Self::Malleable, Self::NonMalleable { .. }) => false,
            (
                Self::NonMalleable { dissat, signed },
                Self::NonMalleable { dissat: other_dissat, signed: other_signed },
            ) => dissat.is_subtype(other_dissat) && *signed >= other_signed,
        }
    }
}

impl Malleability {
    /// Constructor for the malleabilitiy properties of the `pk_k` fragment.
    pub const fn pk_k() -> Self { Self::NonMalleable { dissat: Dissat::Unique, signed: true } }

    /// Constructor for the malleabilitiy properties of the `pk_h` fragment.
    pub const fn pk_h() -> Self { Self::NonMalleable { dissat: Dissat::Unique, signed: true } }

    /// Constructor for the malleabilitiy properties of the `multi` fragment.
    pub const fn multi() -> Self { Self::NonMalleable { dissat: Dissat::Unique, signed: true } }

    /// Constructor for the malleabilitiy properties of the `sortedmulti` fragment.
    pub const fn sortedmulti() -> Self {
        Self::NonMalleable { dissat: Dissat::Unique, signed: true }
    }

    /// Constructor for the malleabilitiy properties of the `multi_a` fragment.
    pub const fn multi_a() -> Self { Self::NonMalleable { dissat: Dissat::Unique, signed: true } }

    /// Constructor for the malleabilitiy properties of the `sortedmulti_a` fragment.
    pub const fn sortedmulti_a() -> Self {
        Self::NonMalleable { dissat: Dissat::Unique, signed: true }
    }

    /// Constructor for the malleabilitiy properties of any of the hash fragments.
    pub const fn hash() -> Self { Self::NonMalleable { dissat: Dissat::Unknown, signed: false } }

    /// Constructor for the malleabilitiy properties of either `after` or `older`.
    pub const fn time() -> Self { Self::NonMalleable { dissat: Dissat::None, signed: false } }

    /// Constructor for the malleabilitiy properties of the `a:` fragment.
    pub const fn cast_alt(self) -> Self { self }

    /// Constructor for the malleabilitiy properties of the `s:` fragment.
    pub const fn cast_swap(self) -> Self { self }

    /// Constructor for the malleabilitiy properties of the `c:` fragment.
    pub const fn cast_check(self) -> Self { self }

    /// Constructor for the malleabilitiy properties of the `d:` fragment.
    pub const fn cast_dupif(self) -> Self { self.cast_dissat_if_forced() }

    /// Constructor for the malleabilitiy properties of the `v:` fragment.
    pub const fn cast_verify(self) -> Self { self.with_dissat(Dissat::None) }

    /// Constructor for the malleabilitiy properties of the `j:` fragment.
    pub const fn cast_nonzero(self) -> Self { self.cast_dissat_if_forced() }

    /// Constructor for the malleabilitiy properties of the `n:` fragment.
    pub const fn cast_zeronotequal(self) -> Self { self }

    /// Constructor for the malleabilitiy properties of the `t:` fragment.
    pub const fn cast_true(self) -> Self { self.with_dissat(Dissat::None) }

    /// Constructor for the malleabilitiy properties of the `l:` or `u:` fragments.
    pub const fn cast_or_i_false(self) -> Self { self.cast_dissat_if_forced() }

    /// Replaces the dissatisfaction properties of a non-malleable fragment,
    /// keeping a malleable one malleable.
    const fn with_dissat(self, dissat: Dissat) -> Self {
        match self {
            Self::Malleable => Self::Malleable,
            Self::NonMalleable { signed, .. } => Self::NonMalleable { dissat, signed },
        }
    }

    /// The malleability of the three wrappers that turn a fragment which
    /// cannot be dissatisfied into one with a unique dissatisfaction, `d:`,
    /// `j:` and the `or_i` the `l:` and `u:` wrappers desugar to.
    const fn cast_dissat_if_forced(self) -> Self {
        match self {
            Self::Malleable => Self::Malleable,
            Self::NonMalleable { dissat, signed } => Self::NonMalleable {
                dissat: if dissat.constfn_eq(Dissat::None) {
                    Dissat::Unique
                } else {
                    Dissat::Unknown
                },
                signed,
            },
        }
    }

    /// Constructor for the malleabilitiy properties of the `and_b` fragment.
    pub const fn and_b(left: Self, right: Self) -> Self {
        let (left_dissat, left_signed, right_dissat, right_signed) = match (left, right) {
            (
                Self::NonMalleable { dissat: ld, signed: ls },
                Self::NonMalleable { dissat: rd, signed: rs },
            ) => (ld, ls, rd, rs),
            _ => return Self::Malleable,
        };

        Self::NonMalleable {
            dissat: match (left_dissat, right_dissat) {
                (Dissat::None, Dissat::None) => Dissat::None,
                (Dissat::None, _) if left_signed => Dissat::None,
                (_, Dissat::None) if right_signed => Dissat::None,
                (Dissat::Unique, Dissat::Unique) => {
                    if left_signed && right_signed {
                        Dissat::Unique
                    } else {
                        Dissat::Unknown
                    }
                }
                _ => Dissat::Unknown,
            },
            signed: left_signed || right_signed,
        }
    }

    /// Constructor for the malleabilitiy properties of the `and_v` fragment.
    pub const fn and_v(left: Self, right: Self) -> Self {
        let (left_signed, right_dissat, right_signed) = match (left, right) {
            (
                Self::NonMalleable { signed: ls, .. },
                Self::NonMalleable { dissat: rd, signed: rs },
            ) => (ls, rd, rs),
            _ => return Self::Malleable,
        };

        Self::NonMalleable {
            dissat: match (left_signed, right_dissat) {
                (_, Dissat::None) => Dissat::None, // fy
                (true, _) => Dissat::None,         // sx
                _ => Dissat::Unknown,
            },
            signed: left_signed || right_signed,
        }
    }

    /// Constructor for the malleabilitiy properties of the `or_b` fragment.
    pub const fn or_b(left: Self, right: Self) -> Self {
        let (left_dissat, left_signed, right_dissat, right_signed) = match (left, right) {
            (
                Self::NonMalleable { dissat: ld, signed: ls },
                Self::NonMalleable { dissat: rd, signed: rs },
            ) => (ld, ls, rd, rs),
            _ => return Self::Malleable,
        };
        if !left_dissat.constfn_eq(Dissat::Unique)
            || !right_dissat.constfn_eq(Dissat::Unique)
            || !(left_signed || right_signed)
        {
            return Self::Malleable;
        }

        Self::NonMalleable { dissat: Dissat::Unique, signed: left_signed && right_signed }
    }

    /// Constructor for the malleabilitiy properties of the `or_d` fragment.
    pub const fn or_d(left: Self, right: Self) -> Self {
        let (left_dissat, left_signed, right_dissat, right_signed) = match (left, right) {
            (
                Self::NonMalleable { dissat: ld, signed: ls },
                Self::NonMalleable { dissat: rd, signed: rs },
            ) => (ld, ls, rd, rs),
            _ => return Self::Malleable,
        };
        if !left_dissat.constfn_eq(Dissat::Unique) || !(left_signed || right_signed) {
            return Self::Malleable;
        }

        Self::NonMalleable { dissat: right_dissat, signed: left_signed && right_signed }
    }

    /// Constructor for the malleabilitiy properties of the `or_c` fragment.
    pub const fn or_c(left: Self, right: Self) -> Self {
        let (left_dissat, left_signed, right_signed) = match (left, right) {
            (
                Self::NonMalleable { dissat: ld, signed: ls },
                Self::NonMalleable { signed: rs, .. },
            ) => (ld, ls, rs),
            _ => return Self::Malleable,
        };
        if !left_dissat.constfn_eq(Dissat::Unique) || !(left_signed || right_signed) {
            return Self::Malleable;
        }

        Self::NonMalleable { dissat: Dissat::None, signed: left_signed && right_signed }
    }

    /// Constructor for the malleabilitiy properties of the `or_i` fragment.
    pub const fn or_i(left: Self, right: Self) -> Self {
        let (left_dissat, left_signed, right_dissat, right_signed) = match (left, right) {
            (
                Self::NonMalleable { dissat: ld, signed: ls },
                Self::NonMalleable { dissat: rd, signed: rs },
            ) => (ld, ls, rd, rs),
            _ => return Self::Malleable,
        };
        if !(left_signed || right_signed) {
            return Self::Malleable;
        }

        Self::NonMalleable {
            dissat: match (left_dissat, right_dissat) {
                (Dissat::None, Dissat::None) => Dissat::None,
                (Dissat::Unique, Dissat::None) => Dissat::Unique,
                (Dissat::None, Dissat::Unique) => Dissat::Unique,
                _ => Dissat::Unknown,
            },
            signed: left_signed && right_signed,
        }
    }

    /// Constructor for the malleabilitiy properties of the `andor` fragment.
    pub const fn and_or(a: Self, b: Self, c: Self) -> Self {
        let (a_dissat, a_signed, b_dissat, b_signed, c_dissat, c_signed) = match (a, b, c) {
            (
                Self::NonMalleable { dissat: ad, signed: asig },
                Self::NonMalleable { dissat: bd, signed: bsig },
                Self::NonMalleable { dissat: cd, signed: csig },
            ) => (ad, asig, bd, bsig, cd, csig),
            _ => return Self::Malleable,
        };
        if !a_dissat.constfn_eq(Dissat::Unique) || !(a_signed || b_signed || c_signed) {
            return Self::Malleable;
        }

        Self::NonMalleable {
            dissat: match (a_signed, b_dissat, c_dissat) {
                (_, Dissat::None, Dissat::Unique) => Dissat::Unique, //E: ez fy
                (true, _, Dissat::Unique) => Dissat::Unique,         // E: ez sx
                (_, Dissat::None, Dissat::None) => Dissat::None,     // F: fy && fz
                (true, _, Dissat::None) => Dissat::None,             // F: sx && fz
                _ => Dissat::Unknown,
            },
            signed: (a_signed || b_signed) && c_signed,
        }
    }

    /// Constructor for the malleabilitiy properties of the `thresh` fragment.
    // Cannot be constfn because it takes a closure.
    pub fn threshold<'a, I>(k: usize, subs: I) -> Self
    where
        I: ExactSizeIterator<Item = &'a Self>,
    {
        let n = subs.len();
        let mut signed_count = 0;
        let mut all_are_dissat_unique = true;
        for subtype in subs {
            match subtype {
                Self::Malleable => return Self::Malleable,
                Self::NonMalleable { dissat, signed } => {
                    signed_count += usize::from(*signed);
                    all_are_dissat_unique &= *dissat == Dissat::Unique;
                }
            }
        }
        if !all_are_dissat_unique || signed_count < n - k {
            return Self::Malleable;
        }

        Self::NonMalleable {
            // Every sub expression has a unique dissatisfaction, which the
            // requirement above enforces, so the threshold has one whenever a
            // third party cannot satisfy any sub expression on its own. This
            // is BIP379's "e=all are s".
            dissat: if signed_count == n {
                Dissat::Unique
            } else {
                Dissat::Unknown
            },
            signed: signed_count > n - k,
        }
    }
}
