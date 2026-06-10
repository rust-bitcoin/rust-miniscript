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

/// Structure representing the type properties of a fragment which have
/// relevance to malleability analysis
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Malleability {
    /// Properties of dissatisfying inputs
    pub dissat: Dissat,
    /// `true` if every satisfaction, if one exists, requires a
    /// signature. `false` for hash preimages and timelocks, since
    /// they can be satisfied without a signature.
    /// Affects malleability.
    pub signed: bool,
    /// Whether a non-malleable satisfaction is guaranteed to exist for
    /// the fragment
    pub non_malleable: bool,
}

impl Malleability {
    /// Malleability data for the `1` combinator
    pub const TRUE: Self = Self { dissat: Dissat::None, signed: false, non_malleable: true };

    /// Malleability data for the `0` combinator
    pub const FALSE: Self = Self { dissat: Dissat::Unique, signed: true, non_malleable: true };

    /// Check whether the `self` is a subtype of `other` argument.
    ///
    /// This checks whether the argument `other` has attributes which are present
    /// in the given `Type`. This returns `true` on same arguments
    /// `a.is_subtype(a)` is `true`.
    pub const fn is_subtype(&self, other: Self) -> bool {
        self.dissat.is_subtype(other.dissat)
            && self.signed >= other.signed
            && self.non_malleable >= other.non_malleable
    }
}

impl Malleability {
    /// Constructor for the malleabilitiy properties of the `pk_k` fragment.
    pub const fn pk_k() -> Self {
        Self { dissat: Dissat::Unique, signed: true, non_malleable: true }
    }

    /// Constructor for the malleabilitiy properties of the `pk_h` fragment.
    pub const fn pk_h() -> Self {
        Self { dissat: Dissat::Unique, signed: true, non_malleable: true }
    }

    /// Constructor for the malleabilitiy properties of the `multi` fragment.
    pub const fn multi() -> Self {
        Self { dissat: Dissat::Unique, signed: true, non_malleable: true }
    }

    /// Constructor for the malleabilitiy properties of the `sortedmulti` fragment.
    pub const fn sortedmulti() -> Self {
        Self { dissat: Dissat::Unique, signed: true, non_malleable: true }
    }

    /// Constructor for the malleabilitiy properties of the `multi_a` fragment.
    pub const fn multi_a() -> Self {
        Self { dissat: Dissat::Unique, signed: true, non_malleable: true }
    }

    /// Constructor for the malleabilitiy properties of the `sortedmulti_a` fragment.
    pub const fn sortedmulti_a() -> Self {
        Self { dissat: Dissat::Unique, signed: true, non_malleable: true }
    }

    /// Constructor for the malleabilitiy properties of any of the hash fragments.
    pub const fn hash() -> Self {
        Self { dissat: Dissat::Unknown, signed: false, non_malleable: true }
    }

    /// Constructor for the malleabilitiy properties of either `after` or `older`.
    pub const fn time() -> Self {
        Self { dissat: Dissat::None, signed: false, non_malleable: true }
    }

    /// Constructor for the malleabilitiy properties of the `a:` fragment.
    pub const fn cast_alt(self) -> Self { self }

    /// Constructor for the malleabilitiy properties of the `s:` fragment.
    pub const fn cast_swap(self) -> Self { self }

    /// Constructor for the malleabilitiy properties of the `c:` fragment.
    pub const fn cast_check(self) -> Self { self }

    /// Constructor for the malleabilitiy properties of the `d:` fragment.
    pub const fn cast_dupif(self) -> Self {
        Self {
            dissat: if self.dissat.constfn_eq(Dissat::None) {
                Dissat::Unique
            } else {
                Dissat::Unknown
            },
            signed: self.signed,
            non_malleable: self.non_malleable,
        }
    }

    /// Constructor for the malleabilitiy properties of the `v:` fragment.
    pub const fn cast_verify(self) -> Self {
        Self { dissat: Dissat::None, signed: self.signed, non_malleable: self.non_malleable }
    }

    /// Constructor for the malleabilitiy properties of the `j:` fragment.
    pub const fn cast_nonzero(self) -> Self {
        Self {
            dissat: if self.dissat.constfn_eq(Dissat::None) {
                Dissat::Unique
            } else {
                Dissat::Unknown
            },
            signed: self.signed,
            non_malleable: self.non_malleable,
        }
    }

    /// Constructor for the malleabilitiy properties of the `n:` fragment.
    pub const fn cast_zeronotequal(self) -> Self { self }

    /// Constructor for the malleabilitiy properties of the `t:` fragment.
    pub const fn cast_true(self) -> Self {
        Self { dissat: Dissat::None, signed: self.signed, non_malleable: self.non_malleable }
    }

    /// Constructor for the malleabilitiy properties of the `l:` or `u:` fragments.
    pub const fn cast_or_i_false(self) -> Self {
        Self {
            dissat: if self.dissat.constfn_eq(Dissat::None) {
                Dissat::Unique
            } else {
                Dissat::Unknown
            },
            signed: self.signed,
            non_malleable: self.non_malleable,
        }
    }

    /// Constructor for the malleabilitiy properties of the `and_b` fragment.
    pub const fn and_b(left: Self, right: Self) -> Self {
        Self {
            dissat: match (left.dissat, right.dissat) {
                (Dissat::None, Dissat::None) => Dissat::None,
                (Dissat::None, _) if left.signed => Dissat::None,
                (_, Dissat::None) if right.signed => Dissat::None,
                (Dissat::Unique, Dissat::Unique) => {
                    if left.signed && right.signed {
                        Dissat::Unique
                    } else {
                        Dissat::Unknown
                    }
                }
                _ => Dissat::Unknown,
            },
            signed: left.signed || right.signed,
            non_malleable: left.non_malleable && right.non_malleable,
        }
    }

    /// Constructor for the malleabilitiy properties of the `and_v` fragment.
    pub const fn and_v(left: Self, right: Self) -> Self {
        Self {
            dissat: match (left.signed, right.dissat) {
                (_, Dissat::None) => Dissat::None, // fy
                (true, _) => Dissat::None,         // sx
                _ => Dissat::Unknown,
            },
            signed: left.signed || right.signed,
            non_malleable: left.non_malleable && right.non_malleable,
        }
    }

    /// Constructor for the malleabilitiy properties of the `or_b` fragment.
    pub const fn or_b(left: Self, right: Self) -> Self {
        Self {
            dissat: Dissat::Unique,
            signed: left.signed && right.signed,
            non_malleable: left.non_malleable
                && left.dissat.constfn_eq(Dissat::Unique)
                && right.non_malleable
                && right.dissat.constfn_eq(Dissat::Unique)
                && (left.signed || right.signed),
        }
    }

    /// Constructor for the malleabilitiy properties of the `or_d` fragment.
    pub const fn or_d(left: Self, right: Self) -> Self {
        Self {
            dissat: right.dissat,
            signed: left.signed && right.signed,
            non_malleable: left.non_malleable
                && left.dissat.constfn_eq(Dissat::Unique)
                && right.non_malleable
                && (left.signed || right.signed),
        }
    }

    /// Constructor for the malleabilitiy properties of the `or_c` fragment.
    pub const fn or_c(left: Self, right: Self) -> Self {
        Self {
            dissat: Dissat::None,
            signed: left.signed && right.signed,
            non_malleable: left.non_malleable
                && left.dissat.constfn_eq(Dissat::Unique)
                && right.non_malleable
                && (left.signed || right.signed),
        }
    }

    /// Constructor for the malleabilitiy properties of the `or_i` fragment.
    pub const fn or_i(left: Self, right: Self) -> Self {
        Self {
            dissat: match (left.dissat, right.dissat) {
                (Dissat::None, Dissat::None) => Dissat::None,
                (Dissat::Unique, Dissat::None) => Dissat::Unique,
                (Dissat::None, Dissat::Unique) => Dissat::Unique,
                _ => Dissat::Unknown,
            },
            signed: left.signed && right.signed,
            non_malleable: left.non_malleable
                && right.non_malleable
                && (left.signed || right.signed),
        }
    }

    /// Constructor for the malleabilitiy properties of the `andor` fragment.
    pub const fn and_or(a: Self, b: Self, c: Self) -> Self {
        Self {
            dissat: match (a.signed, b.dissat, c.dissat) {
                (_, Dissat::None, Dissat::Unique) => Dissat::Unique, //E: ez fy
                (true, _, Dissat::Unique) => Dissat::Unique,         // E: ez sx
                (_, Dissat::None, Dissat::None) => Dissat::None,     // F: fy && fz
                (true, _, Dissat::None) => Dissat::None,             // F: sx && fz
                _ => Dissat::Unknown,
            },
            signed: (a.signed || b.signed) && c.signed,
            non_malleable: a.non_malleable
                && c.non_malleable
                && a.dissat.constfn_eq(Dissat::Unique)
                && b.non_malleable
                && (a.signed || b.signed || c.signed),
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
        let mut all_are_non_malleable = true;
        for subtype in subs {
            signed_count += usize::from(subtype.signed);
            all_are_dissat_unique &= subtype.dissat == Dissat::Unique;
            all_are_non_malleable &= subtype.non_malleable;
        }

        Self {
            dissat: if all_are_dissat_unique && signed_count == n {
                Dissat::Unique
            } else {
                Dissat::Unknown
            },
            signed: signed_count > n - k,
            non_malleable: all_are_non_malleable && signed_count >= n - k && all_are_dissat_unique,
        }
    }
}
