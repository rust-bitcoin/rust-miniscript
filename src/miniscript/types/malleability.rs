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

//! Malleability-related Type properties

use super::{ErrorKind, Property};

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

impl Dissat {
    /// Check whether given `Dissat` is a subtype of `other`. That is,
    /// if some Dissat is `Unique` then it must be `Unknown`.
    fn is_subtype(&self, other: Self) -> bool {
        match (*self, other) {
            (x, y) if x == y => true,
            (_, Dissat::Unknown) => true,
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
    /// `true` if satisfactions cannot be created by any 3rd party
    /// who has not yet seen a satisfaction. (Hash preimages and
    /// signature checks are safe; timelocks are not.) Affects
    /// malleability.
    pub safe: bool,
    /// Whether a non-malleable satisfaction is guaranteed to exist for
    /// the fragment
    pub non_malleable: bool,
}

impl Malleability {
    /// Check whether the `self` is a subtype of `other` argument .
    /// This checks whether the argument `other` has attributes which are present
    /// in the given `Type`. This returns `true` on same arguments
    /// `a.is_subtype(a)` is `true`.
    pub fn is_subtype(&self, other: Self) -> bool {
        if self.dissat.is_subtype(other.dissat)
            && self.safe >= other.safe
            && self.non_malleable >= other.non_malleable
        {
            return true;
        }
        return false;
    }
}

impl Property for Malleability {
    fn from_true() -> Self {
        Malleability {
            dissat: Dissat::None,
            safe: false,
            non_malleable: true,
        }
    }

    fn from_false() -> Self {
        Malleability {
            dissat: Dissat::Unique,
            safe: true,
            non_malleable: true,
        }
    }

    fn from_pk_k() -> Self {
        Malleability {
            dissat: Dissat::Unique,
            safe: true,
            non_malleable: true,
        }
    }

    fn from_pk_h() -> Self {
        Malleability {
            dissat: Dissat::Unique,
            safe: true,
            non_malleable: true,
        }
    }

    fn from_multi(_: usize, _: usize) -> Self {
        Malleability {
            dissat: Dissat::Unique,
            safe: true,
            non_malleable: true,
        }
    }

    fn from_hash() -> Self {
        Malleability {
            dissat: Dissat::Unknown,
            safe: false,
            non_malleable: true,
        }
    }

    fn from_time(_: u32) -> Self {
        Malleability {
            dissat: Dissat::None,
            safe: false,
            non_malleable: true,
        }
    }

    fn from_txtemplate() -> Self {
        Malleability {
            dissat: Dissat::None,
            safe: true,
            non_malleable: true,
        }
    }

    fn cast_alt(self) -> Result<Self, ErrorKind> {
        Ok(self)
    }

    fn cast_swap(self) -> Result<Self, ErrorKind> {
        Ok(self)
    }

    fn cast_check(self) -> Result<Self, ErrorKind> {
        Ok(self)
    }

    fn cast_dupif(self) -> Result<Self, ErrorKind> {
        Ok(Malleability {
            dissat: if self.dissat == Dissat::None {
                Dissat::Unique
            } else {
                Dissat::Unknown
            },
            safe: self.safe,
            non_malleable: self.non_malleable,
        })
    }

    fn cast_verify(self) -> Result<Self, ErrorKind> {
        Ok(Malleability {
            dissat: Dissat::None,
            safe: self.safe,
            non_malleable: self.non_malleable,
        })
    }

    fn cast_nonzero(self) -> Result<Self, ErrorKind> {
        Ok(Malleability {
            dissat: if self.dissat == Dissat::None {
                Dissat::Unique
            } else {
                Dissat::Unknown
            },
            safe: self.safe,
            non_malleable: self.non_malleable,
        })
    }

    fn cast_zeronotequal(self) -> Result<Self, ErrorKind> {
        Ok(self)
    }

    fn cast_true(self) -> Result<Self, ErrorKind> {
        Ok(Malleability {
            dissat: Dissat::None,
            safe: self.safe,
            non_malleable: self.non_malleable,
        })
    }

    fn cast_or_i_false(self) -> Result<Self, ErrorKind> {
        Ok(Malleability {
            dissat: if self.dissat == Dissat::None {
                Dissat::Unique
            } else {
                Dissat::Unknown
            },
            safe: self.safe,
            non_malleable: self.non_malleable,
        })
    }

    fn and_b(left: Self, right: Self) -> Result<Self, ErrorKind> {
        Ok(Malleability {
            dissat: match (left.dissat, right.dissat) {
                (Dissat::None, Dissat::None) => Dissat::None,
                (Dissat::None, _) if left.safe => Dissat::None,
                (_, Dissat::None) if right.safe => Dissat::None,
                (Dissat::Unique, Dissat::Unique) => {
                    if left.safe && right.safe {
                        Dissat::Unique
                    } else {
                        Dissat::Unknown
                    }
                }
                _ => Dissat::Unknown,
            },
            safe: left.safe || right.safe,
            non_malleable: left.non_malleable && right.non_malleable,
        })
    }

    fn and_v(left: Self, right: Self) -> Result<Self, ErrorKind> {
        Ok(Malleability {
            dissat: match (left.safe, right.dissat) {
                (_, Dissat::None) => Dissat::None, // fy
                (true, _) => Dissat::None,         // sx
                _ => Dissat::Unknown,
            },
            safe: left.safe || right.safe,
            non_malleable: left.non_malleable && right.non_malleable,
        })
    }

    fn or_b(left: Self, right: Self) -> Result<Self, ErrorKind> {
        Ok(Malleability {
            dissat: Dissat::Unique,
            safe: left.safe && right.safe,
            non_malleable: left.non_malleable
                && left.dissat == Dissat::Unique
                && right.non_malleable
                && right.dissat == Dissat::Unique
                && (left.safe || right.safe),
        })
    }

    fn or_d(left: Self, right: Self) -> Result<Self, ErrorKind> {
        Ok(Malleability {
            dissat: right.dissat,
            safe: left.safe && right.safe,
            non_malleable: left.non_malleable
                && left.dissat == Dissat::Unique
                && right.non_malleable
                && (left.safe || right.safe),
        })
    }

    fn or_c(left: Self, right: Self) -> Result<Self, ErrorKind> {
        Ok(Malleability {
            dissat: Dissat::None,
            safe: left.safe && right.safe,
            non_malleable: left.non_malleable
                && left.dissat == Dissat::Unique
                && right.non_malleable
                && (left.safe || right.safe),
        })
    }

    fn or_i(left: Self, right: Self) -> Result<Self, ErrorKind> {
        Ok(Malleability {
            dissat: match (left.dissat, right.dissat) {
                (Dissat::None, Dissat::None) => Dissat::None,
                (Dissat::Unique, Dissat::None) => Dissat::Unique,
                (Dissat::None, Dissat::Unique) => Dissat::Unique,
                _ => Dissat::Unknown,
            },
            safe: left.safe && right.safe,
            non_malleable: left.non_malleable && right.non_malleable && (left.safe || right.safe),
        })
    }

    fn and_or(a: Self, b: Self, c: Self) -> Result<Self, ErrorKind> {
        Ok(Malleability {
            dissat: match (a.safe, b.dissat, c.dissat) {
                (_, Dissat::None, Dissat::Unique) => Dissat::Unique, //E: ez fy
                (true, _, Dissat::Unique) => Dissat::Unique,         // E: ez sx
                (_, Dissat::None, Dissat::None) => Dissat::None,     // F: fy && fz
                (true, _, Dissat::None) => Dissat::None,             // F: sx && fz
                _ => Dissat::Unknown,
            },
            safe: (a.safe || b.safe) && c.safe,
            non_malleable: a.non_malleable
                && c.non_malleable
                && a.dissat == Dissat::Unique
                && b.non_malleable
                && (a.safe || b.safe || c.safe),
        })
    }

    fn threshold<S>(k: usize, n: usize, mut sub_ck: S) -> Result<Self, ErrorKind>
    where
        S: FnMut(usize) -> Result<Self, ErrorKind>,
    {
        let mut safe_count = 0;
        let mut all_are_dissat_unique = true;
        let mut all_are_non_malleable = true;
        for i in 0..n {
            let subtype = sub_ck(i)?;
            safe_count += if subtype.safe { 1 } else { 0 };
            all_are_dissat_unique &= subtype.dissat == Dissat::Unique;
            all_are_non_malleable &= subtype.non_malleable;
        }
        Ok(Malleability {
            dissat: if all_are_dissat_unique && (k == 1 || safe_count == n) {
                Dissat::Unique
            } else {
                Dissat::Unknown
            },
            safe: safe_count > n - k,
            non_malleable: all_are_non_malleable
                && safe_count >= n - k
                && (k == n || all_are_dissat_unique),
        })
    }
}
