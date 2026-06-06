// SPDX-License-Identifier: CC0-1.0

//! Positive Floating-Point Numbers
//!
//! A wrapper around [`f64`] used to represent branch probabilities and
//! execution costs within the policy compiler.
//!
//! Values are guaranteed to be positive floats and never NaN (but may be
//! infinite), ensuring that the type can safely implement [`Ord`] and [`Eq`]
//! without panicking.

use core::{cmp, f64, fmt, hash, ops};

/// A positive, possibly-infinite, floating-point number.
#[derive(Copy, Clone, PartialEq, Debug)]
pub struct PositiveF64(pub(super) f64);

impl PositiveF64 {
    /// Positive Infinity, used as a sentinel for impossible compilation branches.
    pub const INFINITY: Self = Self(f64::INFINITY);

    /// Creates a new `PositiveF64` from the given value.
    ///
    /// # Panics
    ///
    /// Panics if `value` is not a positive-floating point number.
    pub fn new(value: f64) -> Self {
        assert!(value > 0.0, "PositiveF64 must be positive and not NaN, got {value}");
        Self(value)
    }

    /// Returns the `PositiveF64` value.
    pub fn value(&self) -> f64 { self.0 }

    /// Normalizes two [`PositiveF64`] values into a valid probability distribution.
    #[must_use]
    pub fn normalized(a: Self, b: Self) -> (Self, Self) {
        let sum = a.0 + b.0;
        (Self(a.0 / sum), Self(b.0 / sum))
    }
}

impl TryFrom<u32> for PositiveF64 {
    type Error = NonZeroExpected;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value == 0 {
            Err(NonZeroExpected)
        } else {
            Ok(Self(value as f64))
        }
    }
}

impl Eq for PositiveF64 {}

// We could derive PartialOrd, but we can't derive Ord, and clippy wants us
// to derive both or neither. Better to be explicit.
impl PartialOrd for PositiveF64 {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> { Some(self.cmp(other)) }
}

impl Ord for PositiveF64 {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        // will panic if given NaN
        self.0.partial_cmp(&other.0).unwrap()
    }
}

/// Hash required for using OrdF64 as key for hashmap
impl hash::Hash for PositiveF64 {
    fn hash<H: hash::Hasher>(&self, state: &mut H) { self.0.to_bits().hash(state); }
}

impl fmt::Display for PositiveF64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

impl ops::Add for PositiveF64 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output { Self(self.0 + rhs.0) }
}

impl ops::Mul for PositiveF64 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output { Self(self.0 * rhs.0) }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct NonZeroExpected;

impl fmt::Display for NonZeroExpected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "value must be non-zero") }
}

#[cfg(feature = "std")]
impl std::error::Error for NonZeroExpected {}
