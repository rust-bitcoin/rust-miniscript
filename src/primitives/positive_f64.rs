// SPDX-License-Identifier: CC0-1.0

//! Positive Floating-Point Numbers
//!
//! A wrapper around [`f64`] used to represent branch probabilities and
//! execution costs within the policy compiler.
//!
//! Values are guaranteed to be positive floats and never NaN (but may be
//! infinite), ensuring that the type can safely implement [`Ord`] and [`Eq`]
//! without panicking.

use core::{cmp, f64, hash};

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
