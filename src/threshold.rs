// SPDX-License-Identifier: CC0-1.0

//! A generic (k,n)-threshold type.

use core::fmt;

use crate::prelude::{vec, Vec};

/// A (k, n)-threshold.
///
/// This type maintains the following invariants:
/// -   n > 0
/// -   k > 0
/// -   k <= n
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Threshold<T> {
    k: usize,
    v: Vec<T>,
}

impl<T> Threshold<T> {
    /// Creates a `Theshold<T>` after checking that invariants hold.
    pub fn new(k: usize, v: Vec<T>) -> Result<Threshold<T>, Error> {
        if v.len() == 0 {
            Err(Error::ZeroN)
        } else if k == 0 {
            Err(Error::ZeroK)
        } else if k > v.len() {
            Err(Error::BigK)
        } else {
            Ok(Threshold { k, v })
        }
    }

    /// Creates a `Theshold<T>` without checking that invariants hold.
    #[cfg(test)]
    pub fn new_unchecked(k: usize, v: Vec<T>) -> Threshold<T> { Threshold { k, v } }

    /// Returns `k`, the threshold value.
    pub fn k(&self) -> usize { self.k }

    /// Returns `n`, the total number of elements in the threshold.
    pub fn n(&self) -> usize { self.v.len() }

    /// Returns a read-only iterator over the threshold elements.
    pub fn iter(&self) -> core::slice::Iter<'_, T> { self.v.iter() }

    /// Creates an iterator over the threshold elements.
    pub fn into_iter(self) -> vec::IntoIter<T> { self.v.into_iter() }

    /// Creates an iterator over the threshold elements.
    pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, T> { self.v.iter_mut() }

    /// Returns the threshold elements, consuming self.
    pub fn into_elements(self) -> Vec<T> { self.v }

    /// Creates a new (k, n)-threshold using a newly mapped vector.
    ///
    /// Typically this function is called after collecting a vector that was
    /// created by iterating this threshold. E.g.,
    ///
    /// `thresh.mapped((0..thresh.n()).map(|element| some_function(element)).collect())`
    ///
    /// # Panics
    ///
    /// Panics if the new vector is not the same length as the
    /// original i.e., `new.len() != self.n()`.
    pub(crate) fn mapped<U>(&self, new: Vec<U>) -> Threshold<U> {
        if self.n() != new.len() {
            panic!("cannot map to a different length vector")
        }
        Threshold { k: self.k(), v: new }
    }
}

/// An error attempting to construct a `Threshold<T>`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Threshold `n` value must be non-zero.
    ZeroN,
    /// Threshold `k` value must be non-zero.
    ZeroK,
    /// Threshold `k` value must be <= `n`.
    BigK,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            ZeroN => f.write_str("threshold `n` value must be non-zero"),
            ZeroK => f.write_str("threshold `k` value must be non-zero"),
            BigK => f.write_str("threshold `k` value must be <= `n`"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        use Error::*;

        match *self {
            ZeroN | ZeroK | BigK => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_constructor_valid() {
        let v = vec![1, 2, 3];
        let n = 3;

        for k in 1..=3 {
            let thresh = Threshold::new(k, v.clone()).expect("failed to create threshold");
            assert_eq!(thresh.k(), k);
            assert_eq!(thresh.n(), n);
        }
    }

    #[test]
    fn threshold_constructor_invalid() {
        let v = vec![1, 2, 3];
        assert!(Threshold::new(0, v.clone()).is_err());
        assert!(Threshold::new(4, v.clone()).is_err());
    }
}
