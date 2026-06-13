// SPDX-License-Identifier: CC0-1.0

//! Positive floats ("branch probabilities" for policies)

use core::iter::FusedIterator;
use core::num::NonZeroU32;
use core::{cmp, hash};

/// Ordered f64 for comparison.
#[derive(Copy, Clone, PartialEq, Debug)]
pub struct PositiveF64(pub f64);

impl PositiveF64 {
    /// Takes an iterator over [`PositiveF64`] and produces a new iterator where
    /// each item is divided so that they all total to 1.
    ///
    /// On an empty iterator, returns a new empty iterator.
    ///
    /// Internally clones the iterator and runs it twice, so best to only use
    /// this with reference-based iterators obtained with e.g. `slice.iter()`
    /// rather than "owning" iterators like you'd get from `vec.into_iter()`.
    pub fn normalized_iter<I>(iter: I) -> NormalizedIterator<I>
    where
        I: Iterator<Item = Self> + Clone,
    {
        // Compute the sum of all the items in the iterator. Because all items in
        // the iterator are positive, this will be 0 iff the iterator is empty.
        let sum = iter.clone().map(|x| x.0).sum::<f64>();
        NormalizedIterator { iter, sum }
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

impl From<PositiveF64> for f64 {
    fn from(value: PositiveF64) -> Self { value.0 }
}

impl From<NonZeroU32> for PositiveF64 {
    fn from(value: NonZeroU32) -> Self { Self(f64::from(u32::from(value))) }
}

pub struct NormalizedIterator<I> {
    iter: I,
    /// Sum must be nonnegative, and may only be zero if `iter` is empty.
    sum: f64,
}

impl<I> Iterator for NormalizedIterator<I>
where
    I: Iterator<Item = PositiveF64>,
{
    type Item = I::Item;
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|x| PositiveF64(x.0 / self.sum))
    }

    fn size_hint(&self) -> (usize, Option<usize>) { self.iter.size_hint() }
}

impl<I> DoubleEndedIterator for NormalizedIterator<I>
where
    I: Iterator<Item = PositiveF64> + DoubleEndedIterator,
{
    fn next_back(&mut self) -> Option<Self::Item> {
        self.iter.next_back().map(|x| PositiveF64(x.0 / self.sum))
    }
}

impl<I: ExactSizeIterator> ExactSizeIterator for NormalizedIterator<I> where
    I: Iterator<Item = PositiveF64> + ExactSizeIterator
{
}

impl<I: FusedIterator> FusedIterator for NormalizedIterator<I> where
    I: Iterator<Item = PositiveF64> + FusedIterator
{
}
