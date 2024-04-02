// SPDX-License-Identifier: CC0-1.0

//! Primitive Types
//!
//! In Miniscript we have a few types which have stronger constraints than
//! their equivalents in Bitcoin (or Rust). In particular, locktimes which
//! appear in `after` and `older` fragments are constrained to be nonzero,
//! and the relative locktimes in `older` fragments are only allowed to be
//! the subset of sequence numbers which form valid locktimes.
//!
//! This module exists for code organization and any types defined here
//! should be re-exported at the crate root.

pub mod absolute_locktime;
pub mod relative_locktime;
pub mod threshold;
