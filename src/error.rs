// Written in 2019 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Errors

use core::fmt;
#[cfg(feature = "std")]
use std::error;

use crate::blanket_traits::StaticDebugAndDisplay;
use crate::primitives::absolute_locktime::AbsLockTimeError;
use crate::primitives::relative_locktime::RelLockTimeError;
use crate::Box;

/// An error parsing a Miniscript object (policy, descriptor or miniscript)
/// from a string.
#[derive(Debug)]
pub enum ParseError {
    /// Invalid absolute locktime
    AbsoluteLockTime(AbsLockTimeError),
    /// Invalid relative locktime
    RelativeLockTime(RelLockTimeError),
    /// Failed to parse a public key or hash.
    ///
    /// Note that the error information is lost for nostd compatibility reasons. See
    /// <https://users.rust-lang.org/t/how-to-box-an-error-type-retaining-std-error-only-when-std-is-enabled/>.
    FromStr(Box<dyn StaticDebugAndDisplay>),
    /// Failed to parse a number.
    Num(crate::ParseNumError),
    /// Error parsing a string into an expression tree.
    Tree(crate::ParseTreeError),
}

impl ParseError {
    /// Boxes a `FromStr` error for a `Pk` (or associated types) into a `ParseError`
    pub(crate) fn box_from_str<E: StaticDebugAndDisplay>(e: E) -> Self {
        Self::FromStr(Box::new(e))
    }
}

impl From<crate::ParseNumError> for ParseError {
    fn from(e: crate::ParseNumError) -> Self { Self::Num(e) }
}

impl From<crate::ParseTreeError> for ParseError {
    fn from(e: crate::ParseTreeError) -> Self { Self::Tree(e) }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::AbsoluteLockTime(ref e) => e.fmt(f),
            Self::RelativeLockTime(ref e) => e.fmt(f),
            Self::FromStr(ref e) => e.fmt(f),
            Self::Num(ref e) => e.fmt(f),
            Self::Tree(ref e) => e.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ParseError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::AbsoluteLockTime(ref e) => Some(e),
            Self::RelativeLockTime(ref e) => Some(e),
            Self::FromStr(..) => None,
            Self::Num(ref e) => Some(e),
            Self::Tree(ref e) => Some(e),
        }
    }
}
