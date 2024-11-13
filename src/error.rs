// Written in 2019 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Errors

use core::fmt;
#[cfg(feature = "std")]
use std::error;

use crate::blanket_traits::StaticDebugAndDisplay;
use crate::Box;
/// An error parsing a Miniscript object (policy, descriptor or miniscript)
/// from a string.
#[derive(Debug)]
pub enum ParseError {
    /// Failed to parse a public key or hash.
    ///
    /// Note that the error information is lost for nostd compatibility reasons. See
    /// <https://users.rust-lang.org/t/how-to-box-an-error-type-retaining-std-error-only-when-std-is-enabled/>.
    FromStr(Box<dyn StaticDebugAndDisplay>),
    /// Error parsing a string into an expression tree.
    Tree(crate::ParseTreeError),
}

impl ParseError {
    /// Boxes a `FromStr` error for a `Pk` (or associated types) into a `ParseError`
    pub(crate) fn box_from_str<E: StaticDebugAndDisplay>(e: E) -> Self {
        ParseError::FromStr(Box::new(e))
    }
}

impl From<crate::ParseTreeError> for ParseError {
    fn from(e: crate::ParseTreeError) -> Self { Self::Tree(e) }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParseError::FromStr(ref e) => e.fmt(f),
            ParseError::Tree(ref e) => e.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ParseError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ParseError::FromStr(..) => None,
            ParseError::Tree(ref e) => Some(e),
        }
    }
}
