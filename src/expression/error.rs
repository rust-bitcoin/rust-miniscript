// SPDX-License-Identifier: CC0-1.0

//! Expression-related errors

use core::fmt;

use crate::prelude::*;
use crate::ThresholdError;

/// Error parsing a threshold expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseThresholdError {
    /// Expression had no children, not even a threshold value.
    NoChildren,
    /// The threshold value appeared to be a sub-expression rather than a number.
    KNotTerminal,
    /// Failed to parse the threshold value.
    // FIXME this should be a more specific type. Will be handled in a later PR
    // that rewrites the expression parsing logic.
    ParseK(String),
    /// Threshold parameters were invalid.
    Threshold(ThresholdError),
}

impl fmt::Display for ParseThresholdError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ParseThresholdError::*;

        match *self {
            NoChildren => f.write_str("expected threshold, found terminal"),
            KNotTerminal => f.write_str("expected positive integer, found expression"),
            ParseK(ref x) => write!(f, "failed to parse threshold value {}", x),
            Threshold(ref e) => e.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseThresholdError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ParseThresholdError::*;

        match *self {
            NoChildren => None,
            KNotTerminal => None,
            ParseK(..) => None,
            Threshold(ref e) => Some(e),
        }
    }
}
