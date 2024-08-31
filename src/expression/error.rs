// SPDX-License-Identifier: CC0-1.0

//! Expression-related errors

use core::fmt;

use crate::prelude::*;
use crate::ThresholdError;

/// An error parsing an expression tree.
#[derive(Debug, PartialEq, Eq)]
pub enum ParseTreeError {
    /// Expression tree had depth exceeding our hard cap.
    MaxRecursionDepthExceeded {
        /// The depth of the tree that was attempted to be parsed.
        actual: usize,
        /// The maximum depth.
        maximum: u32,
    },
    /// Character occurred which was not part of the valid descriptor character set.
    InvalidCharacter {
        /// The character in question.
        ch: char,
        /// Its byte-index into the string.
        pos: usize,
    },
    /// After a close-paren, the only valid next characters are close-parens and commas. Got
    /// something else.
    ExpectedParenOrComma {
        /// What we got instead.
        ch: char,
        /// Its byte-index into the string.
        pos: usize,
    },
    /// An open-parenthesis had no corresponding close-parenthesis.
    UnmatchedOpenParen {
        /// The character in question ('(' or '{')
        ch: char,
        /// Its byte-index into the string.
        pos: usize,
    },
    /// A close-parenthesis had no corresponding open-parenthesis.
    UnmatchedCloseParen {
        /// The character in question (')' or '}')
        ch: char,
        /// Its byte-index into the string.
        pos: usize,
    },
    /// A `(` was matched with a `}` or vice-versa.
    MismatchedParens {
        /// The opening parenthesis ('(' or '{')
        open_ch: char,
        /// The position of the opening parethesis.
        open_pos: usize,
        /// The closing parenthesis (')' or '}')
        close_ch: char,
        /// The position of the closing parethesis.
        close_pos: usize,
    },
    /// Data occurred after the final ).
    TrailingCharacter {
        /// The first trailing character.
        ch: char,
        /// Its byte-index into the string.
        pos: usize,
    },
}

impl fmt::Display for ParseTreeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParseTreeError::MaxRecursionDepthExceeded { actual, maximum } => {
                write!(f, "maximum recursion depth exceeded (max {}, got {})", maximum, actual)
            }
            ParseTreeError::InvalidCharacter { ch, pos } => {
                write!(f, "character `{}` (position {}) not allowed in descriptor", ch, pos)
            }
            ParseTreeError::ExpectedParenOrComma { ch, pos } => {
                write!(
                    f,
                    "invalid character `{}` (position {}); expected comma or close-paren",
                    ch, pos
                )
            }
            ParseTreeError::UnmatchedOpenParen { ch, pos } => {
                write!(f, "`{}` (position {}) not closed", ch, pos)
            }
            ParseTreeError::UnmatchedCloseParen { ch, pos } => {
                write!(f, "`{}` (position {}) not opened", ch, pos)
            }
            ParseTreeError::MismatchedParens { open_ch, open_pos, close_ch, close_pos } => {
                write!(
                    f,
                    "`{}` (position {}) closed by `{}` (position {})",
                    open_ch, open_pos, close_ch, close_pos
                )
            }
            ParseTreeError::TrailingCharacter { ch, pos } => {
                write!(f, "trailing data `{}...` (position {})", ch, pos)
            }
        }
    }
}
#[cfg(feature = "std")]
impl std::error::Error for ParseTreeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

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
