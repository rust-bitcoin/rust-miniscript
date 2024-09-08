// SPDX-License-Identifier: CC0-1.0

//! # Function-like Expression Language
//!

mod error;

use core::fmt;
use core::str::FromStr;

pub use self::error::{ParseThresholdError, ParseTreeError};
use crate::descriptor::checksum::verify_checksum;
use crate::prelude::*;
use crate::{errstr, Error, Threshold, MAX_RECURSION_DEPTH};

/// Allowed characters are descriptor strings.
pub const INPUT_CHARSET: &str = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";

#[derive(Debug)]
/// A token of the form `x(...)` or `x`
pub struct Tree<'a> {
    /// The name `x`
    pub name: &'a str,
    /// The comma-separated contents of the `(...)`, if any
    pub args: Vec<Tree<'a>>,
}

impl PartialEq for Tree<'_> {
    fn eq(&self, other: &Self) -> bool {
        let mut stack = vec![(self, other)];
        while let Some((me, you)) = stack.pop() {
            if me.name != you.name || me.args.len() != you.args.len() {
                return false;
            }
            stack.extend(me.args.iter().zip(you.args.iter()));
        }
        true
    }
}
impl Eq for Tree<'_> {}
// or_b(pk(A),pk(B))
//
// A = musig(musig(B,C),D,E)
// or_b()
// pk(A), pk(B)

/// Whether to treat `{` and `}` as deliminators when parsing an expression.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Delimiter {
    /// Use `(` and `)` as parentheses.
    NonTaproot,
    /// Use `{` and `}` as parentheses.
    Taproot,
}

/// A trait for extracting a structure from a Tree representation in token form
pub trait FromTree: Sized {
    /// Extract a structure from Tree representation
    fn from_tree(top: &Tree) -> Result<Self, Error>;
}

impl<'a> Tree<'a> {
    /// Parse an expression with round brackets
    pub fn from_slice(sl: &'a str) -> Result<Tree<'a>, ParseTreeError> {
        Self::from_slice_delim(sl, Delimiter::NonTaproot)
    }

    /// Check that a string is a well-formed expression string, with optional
    /// checksum.
    ///
    /// Returns the string with the checksum removed and its tree depth.
    fn parse_pre_check(s: &str, open: u8, close: u8) -> Result<(&str, usize), ParseTreeError> {
        // First, scan through string to make sure it is well-formed.
        // Do ASCII/checksum check first; after this we can use .bytes().enumerate() rather
        // than .char_indices(), which is *significantly* faster.
        let s = verify_checksum(s)?;

        let mut max_depth = 0;
        let mut open_paren_stack = Vec::with_capacity(128);
        for (pos, ch) in s.bytes().enumerate() {
            if ch == open {
                open_paren_stack.push((ch, pos));
                if max_depth < open_paren_stack.len() {
                    max_depth = open_paren_stack.len();
                }
            } else if ch == close {
                if let Some((open_ch, open_pos)) = open_paren_stack.pop() {
                    if (open_ch == b'(' && ch == b'}') || (open_ch == b'{' && ch == b')') {
                        return Err(ParseTreeError::MismatchedParens {
                            open_ch: open_ch.into(),
                            open_pos,
                            close_ch: ch.into(),
                            close_pos: pos,
                        });
                    }

                    if let Some(&(paren_ch, paren_pos)) = open_paren_stack.last() {
                        // not last paren; this should not be the end of the string,
                        // and the next character should be a , ) or }.
                        if pos == s.len() - 1 {
                            return Err(ParseTreeError::UnmatchedOpenParen {
                                ch: paren_ch.into(),
                                pos: paren_pos,
                            });
                        } else {
                            let next_byte = s.as_bytes()[pos + 1];
                            if next_byte != b')' && next_byte != b'}' && next_byte != b',' {
                                return Err(ParseTreeError::ExpectedParenOrComma {
                                    ch: next_byte.into(),
                                    pos: pos + 1,
                                });
                                //
                            }
                        }
                    } else {
                        // last paren; this SHOULD be the end of the string
                        if pos < s.len() - 1 {
                            return Err(ParseTreeError::TrailingCharacter {
                                ch: s.as_bytes()[pos + 1].into(),
                                pos: pos + 1,
                            });
                        }
                    }
                } else {
                    // In practice, this is only hit if there are no open parens at all.
                    // If there are open parens, like in "())", then on the first ), we
                    // would have returned TrailingCharacter in the previous clause.
                    //
                    // From a user point of view, UnmatchedCloseParen would probably be
                    // a clearer error to get, but it complicates the parser to do this,
                    // and "TralingCharacter" is technically correct, so we leave it for
                    // now.
                    return Err(ParseTreeError::UnmatchedCloseParen { ch: ch.into(), pos });
                }
            } else if ch == b',' && open_paren_stack.is_empty() {
                // We consider commas outside of the tree to be "trailing characters"
                return Err(ParseTreeError::TrailingCharacter { ch: ch.into(), pos });
            }
        }
        // Catch "early end of string"
        if let Some((ch, pos)) = open_paren_stack.pop() {
            return Err(ParseTreeError::UnmatchedOpenParen { ch: ch.into(), pos });
        }

        // FIXME should be able to remove this once we eliminate all recursion
        // in the library.
        if u32::try_from(max_depth).unwrap_or(u32::MAX) > MAX_RECURSION_DEPTH {
            return Err(ParseTreeError::MaxRecursionDepthExceeded {
                actual: max_depth,
                maximum: MAX_RECURSION_DEPTH,
            });
        }

        Ok((s, max_depth))
    }

    pub(crate) fn from_slice_delim(s: &'a str, delim: Delimiter) -> Result<Self, ParseTreeError> {
        let (oparen, cparen) = match delim {
            Delimiter::NonTaproot => (b'(', b')'),
            Delimiter::Taproot => (b'{', b'}'),
        };

        // First, scan through string to make sure it is well-formed.
        let (s, max_depth) = Self::parse_pre_check(s, oparen, cparen)?;

        // Now, knowing it is sane and well-formed, we can easily parse it backward,
        // which will yield a post-order right-to-left iterator of its nodes.
        let mut stack = Vec::with_capacity(max_depth);
        let mut children = None;
        let mut node_name_end = s.len();
        let mut tapleaf_depth = 0;
        for (pos, ch) in s.bytes().enumerate().rev() {
            if ch == cparen {
                stack.push(vec![]);
                node_name_end = pos;
            } else if tapleaf_depth == 0 && ch == b',' {
                let top = stack.last_mut().unwrap();
                let mut new_tree = Tree {
                    name: &s[pos + 1..node_name_end],
                    args: children.take().unwrap_or(vec![]),
                };
                new_tree.args.reverse();
                top.push(new_tree);
                node_name_end = pos;
            } else if ch == oparen {
                let mut top = stack.pop().unwrap();
                let mut new_tree = Tree {
                    name: &s[pos + 1..node_name_end],
                    args: children.take().unwrap_or(vec![]),
                };
                new_tree.args.reverse();
                top.push(new_tree);
                children = Some(top);
                node_name_end = pos;
            } else if delim == Delimiter::Taproot && ch == b'(' {
                tapleaf_depth += 1;
            } else if delim == Delimiter::Taproot && ch == b')' {
                tapleaf_depth -= 1;
            }
        }

        assert_eq!(stack.len(), 0);
        let mut children = children.take().unwrap_or(vec![]);
        children.reverse();
        Ok(Tree { name: &s[..node_name_end], args: children })
    }

    /// Parses a tree from a string
    #[allow(clippy::should_implement_trait)] // Cannot use std::str::FromStr because of lifetimes.
    pub fn from_str(s: &'a str) -> Result<Tree<'a>, Error> {
        Self::from_slice_delim(s, Delimiter::NonTaproot).map_err(Error::ParseTree)
    }

    /// Parses an expression tree as a threshold (a term with at least one child,
    /// the first of which is a positive integer k).
    ///
    /// This sanity-checks that the threshold is well-formed (begins with a valid
    /// threshold value, etc.) but does not parse the children of the threshold.
    /// Instead it returns a threshold holding the empty type `()`, which is
    /// constructed without any allocations, and expects the caller to convert
    /// this to the "real" threshold type by calling [`Threshold::translate`].
    ///
    /// (An alternate API which does the conversion inline turned out to be
    /// too messy; it needs to take a closure, have multiple generic parameters,
    /// and be able to return multiple error types.)
    pub fn to_null_threshold<const MAX: usize>(
        &self,
    ) -> Result<Threshold<(), MAX>, ParseThresholdError> {
        // First, special case "no arguments" so we can index the first argument without panics.
        if self.args.is_empty() {
            return Err(ParseThresholdError::NoChildren);
        }

        if !self.args[0].args.is_empty() {
            return Err(ParseThresholdError::KNotTerminal);
        }

        let k = parse_num(self.args[0].name)
            .map_err(|e| ParseThresholdError::ParseK(e.to_string()))? as usize;
        Threshold::new(k, vec![(); self.args.len() - 1]).map_err(ParseThresholdError::Threshold)
    }
}

/// Parse a string as a u32, for timelocks or thresholds
pub fn parse_num(s: &str) -> Result<u32, Error> {
    if s.len() > 1 {
        let ch = s.chars().next().unwrap();
        if !('1'..='9').contains(&ch) {
            return Err(Error::Unexpected("Number must start with a digit 1-9".to_string()));
        }
    }
    u32::from_str(s).map_err(|_| errstr(s))
}

/// Attempts to parse a terminal expression
pub fn terminal<T, F, Err>(term: &Tree, convert: F) -> Result<T, Error>
where
    F: FnOnce(&str) -> Result<T, Err>,
    Err: fmt::Display,
{
    if term.args.is_empty() {
        convert(term.name).map_err(|e| Error::Unexpected(e.to_string()))
    } else {
        Err(errstr(term.name))
    }
}

/// Attempts to parse an expression with exactly one child
pub fn unary<L, T, F>(term: &Tree, convert: F) -> Result<T, Error>
where
    L: FromTree,
    F: FnOnce(L) -> T,
{
    if term.args.len() == 1 {
        let left = FromTree::from_tree(&term.args[0])?;
        Ok(convert(left))
    } else {
        Err(errstr(term.name))
    }
}

/// Attempts to parse an expression with exactly two children
pub fn binary<L, R, T, F>(term: &Tree, convert: F) -> Result<T, Error>
where
    L: FromTree,
    R: FromTree,
    F: FnOnce(L, R) -> T,
{
    if term.args.len() == 2 {
        let left = FromTree::from_tree(&term.args[0])?;
        let right = FromTree::from_tree(&term.args[1])?;
        Ok(convert(left, right))
    } else {
        Err(errstr(term.name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test functions to manually build trees
    fn leaf(name: &str) -> Tree { Tree { name, args: vec![] } }

    fn paren_node<'a>(name: &'a str, args: Vec<Tree<'a>>) -> Tree<'a> { Tree { name, args } }

    #[test]
    fn test_parse_num() {
        assert!(parse_num("0").is_ok());
        assert!(parse_num("00").is_err());
        assert!(parse_num("0000").is_err());
        assert!(parse_num("06").is_err());
        assert!(parse_num("+6").is_err());
        assert!(parse_num("-6").is_err());
    }

    #[test]
    fn parse_tree_basic() {
        assert_eq!(Tree::from_str("thresh").unwrap(), leaf("thresh"));

        assert!(matches!(
            Tree::from_str("thresh,").unwrap_err(),
            Error::ParseTree(ParseTreeError::TrailingCharacter { ch: ',', pos: 6 }),
        ));

        assert!(matches!(
            Tree::from_str("thresh,thresh").unwrap_err(),
            Error::ParseTree(ParseTreeError::TrailingCharacter { ch: ',', pos: 6 }),
        ));

        assert!(matches!(
            Tree::from_str("thresh()thresh()").unwrap_err(),
            Error::ParseTree(ParseTreeError::TrailingCharacter { ch: 't', pos: 8 }),
        ));

        assert_eq!(Tree::from_str("thresh()").unwrap(), paren_node("thresh", vec![leaf("")]));

        assert!(matches!(
            Tree::from_str("thresh(a()b)"),
            Err(Error::ParseTree(ParseTreeError::ExpectedParenOrComma { ch: 'b', pos: 10 })),
        ));

        assert!(matches!(
            Tree::from_str("thresh()xyz"),
            Err(Error::ParseTree(ParseTreeError::TrailingCharacter { ch: 'x', pos: 8 })),
        ));
    }

    #[test]
    fn parse_tree_parens() {
        assert!(matches!(
            Tree::from_str("a(").unwrap_err(),
            Error::ParseTree(ParseTreeError::UnmatchedOpenParen { ch: '(', pos: 1 }),
        ));

        assert!(matches!(
            Tree::from_str(")").unwrap_err(),
            Error::ParseTree(ParseTreeError::UnmatchedCloseParen { ch: ')', pos: 0 }),
        ));

        assert!(matches!(
            Tree::from_str("x(y))").unwrap_err(),
            Error::ParseTree(ParseTreeError::TrailingCharacter { ch: ')', pos: 4 }),
        ));

        /* Will be enabled in a later PR which unifies TR and non-TR parsing.
        assert!(matches!(
            Tree::from_str("a{").unwrap_err(),
            Error::ParseTree(ParseTreeError::UnmatchedOpenParen { ch: '{', pos: 1 }),
        ));

        assert!(matches!(
            Tree::from_str("}").unwrap_err(),
            Error::ParseTree(ParseTreeError::UnmatchedCloseParen { ch: '}', pos: 0 }),
        ));
        */

        assert!(matches!(
            Tree::from_str("x(y)}").unwrap_err(),
            Error::ParseTree(ParseTreeError::TrailingCharacter { ch: '}', pos: 4 }),
        ));

        /* Will be enabled in a later PR which unifies TR and non-TR parsing.
        assert!(matches!(
            Tree::from_str("x{y)").unwrap_err(),
            Error::ParseTree(ParseTreeError::MismatchedParens {
                open_ch: '{',
                open_pos: 1,
                close_ch: ')',
                close_pos: 3,
            }),
        ));
        */
    }

    #[test]
    fn parse_tree_taproot() {
        // This test will change in a later PR which unifies TR and non-TR parsing.
        assert!(matches!(
            Tree::from_str("a{b(c),d}").unwrap_err(),
            Error::ParseTree(ParseTreeError::TrailingCharacter { ch: ',', pos: 6 }),
        ));
    }

    #[test]
    fn parse_tree_desc() {
        let keys = [
            "02c2fd50ceae468857bb7eb32ae9cd4083e6c7e42fbbec179d81134b3e3830586c",
            "0257f4a2816338436cccabc43aa724cf6e69e43e84c3c8a305212761389dd73a8a",
        ];
        let desc = format!("wsh(t:or_c(pk({}),v:pkh({})))", keys[0], keys[1]);

        assert_eq!(
            Tree::from_str(&desc).unwrap(),
            paren_node(
                "wsh",
                vec![paren_node(
                    "t:or_c",
                    vec![
                        paren_node("pk", vec![leaf(keys[0])]),
                        paren_node("v:pkh", vec![leaf(keys[1])]),
                    ]
                )]
            ),
        );
    }
}
