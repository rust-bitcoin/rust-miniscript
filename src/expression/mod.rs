// SPDX-License-Identifier: CC0-1.0

//! # Function-like Expression Language
//!

mod error;

use core::fmt;
use core::str::FromStr;

pub use self::error::{ParseThresholdError, ParseTreeError};
use crate::prelude::*;
use crate::{errstr, Error, Threshold, MAX_RECURSION_DEPTH};

/// Allowed characters are descriptor strings.
pub const INPUT_CHARSET: &str = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";

/// Map of valid characters in descriptor strings.
#[rustfmt::skip]
pub const VALID_CHARS: [Option<u8>; 128] = [
    None, None, None, None, None, None, None, None, None, None, None, None, None,
    None, None, None, None, None, None, None, None, None, None, None, None, None,
    None, None, None, None, None, None, Some(94), Some(59), Some(92), Some(91),
    Some(28), Some(29), Some(50), Some(15), Some(10), Some(11), Some(17), Some(51),
    Some(14), Some(52), Some(53), Some(16), Some(0), Some(1), Some(2), Some(3),
    Some(4), Some(5), Some(6), Some(7), Some(8), Some(9), Some(27), Some(54),
    Some(55), Some(56), Some(57), Some(58), Some(26), Some(82), Some(83),
    Some(84), Some(85), Some(86), Some(87), Some(88), Some(89), Some(32), Some(33),
    Some(34), Some(35), Some(36), Some(37), Some(38), Some(39), Some(40), Some(41),
    Some(42), Some(43), Some(44), Some(45), Some(46), Some(47), Some(48), Some(49),
    Some(12), Some(93), Some(13), Some(60), Some(61), Some(90), Some(18), Some(19),
    Some(20), Some(21), Some(22), Some(23), Some(24), Some(25), Some(64), Some(65),
    Some(66), Some(67), Some(68), Some(69), Some(70), Some(71), Some(72), Some(73),
    Some(74), Some(75), Some(76), Some(77), Some(78), Some(79), Some(80), Some(81),
    Some(30), Some(62), Some(31), Some(63), None,
];

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

/// A trait for extracting a structure from a Tree representation in token form
pub trait FromTree: Sized {
    /// Extract a structure from Tree representation
    fn from_tree(top: &Tree) -> Result<Self, Error>;
}

enum Found {
    Nothing,
    LBracket(usize), // Either a left ( or {
    Comma(usize),
    RBracket(usize), // Either a right ) or }
}

fn next_expr(sl: &str, delim: char) -> Found {
    let mut found = Found::Nothing;
    if delim == '(' {
        for (n, ch) in sl.char_indices() {
            match ch {
                '(' => {
                    found = Found::LBracket(n);
                    break;
                }
                ',' => {
                    found = Found::Comma(n);
                    break;
                }
                ')' => {
                    found = Found::RBracket(n);
                    break;
                }
                _ => {}
            }
        }
    } else if delim == '{' {
        let mut new_count = 0;
        for (n, ch) in sl.char_indices() {
            match ch {
                '{' => {
                    found = Found::LBracket(n);
                    break;
                }
                '(' => {
                    new_count += 1;
                }
                ',' => {
                    if new_count == 0 {
                        found = Found::Comma(n);
                        break;
                    }
                }
                ')' => {
                    new_count -= 1;
                }
                '}' => {
                    found = Found::RBracket(n);
                    break;
                }
                _ => {}
            }
        }
    } else {
        unreachable!("{}", "Internal: delimiters in parsing must be '(' or '{'");
    }
    found
}

// Get the corresponding delim
fn closing_delim(delim: char) -> char {
    match delim {
        '(' => ')',
        '{' => '}',
        _ => unreachable!("Unknown delimiter"),
    }
}

impl<'a> Tree<'a> {
    /// Parse an expression with round brackets
    pub fn from_slice(sl: &'a str) -> Result<(Tree<'a>, &'a str), Error> {
        // Parsing TapTree or just miniscript
        Self::from_slice_delim(sl, 0u32, '(')
    }

    fn parse_pre_check(s: &str, open: u8, close: u8) -> Result<(), ParseTreeError> {
        // First, scan through string to make sure it is well-formed.
        let mut max_depth = 0;
        // Do ASCII check first; after this we can use .bytes().enumerate() rather
        // than .char_indices(), which is *significantly* faster.
        for (pos, ch) in s.char_indices() {
            if !(32..128).contains(&u32::from(ch)) {
                return Err(ParseTreeError::InvalidCharacter { ch, pos });
            }
        }

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

        Ok(())
    }

    pub(crate) fn from_slice_delim(
        mut sl: &'a str,
        depth: u32,
        delim: char,
    ) -> Result<(Tree<'a>, &'a str), Error> {
        if depth == 0 {
            if delim == '{' {
                Self::parse_pre_check(sl, b'{', b'}').map_err(Error::ParseTree)?;
            } else {
                Self::parse_pre_check(sl, b'(', b')').map_err(Error::ParseTree)?;
            }
        }

        match next_expr(sl, delim) {
            // String-ending terminal
            Found::Nothing => Ok((Tree { name: sl, args: vec![] }, "")),
            // Terminal
            Found::Comma(n) | Found::RBracket(n) => {
                Ok((Tree { name: &sl[..n], args: vec![] }, &sl[n..]))
            }
            // Function call
            Found::LBracket(n) => {
                let mut ret = Tree { name: &sl[..n], args: vec![] };

                sl = &sl[n + 1..];
                loop {
                    let (arg, new_sl) = Tree::from_slice_delim(sl, depth + 1, delim)?;
                    ret.args.push(arg);

                    if new_sl.is_empty() {
                        unreachable!()
                    }

                    sl = &new_sl[1..];
                    match new_sl.as_bytes()[0] {
                        b',' => {}
                        last_byte => {
                            if last_byte == closing_delim(delim) as u8 {
                                break;
                            } else {
                                unreachable!()
                            }
                        }
                    }
                }
                Ok((ret, sl))
            }
        }
    }

    /// Parses a tree from a string
    #[allow(clippy::should_implement_trait)] // Cannot use std::str::FromStr because of lifetimes.
    pub fn from_str(s: &'a str) -> Result<Tree<'a>, Error> {
        check_valid_chars(s)?;

        let (top, rem) = Tree::from_slice(s)?;
        if rem.is_empty() {
            Ok(top)
        } else {
            unreachable!()
        }
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

/// Filter out non-ASCII because we byte-index strings all over the
/// place and Rust gets very upset when you splinch a string.
pub fn check_valid_chars(s: &str) -> Result<(), Error> {
    for ch in s.bytes() {
        if !ch.is_ascii() {
            return Err(Error::Unprintable(ch));
        }
        // Index bounds: We know that ch is ASCII, so it is <= 127.
        if VALID_CHARS[ch as usize].is_none() {
            return Err(Error::Unexpected(
                "Only characters in INPUT_CHARSET are allowed".to_string(),
            ));
        }
    }
    Ok(())
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
    fn test_valid_char_map() {
        let mut valid_chars = [None; 128];
        for (i, ch) in super::INPUT_CHARSET.chars().enumerate() {
            valid_chars[ch as usize] = Some(i as u8);
        }
        assert_eq!(valid_chars, super::VALID_CHARS);
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
