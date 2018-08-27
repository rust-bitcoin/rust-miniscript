// Script Descriptor Language
// Written in 2018 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Function-like Expression Language
//!

use std::str::FromStr;

use Error;
use errstr;

#[derive(Debug)]
/// A token of the form `x(...)` or `x`
pub struct Tree<'a> {
    /// The name `x`
    pub name: &'a str,
    /// The comma-separated contents of the `(...)`, if any
    pub args: Vec<Tree<'a>>,
}

pub trait FromTree: Sized {
    fn from_tree(top: &Tree) -> Result<Self, Error>;
}

impl<'a> Tree<'a> {
    fn from_slice(mut sl: &'a str) -> Result<(Tree<'a>, &'a str), Error> {
        enum Found { Nothing, Lparen(usize), Comma(usize), Rparen(usize) }

        let mut found = Found::Nothing;
        for (n, ch) in sl.char_indices() {
            match ch {
                '(' => { found = Found::Lparen(n); break; }
                ',' => { found = Found::Comma(n); break; }
                ')' => { found = Found::Rparen(n); break; }
                _ => {}
            }
        }

        match found {
            // Unexpected EOF
            Found::Nothing => Err(Error::ExpectedChar(')')),
            // Terminal
            Found::Comma(n) | Found::Rparen(n) => {
                Ok((
                    Tree {
                        name: &sl[..n],
                        args: vec![],
                    },
                    &sl[n..],
                ))
            }
            // Function call
            Found::Lparen(n) => {
                let mut ret = Tree {
                    name: &sl[..n],
                    args: vec![],
                };

                sl = &sl[n + 1..];
                loop {
                    let (arg, new_sl) = Tree::from_slice(sl)?;
                    ret.args.push(arg);

                    if new_sl.is_empty() {
                        return Err(Error::ExpectedChar(')'));
                    }

                    sl = &new_sl[1..];
                    match new_sl.as_bytes()[0] {
                        b',' => {},
                        b')' => break,
                        _ => return Err(Error::ExpectedChar(','))
                    }
                }
                Ok((ret, sl))
            }
        }
    }

    /// Parses a tree from a string
    pub fn from_str(s: &'a str) -> Result<Tree<'a>, Error> {
        // Filter out non-ASCII because we byte-index strings all over the
        // place and Rust gets very upset when you splinch a string.
        for ch in s.bytes() {
            if ch > 0x7f {
                return Err(Error::Unprintable(ch));
            }
        }

        let (top, rem) = Tree::from_slice(s)?;
        if rem.is_empty() {
            Ok(top)
        } else {
            Err(errstr(rem))
        }
    }
}

/// Parse a string as a u32, for timelocks or thresholds
pub fn parse_num(s: &str) -> Result<u32, Error> {
    u32::from_str(s).map_err(|_| errstr(s))
}

/// Attempts to parse a terminal expression
pub fn terminal<T, F, Err>(term: &Tree, convert: F) -> Result<T, Error>
    where F: FnOnce(&str) -> Result<T, Err>,
          Err: ToString,
{
    if term.args.is_empty() {
        convert(term.name).map_err(|e| Error::Unexpected(e.to_string()))
    } else {
        Err(errstr(term.name))
    }
}

/// Attempts to parse an expression with exactly two children
pub fn unary<L, T, F>(term: &Tree, convert: F) -> Result<T, Error>
    where L: FromTree,
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
    where L: FromTree,
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

