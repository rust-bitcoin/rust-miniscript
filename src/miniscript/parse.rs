// Miniscript
// Written in 2019 by
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

//! AST Elements
//!
//! Trait describing a component of a Miniscript AST tree which has a more-or-less
//! trivial mapping to Script. It consists of five elements: `E`, `W`, `F`, `V`, `T`
//! which are defined below as enums. See the documentation for specific elements
//! for more information.
//!

use std::{fmt, str};
use std::rc::Rc;

use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script;
use bitcoin::util::key::PublicKey;
use bitcoin_hashes::hex::FromHex;
use bitcoin_hashes::sha256;

/// Parse a subexpression that is -not- a wexpr (wexpr is special-cased
/// to avoid splitting expr into expr0 and exprn in the AST structure).
pub fn parse_subexpression(tokens: &mut TokenIter) -> Result<Box<AstElem>, Error> {
