// Miniscript
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

//! Lexer
//!
//! Translates a script into a reversed sequence of tokens
//!

use bitcoin::blockdata::script;
use bitcoin::blockdata::opcodes;
use bitcoin::util::key::PublicKey;
use bitcoin_hashes::{Hash, hash160, sha256};

use std::fmt;

use super::Error;

/// Atom of a tokenized version of a script
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Token {
    BoolAnd,
    BoolOr,
    Add,
    Equal,
    EqualVerify,
    CheckSig,
    CheckSigVerify,
    CheckMultiSig,
    CheckMultiSigVerify,
    CheckSequenceVerify,
    FromAltStack,
    ToAltStack,
    Drop,
    Dup,
    If,
    IfDup,
    NotIf,
    Else,
    EndIf,
    ZeroNotEqual,
    Size,
    Swap,
    Tuck,
    Verify,
    Hash160,
    Sha256,
    Number(u32),
    Hash160Hash(hash160::Hash),
    Sha256Hash(sha256::Hash),
    Pubkey(PublicKey),
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Token::Number(n) => write!(f, "#{}", n),
            Token::Hash160Hash(hash) => {
                for ch in &hash[..] {
                    write!(f, "{:02x}", *ch)?;
                }
                Ok(())
            }
            Token::Sha256Hash(hash) => write!(f, "{:x}", hash),
            Token::Pubkey(pk) => write!(f, "{}", pk),
            x => write!(f, "{:?}", x),
        }
    }
}

#[derive(Debug, Clone)]
/// Iterator that goes through a vector of tokens backward (our parser wants to read
/// backward and this is more efficient anyway since we can use `Vec::pop()`).
pub struct TokenIter(Vec<Token>);

impl TokenIter {
    pub fn new(v: Vec<Token>) -> TokenIter {
        TokenIter(v)
    }

    pub fn peek(&self) -> Option<&Token> {
        self.0.last()
    }

    pub fn un_next(&mut self, tok: Token) {
        self.0.push(tok)
    }
}

impl Iterator for TokenIter {
    type Item = Token;

    fn next(&mut self) -> Option<Token> {
        self.0.pop()
    }
}

/// Tokenize a script
pub fn lex(script: &script::Script) -> Result<Vec<Token>, Error> {
    let mut ret = Vec::with_capacity(script.len());

    for ins in script.iter(true) {
        ret.push(match ins {
            script::Instruction::Error(e) => return Err(Error::Script(e)),
            script::Instruction::Op(opcodes::all::OP_BOOLAND) => Token::BoolAnd,
            script::Instruction::Op(opcodes::all::OP_BOOLOR) => Token::BoolOr,
            script::Instruction::Op(opcodes::all::OP_EQUAL) => Token::Equal,
            script::Instruction::Op(opcodes::all::OP_EQUALVERIFY) => Token::EqualVerify,
            script::Instruction::Op(opcodes::all::OP_CHECKSIG) => Token::CheckSig,
            script::Instruction::Op(opcodes::all::OP_CHECKSIGVERIFY) => Token::CheckSigVerify,
            script::Instruction::Op(opcodes::all::OP_CHECKMULTISIG) => Token::CheckMultiSig,
            script::Instruction::Op(opcodes::all::OP_CHECKMULTISIGVERIFY) => Token::CheckMultiSigVerify,
            script::Instruction::Op(op) if op == opcodes::OP_CSV => Token::CheckSequenceVerify,
            script::Instruction::Op(opcodes::all::OP_FROMALTSTACK) => Token::FromAltStack,
            script::Instruction::Op(opcodes::all::OP_TOALTSTACK) => Token::ToAltStack,
            script::Instruction::Op(opcodes::all::OP_DROP) => Token::Drop,
            script::Instruction::Op(opcodes::all::OP_DUP) => Token::Dup,
            script::Instruction::Op(opcodes::all::OP_IF) => Token::If,
            script::Instruction::Op(opcodes::all::OP_IFDUP) => Token::IfDup,
            script::Instruction::Op(opcodes::all::OP_NOTIF) => Token::NotIf,
            script::Instruction::Op(opcodes::all::OP_ELSE) => Token::Else,
            script::Instruction::Op(opcodes::all::OP_ENDIF) => Token::EndIf,
            script::Instruction::Op(opcodes::all::OP_0NOTEQUAL) => Token::ZeroNotEqual,
            script::Instruction::Op(opcodes::all::OP_SIZE) => Token::Size,
            script::Instruction::Op(opcodes::all::OP_SWAP) => Token::Swap,
            script::Instruction::Op(opcodes::all::OP_TUCK) => Token::Tuck,
            script::Instruction::Op(opcodes::all::OP_VERIFY) => Token::Verify,
            script::Instruction::Op(opcodes::all::OP_HASH160) => Token::Hash160,
            script::Instruction::Op(opcodes::all::OP_SHA256) => Token::Sha256,
            script::Instruction::PushBytes(bytes) => {
                match bytes.len() {
                    20 => Token::Hash160Hash(hash160::Hash::from_slice(bytes).unwrap()),
                    32 => Token::Sha256Hash(sha256::Hash::from_slice(bytes).unwrap()),
                    33 => Token::Pubkey(PublicKey::from_slice(bytes).map_err(Error::BadPubkey)?),
                    _ => {
                        match script::read_scriptint(bytes) {
                            Ok(v) if v >= 0 => {
                                // check minimality of the number
                                if &script::Builder::new().push_int(v).into_script()[1..] != bytes {
                                    return Err(Error::InvalidPush(bytes.to_owned()));
                                }
                                Token::Number(v as u32)
                            }
                            Ok(_) => return Err(Error::InvalidPush(bytes.to_owned())),
                            Err(e) => return Err(Error::Script(e)),
                        }
                    }
                }
            }
            script::Instruction::Op(opcodes::all::OP_PUSHBYTES_0) => Token::Number(0),
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_1) => Token::Number(1),
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_2) => Token::Number(2),
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_3) => Token::Number(3),
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_4) => Token::Number(4),
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_5) => Token::Number(5),
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_6) => Token::Number(6),
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_7) => Token::Number(7),
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_8) => Token::Number(8),
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_9) => Token::Number(9),
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_10) => Token::Number(10),
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_11) => Token::Number(11),
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_12) => Token::Number(12),
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_13) => Token::Number(13),
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_14) => Token::Number(14),
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_15) => Token::Number(15),
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_16) => Token::Number(16),
            script::Instruction::Op(op) => return Err(Error::InvalidOpcode(op)),
        });
    }
    Ok(ret)
}
