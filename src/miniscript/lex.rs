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

use bitcoin::blockdata::{opcodes, script};

use std::fmt;

use super::Error;

/// Atom of a tokenized version of a script
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Token<'s> {
    BoolAnd,
    BoolOr,
    Add,
    Equal,
    NumEqual,
    CheckSig,
    CheckSigAdd,
    CheckMultiSig,
    CheckSequenceVerify,
    CheckLockTimeVerify,
    CheckTemplateVerify,
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
    Verify,
    Ripemd160,
    Hash160,
    Sha256,
    Hash256,
    Num(u32),
    Hash20(&'s [u8]),
    Bytes32(&'s [u8]),
    Bytes33(&'s [u8]),
    Bytes65(&'s [u8]),
}

impl<'s> fmt::Display for Token<'s> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Token::Num(n) => write!(f, "#{}", n),
            Token::Hash20(b) | Token::Bytes33(b) | Token::Bytes32(b) | Token::Bytes65(b) => {
                for ch in &b[..] {
                    write!(f, "{:02x}", *ch)?;
                }
                Ok(())
            }
            x => write!(f, "{:?}", x),
        }
    }
}

#[derive(Debug, Clone)]
/// Iterator that goes through a vector of tokens backward (our parser wants to read
/// backward and this is more efficient anyway since we can use `Vec::pop()`).
pub struct TokenIter<'s>(Vec<Token<'s>>);

impl<'s> TokenIter<'s> {
    /// Create a new TokenIter
    pub fn new(v: Vec<Token<'s>>) -> TokenIter<'s> {
        TokenIter(v)
    }

    /// Look at the top at Iterator
    pub fn peek(&self) -> Option<&'s Token> {
        self.0.last()
    }

    /// Push a value to the iterator
    /// This will be first value consumed by popun_
    pub fn un_next(&mut self, tok: Token<'s>) {
        self.0.push(tok)
    }

    /// The len of the iterator
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl<'s> Iterator for TokenIter<'s> {
    type Item = Token<'s>;

    fn next(&mut self) -> Option<Token<'s>> {
        self.0.pop()
    }
}

/// Tokenize a script
pub fn lex<'s>(script: &'s script::Script) -> Result<Vec<Token<'s>>, Error> {
    let mut ret = Vec::with_capacity(script.len());

    for ins in script.instructions_minimal() {
        match ins.map_err(Error::Script)? {
            script::Instruction::Op(opcodes::all::OP_BOOLAND) => {
                ret.push(Token::BoolAnd);
            }
            script::Instruction::Op(opcodes::all::OP_BOOLOR) => {
                ret.push(Token::BoolOr);
            }
            script::Instruction::Op(opcodes::all::OP_EQUAL) => {
                ret.push(Token::Equal);
            }
            script::Instruction::Op(opcodes::all::OP_EQUALVERIFY) => {
                ret.push(Token::Equal);
                ret.push(Token::Verify);
            }
            script::Instruction::Op(opcodes::all::OP_NUMEQUAL) => {
                ret.push(Token::NumEqual);
            }
            script::Instruction::Op(opcodes::all::OP_NUMEQUALVERIFY) => {
                ret.push(Token::NumEqual);
                ret.push(Token::Verify);
            }
            script::Instruction::Op(opcodes::all::OP_CHECKSIG) => {
                ret.push(Token::CheckSig);
            }
            script::Instruction::Op(opcodes::all::OP_CHECKSIGVERIFY) => {
                ret.push(Token::CheckSig);
                ret.push(Token::Verify);
            }
            // Change once the opcode name is updated
            script::Instruction::Op(opcodes::all::OP_CHECKSIGADD) => {
                ret.push(Token::CheckSigAdd);
            }
            script::Instruction::Op(opcodes::all::OP_CHECKMULTISIG) => {
                ret.push(Token::CheckMultiSig);
            }
            script::Instruction::Op(opcodes::all::OP_CHECKMULTISIGVERIFY) => {
                ret.push(Token::CheckMultiSig);
                ret.push(Token::Verify);
            }
            script::Instruction::Op(op) if op == opcodes::all::OP_CSV => {
                ret.push(Token::CheckSequenceVerify);
            }
            script::Instruction::Op(op) if op == opcodes::all::OP_CLTV => {
                ret.push(Token::CheckLockTimeVerify);
            }
            script::Instruction::Op(op) if op == opcodes::all::OP_NOP4 => {
                ret.push(Token::CheckTemplateVerify);
            }
            script::Instruction::Op(opcodes::all::OP_FROMALTSTACK) => {
                ret.push(Token::FromAltStack);
            }
            script::Instruction::Op(opcodes::all::OP_TOALTSTACK) => {
                ret.push(Token::ToAltStack);
            }
            script::Instruction::Op(opcodes::all::OP_DROP) => {
                ret.push(Token::Drop);
            }
            script::Instruction::Op(opcodes::all::OP_DUP) => {
                ret.push(Token::Dup);
            }
            script::Instruction::Op(opcodes::all::OP_ADD) => {
                ret.push(Token::Add);
            }
            script::Instruction::Op(opcodes::all::OP_IF) => {
                ret.push(Token::If);
            }
            script::Instruction::Op(opcodes::all::OP_IFDUP) => {
                ret.push(Token::IfDup);
            }
            script::Instruction::Op(opcodes::all::OP_NOTIF) => {
                ret.push(Token::NotIf);
            }
            script::Instruction::Op(opcodes::all::OP_ELSE) => {
                ret.push(Token::Else);
            }
            script::Instruction::Op(opcodes::all::OP_ENDIF) => {
                ret.push(Token::EndIf);
            }
            script::Instruction::Op(opcodes::all::OP_0NOTEQUAL) => {
                ret.push(Token::ZeroNotEqual);
            }
            script::Instruction::Op(opcodes::all::OP_SIZE) => {
                ret.push(Token::Size);
            }
            script::Instruction::Op(opcodes::all::OP_SWAP) => {
                ret.push(Token::Swap);
            }
            script::Instruction::Op(opcodes::all::OP_VERIFY) => {
                match ret.last() {
                    Some(op @ &Token::Equal)
                    | Some(op @ &Token::CheckSig)
                    | Some(op @ &Token::CheckMultiSig) => {
                        return Err(Error::NonMinimalVerify(String::from(format!("{:?}", op))))
                    }
                    _ => {}
                }
                ret.push(Token::Verify);
            }
            script::Instruction::Op(opcodes::all::OP_RIPEMD160) => {
                ret.push(Token::Ripemd160);
            }
            script::Instruction::Op(opcodes::all::OP_HASH160) => {
                ret.push(Token::Hash160);
            }
            script::Instruction::Op(opcodes::all::OP_SHA256) => {
                ret.push(Token::Sha256);
            }
            script::Instruction::Op(opcodes::all::OP_HASH256) => {
                ret.push(Token::Hash256);
            }
            script::Instruction::PushBytes(bytes) => {
                match bytes.len() {
                    20 => ret.push(Token::Hash20(&bytes)),
                    32 => ret.push(Token::Bytes32(&bytes)),
                    33 => ret.push(Token::Bytes33(&bytes)),
                    65 => ret.push(Token::Bytes65(&bytes)),
                    _ => {
                        match script::read_scriptint(bytes) {
                            Ok(v) if v >= 0 => {
                                // check minimality of the number
                                if &script::Builder::new().push_int(v).into_script()[1..] != bytes {
                                    return Err(Error::InvalidPush(bytes.to_owned()));
                                }
                                ret.push(Token::Num(v as u32));
                            }
                            Ok(_) => return Err(Error::InvalidPush(bytes.to_owned())),
                            Err(e) => return Err(Error::Script(e)),
                        }
                    }
                }
            }
            script::Instruction::Op(opcodes::all::OP_PUSHBYTES_0) => {
                ret.push(Token::Num(0));
            }
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_1) => {
                ret.push(Token::Num(1));
            }
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_2) => {
                ret.push(Token::Num(2));
            }
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_3) => {
                ret.push(Token::Num(3));
            }
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_4) => {
                ret.push(Token::Num(4));
            }
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_5) => {
                ret.push(Token::Num(5));
            }
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_6) => {
                ret.push(Token::Num(6));
            }
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_7) => {
                ret.push(Token::Num(7));
            }
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_8) => {
                ret.push(Token::Num(8));
            }
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_9) => {
                ret.push(Token::Num(9));
            }
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_10) => {
                ret.push(Token::Num(10));
            }
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_11) => {
                ret.push(Token::Num(11));
            }
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_12) => {
                ret.push(Token::Num(12));
            }
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_13) => {
                ret.push(Token::Num(13));
            }
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_14) => {
                ret.push(Token::Num(14));
            }
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_15) => {
                ret.push(Token::Num(15));
            }
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_16) => {
                ret.push(Token::Num(16));
            }
            script::Instruction::Op(op) => return Err(Error::InvalidOpcode(op)),
        };
    }
    Ok(ret)
}
