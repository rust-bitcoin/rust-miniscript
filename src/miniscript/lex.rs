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
use bitcoin::PublicKey;
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
    CheckSig,
    CheckMultiSig,
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
        match ins {
            script::Instruction::Error(e) => return Err(Error::Script(e)),
            script::Instruction::Op(opcodes::all::OP_BOOLAND) => {
                ret.push(Token::BoolAnd);
            },
            script::Instruction::Op(opcodes::all::OP_BOOLOR) => {
                ret.push(Token::BoolOr);
            },
            script::Instruction::Op(opcodes::all::OP_EQUAL) => {
                ret.push(Token::Equal);
            },
            script::Instruction::Op(opcodes::all::OP_EQUALVERIFY) => {
                ret.push(Token::Equal);
                ret.push(Token::Verify);
            },
            script::Instruction::Op(opcodes::all::OP_CHECKSIG) => {
                ret.push(Token::CheckSig);
            },
            script::Instruction::Op(opcodes::all::OP_CHECKSIGVERIFY) => {
                ret.push(Token::CheckSig);
                ret.push(Token::Verify);
            }
            script::Instruction::Op(opcodes::all::OP_CHECKMULTISIG) => {
                ret.push(Token::CheckMultiSig);
            },
            script::Instruction::Op(opcodes::all::OP_CHECKMULTISIGVERIFY) => {
                ret.push(Token::CheckMultiSig);
                ret.push(Token::Verify);
            }
            script::Instruction::Op(op) if op == opcodes::OP_CSV => {
                ret.push(Token::CheckSequenceVerify);
            },
            script::Instruction::Op(opcodes::all::OP_FROMALTSTACK) => {
                ret.push(Token::FromAltStack);
            },
            script::Instruction::Op(opcodes::all::OP_TOALTSTACK) => {
                ret.push(Token::ToAltStack);
            },
            script::Instruction::Op(opcodes::all::OP_DROP) => {
                ret.push(Token::Drop);
            },
            script::Instruction::Op(opcodes::all::OP_DUP) => {
                ret.push(Token::Dup);
            },
            script::Instruction::Op(opcodes::all::OP_ADD) => {
                ret.push(Token::Add);
            },
            script::Instruction::Op(opcodes::all::OP_IF) => {
                ret.push(Token::If);
            },
            script::Instruction::Op(opcodes::all::OP_IFDUP) => {
                ret.push(Token::IfDup);
            },
            script::Instruction::Op(opcodes::all::OP_NOTIF) => {
                ret.push(Token::NotIf);
            },
            script::Instruction::Op(opcodes::all::OP_ELSE) => {
                ret.push(Token::Else);
            },
            script::Instruction::Op(opcodes::all::OP_ENDIF) => {
                ret.push(Token::EndIf);
            },
            script::Instruction::Op(opcodes::all::OP_0NOTEQUAL) => {
                ret.push(Token::ZeroNotEqual);
            },
            script::Instruction::Op(opcodes::all::OP_SIZE) => {
                ret.push(Token::Size);
            },
            script::Instruction::Op(opcodes::all::OP_SWAP) => {
                ret.push(Token::Swap);
            },
            script::Instruction::Op(opcodes::all::OP_VERIFY) => {
                ret.push(Token::Verify);
            },
            script::Instruction::Op(opcodes::all::OP_HASH160) => {
                ret.push(Token::Hash160);
            },
            script::Instruction::Op(opcodes::all::OP_SHA256) => {
                ret.push(Token::Sha256);
            },
            script::Instruction::PushBytes(bytes) => {
                match bytes.len() {
                    20 => {
                        ret.push(Token::Hash160Hash(hash160::Hash::from_slice(bytes).unwrap()));
                    },
                    32 => {
                        ret.push(Token::Sha256Hash(sha256::Hash::from_slice(bytes).unwrap()));
                    },
                    33 => {
                        ret.push(Token::Pubkey(PublicKey::from_slice(bytes).map_err(Error::BadPubkey)?));
                    },
                    _ => {
                        match script::read_scriptint(bytes) {
                            Ok(v) if v >= 0 => {
                                // check minimality of the number
                                if &script::Builder::new().push_int(v).into_script()[1..] != bytes {
                                    return Err(Error::InvalidPush(bytes.to_owned()));
                                }
                                ret.push(Token::Number(v as u32));
                            }
                            Ok(_) => return Err(Error::InvalidPush(bytes.to_owned())),
                            Err(e) => return Err(Error::Script(e)),
                        }
                    }
                }
            }
            script::Instruction::Op(opcodes::all::OP_PUSHBYTES_0) => {
                ret.push(Token::Number(0));
            },
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_1) => {
                ret.push(Token::Number(1));
            },
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_2) => {
                ret.push(Token::Number(2));
            },
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_3) => {
                ret.push(Token::Number(3));
            },
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_4) => {
                ret.push(Token::Number(4));
            },
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_5) => {
                ret.push(Token::Number(5));
            },
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_6) => {
                ret.push(Token::Number(6));
            },
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_7) => {
                ret.push(Token::Number(7));
            },
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_8) => {
                ret.push(Token::Number(8));
            },
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_9) => {
                ret.push(Token::Number(9));
            },
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_10) => {
                ret.push(Token::Number(10));
            },
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_11) => {
                ret.push(Token::Number(11));
            },
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_12) => {
                ret.push(Token::Number(12));
            },
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_13) => {
                ret.push(Token::Number(13));
            },
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_14) => {
                ret.push(Token::Number(14));
            },
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_15) => {
                ret.push(Token::Number(15));
            },
            script::Instruction::Op(opcodes::all::OP_PUSHNUM_16) => {
                ret.push(Token::Number(16));
            },
            script::Instruction::Op(op) => return Err(Error::InvalidOpcode(op)),
        };
    }
    Ok(ret)
}
