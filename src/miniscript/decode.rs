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

//! Script Decoder
//!
//! Functionality to parse a Bitcoin Script into a `Miniscript`
//!

use bitcoin;

use miniscript::astelem::AstElem;
use miniscript::lex::{Token, TokenIter};
use miniscript::Error;

macro_rules! is_fn(
    (E) => (AstElem::is_e);
    (Q) => (AstElem::is_q);
    (W) => (AstElem::is_w);
    (V) => (AstElem::is_v);
    (F) => (AstElem::is_f);
    (T) => (AstElem::is_t);
);

macro_rules! expect_token(
    ($tokens:expr, $expected:pat => $b:block) => ({
        match $tokens.next() {
            Some($expected) => $b,
            Some(tok) => return Err(Error::Unexpected(tok.to_string())),
            None => return Err(Error::UnexpectedStart),
        }
    });
    ($tokens:expr, $expected:pat) => (expect_token!($tokens, $expected => {}));
);

macro_rules! parse_tree(
    // Tree
    (
        // list of tokens passed into macro scope
        $tokens:expr,
        // list of expected tokens
        $($expected:pat $(, $more:pat)* => { $($sub:tt)* }),*
        // list of expected subexpressions. The whole thing is surrounded
        // in a $(..)* because it's optional. But it should only be used once.
        $(
        #subexpression $($parse_expected:tt: $name:ident $(, $parse_more:pat)* => { $($parse_sub:tt)* }),*
        )*
    ) => ({
        match $tokens.next() {
            $(Some($expected) => {
                $(expect_token!($tokens, $more);)*
                parse_tree!($tokens, $($sub)*)
            },)*
            Some(tok) => {
                #[allow(unused_assignments)]
                #[allow(unused_mut)]
                let mut ret: Result<AstElem<bitcoin::PublicKey>, Error> = Err(Error::Unexpected(tok.to_string()));
                $(
                $tokens.un_next(tok);
                let subexpr = parse($tokens)?;
                ret =
                $(if is_fn!($parse_expected)(&subexpr) {
                    let $name = subexpr;
                    $(expect_token!($tokens, $parse_more);)*
                    parse_tree!($tokens, $($parse_sub)*)
                } else)* {
                    Err(Error::Unexpected(subexpr.to_string()))
                };
                )*
                ret
            }
            None => return Err(Error::UnexpectedStart),
        }
    });
    // Not a tree; must be a block
    ($tokens:expr, $($b:tt)*) => ({ $($b)* });
);

/// Parse a script fragment into an `AstElem`
pub fn parse(tokens: &mut TokenIter) -> Result<AstElem<bitcoin::PublicKey>, Error> {
    let ret: Result<AstElem<bitcoin::PublicKey>, Error> = parse_tree!(tokens,
        Token::BoolAnd => {
            #subexpression
            W: wexpr => {
                #subexpression
                E: expr => {
                    Ok(AstElem::AndBool(Box::new(expr), Box::new(wexpr)))
                }
            }
        },
        Token::BoolOr => {
            #subexpression
            W: wexpr => {
                #subexpression
                E: expr => {
                    Ok(AstElem::OrBool(Box::new(expr), Box::new(wexpr)))
                }
            }
        },
        Token::Equal => {
            Token::Sha256Hash(hash), Token::Sha256, Token::EqualVerify, Token::Number(32), Token::Size => {
                Ok(AstElem::HashT(hash))
            },
            Token::Number(k) => {{
                let mut subs = vec![];
                loop {
                    match tokens.next() {
                        Some(Token::Add) => {
                            let next_sub = parse(tokens)?;
                            if next_sub.is_w() {
                                subs.push(next_sub);
                            } else {
                                return Err(Error::Unexpected(next_sub.to_string()));
                            }
                        }
                        Some(x) => {
                            tokens.un_next(x);
                            let next_sub = parse(tokens)?;
                            if next_sub.is_e() {
                                subs.push(next_sub);
                                break;
                            } else {
                                return Err(Error::Unexpected(next_sub.to_string()));
                            }
                        }
                        None => return Err(Error::UnexpectedStart)
                    }
                }
                subs.reverse();
                Ok(AstElem::Thresh(k as usize, subs))
            }}
        },
        Token::EqualVerify => {
            Token::Sha256Hash(hash), Token::Sha256, Token::EqualVerify, Token::Number(32), Token::Size => {
                Ok(AstElem::HashV(hash))
            },
            Token::Number(k) => {{
                let mut subs = vec![];
                loop {
                    match tokens.next() {
                        Some(Token::Add) => {
                            let next_sub = parse(tokens)?;
                            if next_sub.is_w() {
                                subs.push(next_sub);
                            } else {
                                return Err(Error::Unexpected(next_sub.to_string()));
                            }
                        }
                        Some(x) => {
                            tokens.un_next(x);
                            let next_sub = parse(tokens)?;
                            if next_sub.is_e() {
                                subs.push(next_sub);
                                break;
                            } else {
                                return Err(Error::Unexpected(next_sub.to_string()));
                            }
                        }
                        None => return Err(Error::UnexpectedStart)
                    }
                }
                subs.reverse();
                Ok(AstElem::ThreshV(k as usize, subs))
            }}
        },
        Token::CheckSig => {
            Token::Pubkey(pk) => {{
                match tokens.next() {
                    Some(Token::Swap) => Ok(AstElem::PkW(pk)),
                    Some(x) => {
                        tokens.un_next(x);
                        Ok(AstElem::Pk(pk))
                    }
                    None => Ok(AstElem::Pk(pk)),
                }
            }},
            Token::EndIf => {
                #subexpression
                Q: right => {
                    Token::Else => {
                        #subexpression
                        Q: left, Token::If => {
                            Ok(AstElem::OrKey(Box::new(left), Box::new(right)))
                        }
                    }
                }
            }
        },
        Token::CheckSigVerify => {
            Token::Pubkey(pk) => {
                Ok(AstElem::PkV(pk))
            },
            Token::EndIf => {
                #subexpression
                Q: right => {
                    Token::Else => {
                        #subexpression
                        Q: left, Token::If => {
                            Ok(AstElem::OrKeyV(Box::new(left), Box::new(right)))
                        }
                    }
                }
            }
        },
        Token::CheckMultiSig => {{
            let n = expect_token!(tokens, Token::Number(n) => { n });
            let mut pks = vec![];
            for _ in 0..n {
                pks.push(expect_token!(tokens, Token::Pubkey(pk) => { pk }));
            }
            pks.reverse();
            let k = expect_token!(tokens, Token::Number(n) => { n });
            Ok(AstElem::Multi(k as usize, pks))
        }},
        Token::CheckMultiSigVerify => {{
            let n = expect_token!(tokens, Token::Number(n) => { n });
            let mut pks = vec![];
            for _ in 0..n {
                pks.push(expect_token!(tokens, Token::Pubkey(pk) => { pk }));
            }
            pks.reverse();
            let k = expect_token!(tokens, Token::Number(n) => { n });
            Ok(AstElem::MultiV(k as usize, pks))
        }},
        Token::ZeroNotEqual, Token::CheckSequenceVerify => {
            Token::Number(n) => {
                Ok(AstElem::TimeF(n))
            }
        },
        Token::CheckSequenceVerify => {
            Token::Number(n) => {
                Ok(AstElem::TimeT(n))
            }
        },
        Token::FromAltStack => {
            #subexpression
            E: expr, Token::ToAltStack => {
                Ok(AstElem::Wrap(Box::new(expr)))
            }
        },
        Token::Drop, Token::CheckSequenceVerify => {
            Token::Number(n) => {
                Ok(AstElem::TimeV(n))
            }
        },
        Token::EndIf => {
            Token::Drop, Token::CheckSequenceVerify => {
                Token::Number(n), Token::If, Token::Dup => {{
                    match tokens.next() {
                        Some(Token::Swap) => Ok(AstElem::TimeW(n)),
                        Some(x) => {
                            tokens.un_next(x);
                            Ok(AstElem::Time(n))
                        }
                        None => Ok(AstElem::Time(n))
                    }
                }}
            },
            Token::Number(0), Token::Else => {
                #subexpression
                F: right => {
                    Token::If => {
                        Ok(AstElem::Unlikely(Box::new(right)))
                    },
                    Token::NotIf => {
                        Ok(AstElem::Likely(Box::new(right)))
                    }
                }
            }
            #subexpression
            Q: right => {
                Token::Else => {
                    #subexpression
                    Q: left, Token::If => {
                        Ok(AstElem::OrIf(Box::new(left), Box::new(right)))
                    }
                }
            },
            F: right => {
                Token::If, Token::ZeroNotEqual, Token::Size, Token::Swap => {{
                    // Rust doesn't let us match on Box<enum> so we've gotta
                    // destructure into `trued` and `truebox` then dereference
                    // both in order to check that they're what we expect.
                    if let AstElem::AndCat(trued, truebox) = right {
                        if let AstElem::True = *truebox {
                            if let AstElem::HashV(hash) = *trued {
                                Ok(AstElem::HashW(hash))
                            } else {
                                Err(Error::Unexpected(truebox.to_string()))
                            }
                        } else {
                            Err(Error::Unexpected(trued.to_string()))
                        }
                    } else {
                        Err(Error::Unexpected(right.to_string()))
                    }
                }},
                Token::Else => {
                    Token::Number(0), Token::NotIf => {
                        #subexpression
                        E: left => {
                            Ok(AstElem::AndCasc(Box::new(left), Box::new(right)))
                        }
                    }
                    #subexpression
                    F: left, Token::If => {
                        Ok(AstElem::OrIf(Box::new(left), Box::new(right)))
                    }
                }
            },
            E: right => {
                Token::Else => {
                    #subexpression
                    F: left => {
                        Token::If => {
                            Ok(AstElem::OrIf(Box::new(left), Box::new(right)))
                        },
                        Token::NotIf => {
                            Ok(AstElem::OrNotif(Box::new(left), Box::new(right)))
                        }
                    }
                }
            },
            V: right => {
                Token::Else => {
                    #subexpression
                    V: left, Token::If => {
                        Ok(AstElem::OrIf(Box::new(left), Box::new(right)))
                    }
                },
                Token::NotIf => {
                    #subexpression
                    E: left => {
                        Ok(AstElem::OrCont(Box::new(left), Box::new(right)))
                    }
                }
            },
            T: right => {
                Token::Else => {
                    #subexpression
                    T: left, Token::If => {
                        Ok(AstElem::OrIf(Box::new(left), Box::new(right)))
                    }
                },
                Token::NotIf, Token::IfDup => {
                    #subexpression
                    E: left => {
                        Ok(AstElem::OrCasc(Box::new(left), Box::new(right)))
                    }
                }
            }
        },
        Token::Verify => { 
            Token::EndIf => {
                #subexpression
                T: right, Token::Else => {
                    #subexpression
                    T: left, Token::If => {
                        Ok(AstElem::OrIfV(Box::new(left), Box::new(right)))
                    }
                }
            }
        },
        Token::Number(1) => {
            Ok(AstElem::True)
        },
        Token::Pubkey(pk) => {
            Ok(AstElem::PkQ(pk))
        }
    );

    if let Ok(right) = ret {
        // vexpr [tfvq]expr AND
        if right.is_t() || right.is_f() || right.is_v() || right.is_q() {
            match tokens.peek() {
                None | Some(&Token::If) | Some(&Token::NotIf) | Some(&Token::Else) => Ok(right),
                _ => {
                    let left = parse(tokens)?;
                    if !left.is_v() {
                        return Err(Error::Unexpected(left.to_string()))
                    };

                    Ok(AstElem::AndCat(Box::new(left), Box::new(right)))
                }
            }
        } else {
            Ok(right)
        }
    } else {
        ret
    }
}

