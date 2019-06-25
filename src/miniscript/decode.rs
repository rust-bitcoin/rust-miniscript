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
use bitcoin_hashes::{Hash, hash160, ripemd160, sha256, sha256d};

use miniscript::astelem::AstElem;
use miniscript::lex::{Token as Tk, TokenIter};
use miniscript::Error;

#[derive(Copy, Clone, Debug)]
enum NonTerm {
    Expression,
    MaybeAndV,
    Alt,
    Check,
    DupIf,
    Verify,
    NonZero,
    ZeroNotEqual,
    AndV,
    AndB,
    Tern,
    OrB,
    OrD,
    OrC,
    ThreshW { k: usize, n: usize },
    ThreshE { k: usize, n: usize },
    // could be or_d, or_c, or_i, d:, n:
    EndIf,
    // could be or_d, or_c
    EndIfNotIf,
    // could be or_i or tern
    EndIfElse,
}

macro_rules! match_token {
    // Base case
    ($tokens:expr => $sub:expr,) => { $sub };
    // Recursive case
    ($tokens:expr, $($first:pat $(,$rest:pat)* => $sub:expr,)*) => {
        match $tokens.next() {
            $(
                Some($first) => match_token!($tokens $(,$rest)* => $sub,),
            )*
            Some(other) => return Err(Error::Unexpected(other.to_string())),
            None => return Err(Error::UnexpectedStart),
        }
    };
}

fn rewrap1<Pk, Pkh, F>(term: &mut Vec<AstElem<Pk, Pkh>>, wrap: F)
where
    F: FnOnce(Box<AstElem<Pk, Pkh>>) -> AstElem<Pk, Pkh>
{
    let top = term.pop().unwrap();
    term.push(wrap(Box::new(top)));
}

fn rewrap2<Pk, Pkh, F>(term: &mut Vec<AstElem<Pk, Pkh>>, wrap: F)
where
    F: FnOnce(Box<AstElem<Pk, Pkh>>, Box<AstElem<Pk, Pkh>>) -> AstElem<Pk, Pkh>
{
    let left = term.pop().unwrap();
    let right = term.pop().unwrap();
    term.push(wrap(Box::new(left), Box::new(right)));
}

/// Parse a script fragment into an `AstElem`
#[allow(unreachable_patterns)]
pub fn parse(
    tokens: &mut TokenIter,
) -> Result<AstElem<bitcoin::PublicKey, hash160::Hash>, Error> {
    let mut non_term = Vec::with_capacity(tokens.len());
    let mut term = Vec::with_capacity(tokens.len());

    non_term.push(NonTerm::MaybeAndV);
    non_term.push(NonTerm::Expression);
    loop {
        // Special-case OP_SWAP prefixing to allow SWAPs to appear
        // basically everywhere without pushing `NonTerm::MaybeSwap`
        // before `NonTerm::Expression` basically everywhere.
        if let Some(top) = term.pop() {
            match non_term.last() {
                Some(&NonTerm::Verify)
                    | Some(&NonTerm::Check)
                    | Some(&NonTerm::OrD) => {
                        // no SWAPs inside `v:` or `c:` or in the
                        // leftmost part of an `or_d`
                        term.push(top);
                    },
                _ => {
                    if let Some(&Tk::Swap) = tokens.peek() {
                        tokens.next();
                        term.push(AstElem::Swap(Box::new(top)));
                    } else {
                        term.push(top);
                    }
                }
            }
        }

        match non_term.pop() {
            Some(NonTerm::Expression) => {
                match_token!(
                    tokens,
                    // pubkey
                    Tk::Pubkey(pk) => term.push(AstElem::Pk(pk)),
                    // checksig
                    Tk::CheckSig => {
                        non_term.push(NonTerm::Check);
                        non_term.push(NonTerm::Expression);
                    },
                    // pubkeyhash and [T] VERIFY and [T] 0NOTEQUAL
                    Tk::Verify => match_token!(
                        tokens,
                        Tk::Equal, Tk::Hash20(hash), Tk::Hash160, Tk::Dup
                            => term.push(AstElem::PkH(
                                hash160::Hash::from_inner(hash)
                            )),
                        x => {
                            tokens.un_next(x);
                            non_term.push(NonTerm::Verify);
                            non_term.push(NonTerm::Expression);
                        },
                    ),
                    Tk::ZeroNotEqual => {
                        non_term.push(NonTerm::ZeroNotEqual);
                        non_term.push(NonTerm::Expression);
                    },
                    // timelocks
                    Tk::CheckSequenceVerify, Tk::Num(n)
                        => term.push(AstElem::After(n)),
                    Tk::CheckLockTimeVerify, Tk::Num(n)
                        => term.push(AstElem::Older(n)),
                    // hashlocks
                    Tk::Equal => match_token!(
                        tokens,
                        Tk::Hash32(hash) => match_token!(
                            tokens,
                            Tk::Sha256,
                            Tk::Verify,
                            Tk::Equal,
                            Tk::Num(32),
                            Tk::Size => term.push(AstElem::Sha256(
                                sha256::Hash::from_inner(hash)
                            )),
                            Tk::Hash256,
                            Tk::Verify,
                            Tk::Equal,
                            Tk::Num(32),
                            Tk::Size => term.push(AstElem::Hash256(
                                sha256d::Hash::from_inner(hash)
                            )),
                        ),
                        Tk::Hash20(hash) => match_token!(
                            tokens,
                            Tk::Ripemd160,
                            Tk::Verify,
                            Tk::Equal,
                            Tk::Num(32),
                            Tk::Size => term.push(AstElem::Ripemd160(
                                ripemd160::Hash::from_inner(hash)
                            )),
                            Tk::Hash160,
                            Tk::Verify,
                            Tk::Equal,
                            Tk::Num(32),
                            Tk::Size => term.push(AstElem::Hash160(
                                hash160::Hash::from_inner(hash)
                            )),
                        ),
                        // thresholds
                        Tk::Num(k) => {
                            non_term.push(NonTerm::ThreshW {
                                k: k as usize,
                                n: 0
                            });
                            // note we do *not* expect an `Expression` here;
                            // the `ThreshW` handler below will look for
                            // `OP_ADD` or not and do the right thing
                        },
                    ),
                    // fromaltstack
                    Tk::FromAltStack => {
                        non_term.push(NonTerm::Alt);
                        non_term.push(NonTerm::MaybeAndV);
                        non_term.push(NonTerm::Expression);
                    },
                    // most other fragments
                    Tk::Num(0) => term.push(AstElem::False),
                    Tk::Num(1) => term.push(AstElem::True),
                    Tk::EndIf => {
                        non_term.push(NonTerm::EndIf);
                        non_term.push(NonTerm::MaybeAndV);
                        non_term.push(NonTerm::Expression);
                    },
                    // boolean conjunctions and disjunctions
                    Tk::BoolAnd => {
                        non_term.push(NonTerm::AndB);
                        non_term.push(NonTerm::Expression);
                        non_term.push(NonTerm::Expression);
                    },
                    Tk::BoolOr => {
                        non_term.push(NonTerm::OrB);
                        non_term.push(NonTerm::Expression);
                        non_term.push(NonTerm::Expression);
                    },
                    // CHECKMULTISIG based multisig
                    Tk::CheckMultiSig, Tk::Num(n) => {
                        if n > 20 {
                            return Err(Error::CmsTooManyKeys(n));
                        }
                        let mut keys = Vec::with_capacity(n as usize);
                        for _ in 0..n {
                            match_token!(
                                tokens,
                                Tk::Pubkey(pk) => keys.push(pk),
                            );
                        }
                        let k = match_token!(
                            tokens,
                            Tk::Num(k) => k,
                        );
                        keys.reverse();
                        term.push(AstElem::ThreshM(k as usize, keys));
                    },
                );
            },
            Some(NonTerm::MaybeAndV) => {
                // Handle `and_v` prefixing
                match tokens.peek() {
                    None
                        | Some(&Tk::If)
                        | Some(&Tk::NotIf)
                        | Some(&Tk::Else)
                        | Some(&Tk::ToAltStack) => {},
                    _ => {
                        non_term.push(NonTerm::AndV);
                        non_term.push(NonTerm::Expression);
                    }
                }
            },
            Some(NonTerm::Alt) => {
                match_token!(
                    tokens,
                    Tk::ToAltStack => {},
                );
                rewrap1(&mut term, AstElem::Alt);
            },
            Some(NonTerm::Check) => rewrap1(&mut term, AstElem::Check),
            Some(NonTerm::DupIf) => rewrap1(&mut term, AstElem::DupIf),
            Some(NonTerm::Verify) => rewrap1(&mut term, AstElem::Verify),
            Some(NonTerm::NonZero) => rewrap1(&mut term, AstElem::NonZero),
            Some(NonTerm::ZeroNotEqual)
                => rewrap1(&mut term, AstElem::ZeroNotEqual),
            Some(NonTerm::AndV) => rewrap2(&mut term, AstElem::AndV),
            Some(NonTerm::AndB) => rewrap2(&mut term, AstElem::AndB),
            Some(NonTerm::OrB) => rewrap2(&mut term, AstElem::OrB),
            Some(NonTerm::OrC) => rewrap2(&mut term, AstElem::OrC),
            Some(NonTerm::OrD) => rewrap2(&mut term, AstElem::OrD),
            Some(NonTerm::Tern) => {
                let a = term.pop().unwrap();
                let b = term.pop().unwrap();
                let c = term.pop().unwrap();
                term.push(
                    AstElem::AndOr(Box::new(a), Box::new(b), Box::new(c))
                );
            },
            Some(NonTerm::ThreshW { n, k }) => {
                match_token!(
                    tokens,
                    Tk::Add => {
                        non_term.push(NonTerm::ThreshW { n: n + 1, k });
                    },
                    x => {
                        tokens.un_next(x);
                        non_term.push(NonTerm::ThreshE { n: n + 1, k });
                    },
                );
                non_term.push(NonTerm::Expression);
            },
            Some(NonTerm::ThreshE { n, k }) => {
                let mut subs = Vec::with_capacity(n);
                for _ in 0..n {
                    subs.push(term.pop().unwrap());
                }
                term.push(AstElem::Thresh(k, subs));
            },
            Some(NonTerm::EndIf) => {
                match_token!(
                    tokens,
                    Tk::Else => {
                        non_term.push(NonTerm::EndIfElse);
                        non_term.push(NonTerm::MaybeAndV);
                        non_term.push(NonTerm::Expression);
                    },
                    Tk::If => match_token!(
                        tokens,
                        Tk::Dup => non_term.push(NonTerm::DupIf),
                        Tk::ZeroNotEqual, Tk::Size
                            => non_term.push(NonTerm::NonZero),
                    ),
                    Tk::NotIf => {
                        non_term.push(NonTerm::EndIfNotIf);
                    },
                );
            },
            Some(NonTerm::EndIfNotIf) => {
                match_token!(
                    tokens,
                    Tk::IfDup => non_term.push(NonTerm::OrD),
                    x => {
                        tokens.un_next(x);
                        non_term.push(NonTerm::OrC);
                    },
                );
                non_term.push(NonTerm::Expression);
            },
            Some(NonTerm::EndIfElse) => {
                match_token!(
                    tokens,
                    Tk::If => {
                        let left = term.pop().unwrap();
                        let right = term.pop().unwrap();
                        term.push(AstElem::OrI(
                            Box::new(left),
                            Box::new(right),
                        ));
                    },
                    Tk::NotIf => {
                        non_term.push(NonTerm::Tern);
                        non_term.push(NonTerm::Expression);
                    },
                );
            },
            None => {
                // Done :)
                break;
            },
        }
    }

    assert_eq!(non_term.len(), 0);
    assert_eq!(term.len(), 1);
    Ok(term.pop().unwrap())
}
