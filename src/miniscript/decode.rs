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

use ::{bitcoin, Miniscript};
use bitcoin_hashes::{Hash, hash160, ripemd160, sha256, sha256d};

use miniscript::lex::{Token as Tk, TokenIter};
use miniscript::types::Type;
use miniscript::types::extra_props::ExtData;
use miniscript::types::Property;
use std;
use Error;
use miniscript::astelem::AstElem;

fn return_none<T>(_: usize) -> Option<T> { None }

#[derive(Copy, Clone, Debug)]
enum NonTerm {
    Expression,
    MaybeSwap,
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

trait Decodable <Pk, Pkh>{
    fn push_ast0(&mut self, ms : AstElem<Pk, Pkh>) -> Result<(), Error>
        where Pk: Clone + std::fmt::Debug + std::fmt::Display,
              Pkh:Clone + std::fmt::Debug + std::fmt::Display;

    fn push_ast1<F>(&mut self, wrap: F) -> Result<(), Error>
        where  F: FnOnce(Box<Miniscript<Pk, Pkh>>) -> AstElem<Pk, Pkh>,
               Pk: Clone + std::fmt::Debug + std::fmt::Display,
               Pkh:Clone + std::fmt::Debug + std::fmt::Display;

    fn push_ast2<F>(&mut self, wrap: F) -> Result<(), Error>
        where
            F: FnOnce(Box<Miniscript<Pk, Pkh>>, Box<Miniscript<Pk, Pkh>>) -> AstElem<Pk, Pkh>,
            Pk: Clone + std::fmt::Debug + std::fmt::Display,
            Pkh:Clone + std::fmt::Debug + std::fmt::Display;
}
impl<Pk, Pkh> Decodable<Pk, Pkh> for Vec<Miniscript<Pk, Pkh>> {

    fn push_ast0(&mut self, ms : AstElem<Pk, Pkh>) -> Result<(), Error>
        where Pk: Clone + std::fmt::Debug + std::fmt::Display,
              Pkh:Clone + std::fmt::Debug + std::fmt::Display,
    {
        let ty = Type::type_check(&ms, return_none)?;
        let ext = ExtData::type_check(&ms, return_none)?;
        self.push(Miniscript{node: ms, ty: ty, ext: ext});
        Ok(())
    }

    fn push_ast1<F>(&mut self, wrap: F) -> Result<(), Error>
        where  F: FnOnce(Box<Miniscript<Pk, Pkh>>) -> AstElem<Pk, Pkh>,
        Pk: Clone + std::fmt::Debug + std::fmt::Display,
        Pkh:Clone + std::fmt::Debug + std::fmt::Display,
    {
        let top = self.pop().unwrap();
        let wrapped_ms = wrap(Box::new(top));

        let ty = Type::type_check(&wrapped_ms, return_none)?;
        let ext = ExtData::type_check(&wrapped_ms, return_none)?;
        self.push(Miniscript{node: wrapped_ms, ty: ty, ext: ext});
        Ok(())
    }

    fn push_ast2<F>(&mut self, wrap: F) -> Result<(), Error>
    where
        F: FnOnce(Box<Miniscript<Pk, Pkh>>, Box<Miniscript<Pk, Pkh>>) -> AstElem<Pk, Pkh>,
        Pk: Clone + std::fmt::Debug + std::fmt::Display,
        Pkh:Clone + std::fmt::Debug + std::fmt::Display,
    {
        let left = self.pop().unwrap();
        let right = self.pop().unwrap();

        let wrapped_ms = wrap(Box::new(left), Box::new(right));
        let ty = Type::type_check(&wrapped_ms, return_none)?;
        let ext = ExtData::type_check(&wrapped_ms, return_none)?;
        self.push(Miniscript{node: wrapped_ms, ty: ty, ext: ext});
        Ok(())
    }
}

/// Parse a script fragment into an `Terminal`
#[allow(unreachable_patterns)]
pub fn parse(
    tokens: &mut TokenIter,
) -> Result<Miniscript<bitcoin::PublicKey, hash160::Hash>, Error> {
    let mut non_term = Vec::with_capacity(tokens.len());
    let mut term = Vec::with_capacity(tokens.len());

    non_term.push(NonTerm::MaybeAndV);
    non_term.push(NonTerm::MaybeSwap);
    non_term.push(NonTerm::Expression);
    loop {
        match non_term.pop() {
            Some(NonTerm::Expression) => {
                match_token!(
                    tokens,
                    // pubkey
                    Tk::Pubkey(pk) => term.push_ast0(AstElem::Pk(pk))?,
                    // checksig
                    Tk::CheckSig => {
                        non_term.push(NonTerm::Check);
                        non_term.push(NonTerm::Expression);
                    },
                    // pubkeyhash and [T] VERIFY and [T] 0NOTEQUAL
                    Tk::Verify => match_token!(
                        tokens,
                        Tk::Equal, Tk::Hash20(hash), Tk::Hash160, Tk::Dup
                            => term.push_ast0(AstElem::PkH(
                                hash160::Hash::from_inner(hash)
                            ))?,
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
                        => term.push_ast0(AstElem::After(n))?,
                    Tk::CheckLockTimeVerify, Tk::Num(n)
                        => term.push_ast0(AstElem::Older(n))?,
                    // hashlocks
                    Tk::Equal => match_token!(
                        tokens,
                        Tk::Hash32(hash) => match_token!(
                            tokens,
                            Tk::Sha256,
                            Tk::Verify,
                            Tk::Equal,
                            Tk::Num(32),
                            Tk::Size => term.push_ast0(AstElem::Sha256(
                                sha256::Hash::from_inner(hash)
                            ))?,
                            Tk::Hash256,
                            Tk::Verify,
                            Tk::Equal,
                            Tk::Num(32),
                            Tk::Size => term.push_ast0(AstElem::Hash256(
                                sha256d::Hash::from_inner(hash)
                            ))?,
                        ),
                        Tk::Hash20(hash) => match_token!(
                            tokens,
                            Tk::Ripemd160,
                            Tk::Verify,
                            Tk::Equal,
                            Tk::Num(32),
                            Tk::Size => term.push_ast0(AstElem::Ripemd160(
                                ripemd160::Hash::from_inner(hash)
                            ))?,
                            Tk::Hash160,
                            Tk::Verify,
                            Tk::Equal,
                            Tk::Num(32),
                            Tk::Size => term.push_ast0(AstElem::Hash160(
                                hash160::Hash::from_inner(hash)
                            ))?,
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
                        non_term.push(NonTerm::MaybeSwap);
                        non_term.push(NonTerm::Expression);
                    },
                    // most other fragments
                    Tk::Num(0) => term.push_ast0(AstElem::False)?,
                    Tk::Num(1) => term.push_ast0(AstElem::True)?,
                    Tk::EndIf => {
                        non_term.push(NonTerm::EndIf);
                        non_term.push(NonTerm::MaybeAndV);
                        non_term.push(NonTerm::MaybeSwap);
                        non_term.push(NonTerm::Expression);
                    },
                    // boolean conjunctions and disjunctions
                    Tk::BoolAnd => {
                        non_term.push(NonTerm::AndB);
                        non_term.push(NonTerm::Expression);
                        non_term.push(NonTerm::MaybeSwap);
                        non_term.push(NonTerm::Expression);
                    },
                    Tk::BoolOr => {
                        non_term.push(NonTerm::OrB);
                        non_term.push(NonTerm::Expression);
                        non_term.push(NonTerm::MaybeSwap);
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
                        term.push_ast0(AstElem::ThreshM(k as usize, keys))?;
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
            Some(NonTerm::MaybeSwap) => {
                // Handle `SWAP` prefixing
                if let Some(&Tk::Swap) = tokens.peek() {
                    tokens.next();
//                    let top = term.pop().unwrap();
                    term.push_ast1(AstElem::Swap)?;
//                    term.push(AstElem::Swap(Box::new(top)));
                    non_term.push(NonTerm::MaybeSwap);
                }
            },
            Some(NonTerm::Alt) => {
                match_token!(
                    tokens,
                    Tk::ToAltStack => {},
                );
                term.push_ast1(AstElem::Alt)?;
            },
            Some(NonTerm::Check) => term.push_ast1(AstElem::Check)?,
            Some(NonTerm::DupIf) => term.push_ast1(AstElem::DupIf)?,
            Some(NonTerm::Verify) => term.push_ast1(AstElem::Verify)?,
            Some(NonTerm::NonZero) => term.push_ast1(AstElem::NonZero)?,
            Some(NonTerm::ZeroNotEqual)
                => term.push_ast1(AstElem::ZeroNotEqual)?,
            Some(NonTerm::AndV) => term.push_ast2(AstElem::AndV)?,
            Some(NonTerm::AndB) => term.push_ast2(AstElem::AndB)?,
            Some(NonTerm::OrB) => term.push_ast2(AstElem::OrB)?,
            Some(NonTerm::OrC) => term.push_ast2(AstElem::OrC)?,
            Some(NonTerm::OrD) => term.push_ast2(AstElem::OrD)?,
            Some(NonTerm::Tern) => {
                let a = term.pop().unwrap();
                let b = term.pop().unwrap();
                let c = term.pop().unwrap();
                let wrapped_ms = AstElem::AndOr(Box::new(a), Box::new(b), Box::new(c));

                let ty = Type::type_check(&wrapped_ms, return_none)?;
                let ext = ExtData::type_check(&wrapped_ms, return_none)?;

                term.push(Miniscript{node: wrapped_ms, ty: ty, ext: ext});
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
                non_term.push(NonTerm::MaybeSwap);
                non_term.push(NonTerm::Expression);
            },
            Some(NonTerm::ThreshE { n, k }) => {
                let mut subs = Vec::with_capacity(n);
                for _ in 0..n {
                    subs.push(term.pop().unwrap());
                }
                term.push_ast0(AstElem::Thresh(k, subs))?;
            },
            Some(NonTerm::EndIf) => {
                match_token!(
                    tokens,
                    Tk::Else => {
                        non_term.push(NonTerm::EndIfElse);
                        non_term.push(NonTerm::MaybeAndV);
                        non_term.push(NonTerm::MaybeSwap);
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
                        term.push_ast2(AstElem::OrI)?;
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
