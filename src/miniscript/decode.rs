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

use bitcoin::hashes::{hash160, ripemd160, sha256, sha256d, Hash};
use std::marker::PhantomData;
use {bitcoin, Miniscript};

use miniscript::lex::{Token as Tk, TokenIter};
use miniscript::types::extra_props::ExtData;
use miniscript::types::Property;
use miniscript::types::Type;
use miniscript::ScriptContext;
use std::sync::Arc;
use Error;
use MiniscriptKey;

fn return_none<T>(_: usize) -> Option<T> {
    None
}

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
/// All AST elements
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Terminal<Pk: MiniscriptKey, Ctx: ScriptContext> {
    /// `1`
    True,
    /// `0`
    False,
    // pubkey checks
    /// `<key>`
    PkK(Pk),
    /// `DUP HASH160 <keyhash> EQUALVERIFY`
    PkH(Pk::Hash),
    // timelocks
    /// `n CHECKLOCKTIMEVERIFY`
    After(u32),
    /// `n CHECKSEQUENCEVERIFY`
    Older(u32),
    // hashlocks
    /// `SIZE 32 EQUALVERIFY SHA256 <hash> EQUAL`
    Sha256(sha256::Hash),
    /// `SIZE 32 EQUALVERIFY HASH256 <hash> EQUAL`
    Hash256(sha256d::Hash),
    /// `SIZE 32 EQUALVERIFY RIPEMD160 <hash> EQUAL`
    Ripemd160(ripemd160::Hash),
    /// `SIZE 32 EQUALVERIFY HASH160 <hash> EQUAL`
    Hash160(hash160::Hash),
    // Wrappers
    /// `TOALTSTACK [E] FROMALTSTACK`
    Alt(Arc<Miniscript<Pk, Ctx>>),
    /// `SWAP [E1]`
    Swap(Arc<Miniscript<Pk, Ctx>>),
    /// `[Kt]/[Ke] CHECKSIG`
    Check(Arc<Miniscript<Pk, Ctx>>),
    /// `DUP IF [V] ENDIF`
    DupIf(Arc<Miniscript<Pk, Ctx>>),
    /// [T] VERIFY
    Verify(Arc<Miniscript<Pk, Ctx>>),
    /// SIZE 0NOTEQUAL IF [Fn] ENDIF
    NonZero(Arc<Miniscript<Pk, Ctx>>),
    /// [X] 0NOTEQUAL
    ZeroNotEqual(Arc<Miniscript<Pk, Ctx>>),
    // Conjunctions
    /// [V] [T]/[V]/[F]/[Kt]
    AndV(Arc<Miniscript<Pk, Ctx>>, Arc<Miniscript<Pk, Ctx>>),
    /// [E] [W] BOOLAND
    AndB(Arc<Miniscript<Pk, Ctx>>, Arc<Miniscript<Pk, Ctx>>),
    /// [various] NOTIF [various] ELSE [various] ENDIF
    AndOr(
        Arc<Miniscript<Pk, Ctx>>,
        Arc<Miniscript<Pk, Ctx>>,
        Arc<Miniscript<Pk, Ctx>>,
    ),
    // Disjunctions
    /// [E] [W] BOOLOR
    OrB(Arc<Miniscript<Pk, Ctx>>, Arc<Miniscript<Pk, Ctx>>),
    /// [E] IFDUP NOTIF [T]/[E] ENDIF
    OrD(Arc<Miniscript<Pk, Ctx>>, Arc<Miniscript<Pk, Ctx>>),
    /// [E] NOTIF [V] ENDIF
    OrC(Arc<Miniscript<Pk, Ctx>>, Arc<Miniscript<Pk, Ctx>>),
    /// IF [various] ELSE [various] ENDIF
    OrI(Arc<Miniscript<Pk, Ctx>>, Arc<Miniscript<Pk, Ctx>>),
    // Thresholds
    /// [E] ([W] ADD)* k EQUAL
    Thresh(usize, Vec<Arc<Miniscript<Pk, Ctx>>>),
    /// k (<key>)* n CHECKMULTISIG
    Multi(usize, Vec<Pk>),
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

///Vec representing terminals stack while decoding.
struct TerminalStack<Pk: MiniscriptKey, Ctx: ScriptContext>(Vec<Miniscript<Pk, Ctx>>);

impl<Pk: MiniscriptKey, Ctx: ScriptContext> TerminalStack<Pk, Ctx> {
    ///Wrapper around self.0.pop()
    fn pop(&mut self) -> Option<Miniscript<Pk, Ctx>> {
        self.0.pop()
    }

    ///reduce, type check and push a 0-arg node
    fn reduce0(&mut self, ms: Terminal<Pk, Ctx>) -> Result<(), Error> {
        Ctx::check_frag_validity(&ms)?;

        let ty = Type::type_check(&ms, return_none)?;
        let ext = ExtData::type_check(&ms, return_none)?;
        self.0.push(Miniscript {
            node: ms,
            ty: ty,
            ext: ext,
            phantom: PhantomData,
        });
        Ok(())
    }

    ///reduce, type check and push a 1-arg node
    fn reduce1<F>(&mut self, wrap: F) -> Result<(), Error>
    where
        F: FnOnce(Arc<Miniscript<Pk, Ctx>>) -> Terminal<Pk, Ctx>,
    {
        let top = self.pop().unwrap();
        let wrapped_ms = wrap(Arc::new(top));
        Ctx::check_frag_validity(&wrapped_ms)?;

        let ty = Type::type_check(&wrapped_ms, return_none)?;
        let ext = ExtData::type_check(&wrapped_ms, return_none)?;
        self.0.push(Miniscript {
            node: wrapped_ms,
            ty: ty,
            ext: ext,
            phantom: PhantomData,
        });
        Ok(())
    }

    ///reduce, type check and push a 2-arg node
    fn reduce2<F>(&mut self, wrap: F) -> Result<(), Error>
    where
        F: FnOnce(Arc<Miniscript<Pk, Ctx>>, Arc<Miniscript<Pk, Ctx>>) -> Terminal<Pk, Ctx>,
    {
        let left = self.pop().unwrap();
        let right = self.pop().unwrap();

        let wrapped_ms = wrap(Arc::new(left), Arc::new(right));
        Ctx::check_frag_validity(&wrapped_ms)?;

        let ty = Type::type_check(&wrapped_ms, return_none)?;
        let ext = ExtData::type_check(&wrapped_ms, return_none)?;
        self.0.push(Miniscript {
            node: wrapped_ms,
            ty: ty,
            ext: ext,
            phantom: PhantomData,
        });
        Ok(())
    }
}

/// Parse a script fragment into an `Terminal`
#[allow(unreachable_patterns)]
pub fn parse<Ctx: ScriptContext>(
    tokens: &mut TokenIter,
) -> Result<Miniscript<bitcoin::PublicKey, Ctx>, Error> {
    let mut non_term = Vec::with_capacity(tokens.len());
    let mut term = TerminalStack(Vec::with_capacity(tokens.len()));

    non_term.push(NonTerm::MaybeAndV);
    non_term.push(NonTerm::MaybeSwap);
    non_term.push(NonTerm::Expression);
    loop {
        match non_term.pop() {
            Some(NonTerm::Expression) => {
                match_token!(
                    tokens,
                    // pubkey
                    Tk::Pubkey(pk) => term.reduce0(Terminal::PkK(pk))?,
                    // checksig
                    Tk::CheckSig => {
                        non_term.push(NonTerm::Check);
                        non_term.push(NonTerm::Expression);
                    },
                    // pubkeyhash and [T] VERIFY and [T] 0NOTEQUAL
                    Tk::Verify => match_token!(
                        tokens,
                        Tk::Equal => match_token!(
                            tokens,
                            Tk::Hash20(hash), Tk::Hash160, Tk::Dup => {
                                term.reduce0(Terminal::PkH(
                                    hash160::Hash::from_inner(hash)
                                ))?
                            },
                            Tk::Hash32(hash), Tk::Sha256, Tk::Verify, Tk::Equal, Tk::Num(32), Tk::Size => {
                                non_term.push(NonTerm::Verify);
                                term.reduce0(Terminal::Sha256(
                                    sha256::Hash::from_inner(hash)
                                ))?
                            },
                        ),
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
                        => term.reduce0(Terminal::Older(n))?,
                    Tk::CheckLockTimeVerify, Tk::Num(n)
                        => term.reduce0(Terminal::After(n))?,
                    // hashlocks
                    Tk::Equal => match_token!(
                        tokens,
                        Tk::Hash32(hash) => match_token!(
                            tokens,
                            Tk::Sha256,
                            Tk::Verify,
                            Tk::Equal,
                            Tk::Num(32),
                            Tk::Size => term.reduce0(Terminal::Sha256(
                                sha256::Hash::from_inner(hash)
                            ))?,
                            Tk::Hash256,
                            Tk::Verify,
                            Tk::Equal,
                            Tk::Num(32),
                            Tk::Size => term.reduce0(Terminal::Hash256(
                                sha256d::Hash::from_inner(hash)
                            ))?,
                        ),
                        Tk::Hash20(hash) => match_token!(
                            tokens,
                            Tk::Ripemd160,
                            Tk::Verify,
                            Tk::Equal,
                            Tk::Num(32),
                            Tk::Size => term.reduce0(Terminal::Ripemd160(
                                ripemd160::Hash::from_inner(hash)
                            ))?,
                            Tk::Hash160,
                            Tk::Verify,
                            Tk::Equal,
                            Tk::Num(32),
                            Tk::Size => term.reduce0(Terminal::Hash160(
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
                    Tk::Num(0) => term.reduce0(Terminal::False)?,
                    Tk::Num(1) => term.reduce0(Terminal::True)?,
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
                        term.reduce0(Terminal::Multi(k as usize, keys))?;
                    },
                );
            }
            Some(NonTerm::MaybeAndV) => {
                // Handle `and_v` prefixing
                if is_and_v(tokens) {
                    non_term.push(NonTerm::AndV);
                    non_term.push(NonTerm::Expression);
                }
            }
            Some(NonTerm::MaybeSwap) => {
                // Handle `SWAP` prefixing
                if let Some(&Tk::Swap) = tokens.peek() {
                    tokens.next();
                    //                    let top = term.pop().unwrap();
                    term.reduce1(Terminal::Swap)?;
                    //                    term.push(Terminal::Swap(Arc::new(top)));
                    non_term.push(NonTerm::MaybeSwap);
                }
            }
            Some(NonTerm::Alt) => {
                match_token!(
                    tokens,
                    Tk::ToAltStack => {},
                );
                term.reduce1(Terminal::Alt)?;
            }
            Some(NonTerm::Check) => term.reduce1(Terminal::Check)?,
            Some(NonTerm::DupIf) => term.reduce1(Terminal::DupIf)?,
            Some(NonTerm::Verify) => term.reduce1(Terminal::Verify)?,
            Some(NonTerm::NonZero) => term.reduce1(Terminal::NonZero)?,
            Some(NonTerm::ZeroNotEqual) => term.reduce1(Terminal::ZeroNotEqual)?,
            Some(NonTerm::AndV) => {
                if is_and_v(tokens) {
                    non_term.push(NonTerm::AndV);
                    non_term.push(NonTerm::MaybeAndV);
                } else {
                    term.reduce2(Terminal::AndV)?
                }
            }
            Some(NonTerm::AndB) => term.reduce2(Terminal::AndB)?,
            Some(NonTerm::OrB) => term.reduce2(Terminal::OrB)?,
            Some(NonTerm::OrC) => term.reduce2(Terminal::OrC)?,
            Some(NonTerm::OrD) => term.reduce2(Terminal::OrD)?,
            Some(NonTerm::Tern) => {
                let a = term.pop().unwrap();
                let b = term.pop().unwrap();
                let c = term.pop().unwrap();
                let wrapped_ms = Terminal::AndOr(Arc::new(a), Arc::new(c), Arc::new(b));

                let ty = Type::type_check(&wrapped_ms, return_none)?;
                let ext = ExtData::type_check(&wrapped_ms, return_none)?;

                term.0.push(Miniscript {
                    node: wrapped_ms,
                    ty: ty,
                    ext: ext,
                    phantom: PhantomData,
                });
            }
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
            }
            Some(NonTerm::ThreshE { n, k }) => {
                let mut subs = Vec::with_capacity(n);
                for _ in 0..n {
                    subs.push(Arc::new(term.pop().unwrap()));
                }
                term.reduce0(Terminal::Thresh(k, subs))?;
            }
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
            }
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
            }
            Some(NonTerm::EndIfElse) => {
                match_token!(
                    tokens,
                    Tk::If => {
                        term.reduce2(Terminal::OrI)?;
                    },
                    Tk::NotIf => {
                        non_term.push(NonTerm::Tern);
                        non_term.push(NonTerm::Expression);
                    },
                );
            }
            None => {
                // Done :)
                break;
            }
        }
    }

    assert_eq!(non_term.len(), 0);
    assert_eq!(term.0.len(), 1);
    Ok(term.pop().unwrap())
}

fn is_and_v(tokens: &mut TokenIter) -> bool {
    match tokens.peek() {
        None | Some(&Tk::If) | Some(&Tk::NotIf) | Some(&Tk::Else) | Some(&Tk::ToAltStack) => false,
        _ => true,
    }
}
