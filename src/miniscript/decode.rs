// Written in 2019 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Script Decoder
//!
//! Functionality to parse a Bitcoin Script into a `Miniscript`
//!

use core::fmt;
use core::marker::PhantomData;
#[cfg(feature = "std")]
use std::error;

use bitcoin::blockdata::constants::MAX_BLOCK_WEIGHT;
use bitcoin::hashes::{hash160, ripemd160, sha256, Hash};
use sync::Arc;

use crate::bitcoin::{LockTime, PackedLockTime, Sequence};
use crate::miniscript::lex::{Token as Tk, TokenIter};
use crate::miniscript::limits::MAX_PUBKEYS_PER_MULTISIG;
use crate::miniscript::types::extra_props::ExtData;
use crate::miniscript::types::{Property, Type};
use crate::miniscript::ScriptContext;
use crate::prelude::*;
#[cfg(doc)]
use crate::Descriptor;
use crate::{bitcoin, hash256, Error, Miniscript, MiniscriptKey, ToPublicKey};

fn return_none<T>(_: usize) -> Option<T> {
    None
}

/// Trait for parsing keys from byte slices
pub trait ParseableKey: Sized + ToPublicKey + private::Sealed {
    /// Parse a key from slice
    fn from_slice(sl: &[u8]) -> Result<Self, KeyParseError>;
}

impl ParseableKey for bitcoin::PublicKey {
    fn from_slice(sl: &[u8]) -> Result<Self, KeyParseError> {
        bitcoin::PublicKey::from_slice(sl).map_err(KeyParseError::FullKeyParseError)
    }
}

impl ParseableKey for bitcoin::secp256k1::XOnlyPublicKey {
    fn from_slice(sl: &[u8]) -> Result<Self, KeyParseError> {
        bitcoin::secp256k1::XOnlyPublicKey::from_slice(sl)
            .map_err(KeyParseError::XonlyKeyParseError)
    }
}

/// Decoding error while parsing keys
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyParseError {
    /// Bitcoin PublicKey parse error
    FullKeyParseError(bitcoin::util::key::Error),
    /// Xonly key parse Error
    XonlyKeyParseError(bitcoin::secp256k1::Error),
}

impl fmt::Display for KeyParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyParseError::FullKeyParseError(_e) => write!(f, "FullKey Parse Error"),
            KeyParseError::XonlyKeyParseError(_e) => write!(f, "XonlyKey Parse Error"),
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for KeyParseError {
    fn cause(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            KeyParseError::FullKeyParseError(e) => Some(e),
            KeyParseError::XonlyKeyParseError(e) => Some(e),
        }
    }
}

/// Private Mod to prevent downstream from implementing this public trait
mod private {

    pub trait Sealed {}

    // Implement for those same types, but no others.
    impl Sealed for super::bitcoin::PublicKey {}
    impl Sealed for super::bitcoin::secp256k1::XOnlyPublicKey {}
}

#[derive(Copy, Clone, Debug)]
enum NonTerm {
    Expression,
    WExpression,
    Swap,
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
/// All AST elements.
///
/// This variant is the inner Miniscript variant that allows the user to bypass some of the
/// miniscript rules. You should *never* construct `Terminal` directly. This is only exposed to
/// external users to allow matching on the [`Miniscript`].
///
/// The average user should always use the [`Descriptor`] APIs. Advanced users who want deal
/// with Miniscript ASTs should use the [`Miniscript`] APIs.
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
    PkH(Pk),
    /// Only for parsing PkH for Script. These raw descriptors are not yet specified in miniscript.
    /// We only this variant internally for inferring miniscripts from raw Scripts.
    /// It is not possible to construct this variant from any of the Miniscript APIs.
    /// We don't have a generic over here because we don't want to user to have any abstract reasoning
    /// over raw descriptors.
    RawPkH(hash160::Hash),
    // timelocks
    /// `n CHECKLOCKTIMEVERIFY`
    After(PackedLockTime),
    /// `n CHECKSEQUENCEVERIFY`
    Older(Sequence),
    // hashlocks
    /// `SIZE 32 EQUALVERIFY SHA256 <hash> EQUAL`
    Sha256(Pk::Sha256),
    /// `SIZE 32 EQUALVERIFY HASH256 <hash> EQUAL`
    Hash256(Pk::Hash256),
    /// `SIZE 32 EQUALVERIFY RIPEMD160 <hash> EQUAL`
    Ripemd160(Pk::Ripemd160),
    /// `SIZE 32 EQUALVERIFY HASH160 <hash> EQUAL`
    Hash160(Pk::Hash160),
    // Wrappers
    /// `TOALTSTACK [E] FROMALTSTACK`
    Alt(Arc<Miniscript<Pk, Ctx>>),
    /// `SWAP [E1]`
    Swap(Arc<Miniscript<Pk, Ctx>>),
    /// `[Kt]/[Ke] CHECKSIG`
    Check(Arc<Miniscript<Pk, Ctx>>),
    /// `DUP IF [V] ENDIF`
    DupIf(Arc<Miniscript<Pk, Ctx>>),
    /// `[T] VERIFY`
    Verify(Arc<Miniscript<Pk, Ctx>>),
    /// `SIZE 0NOTEQUAL IF [Fn] ENDIF`
    NonZero(Arc<Miniscript<Pk, Ctx>>),
    /// `[X] 0NOTEQUAL`
    ZeroNotEqual(Arc<Miniscript<Pk, Ctx>>),
    // Conjunctions
    /// `[V] [T]/[V]/[F]/[Kt]`
    AndV(Arc<Miniscript<Pk, Ctx>>, Arc<Miniscript<Pk, Ctx>>),
    /// `[E] [W] BOOLAND`
    AndB(Arc<Miniscript<Pk, Ctx>>, Arc<Miniscript<Pk, Ctx>>),
    /// `[various] NOTIF [various] ELSE [various] ENDIF`
    AndOr(
        Arc<Miniscript<Pk, Ctx>>,
        Arc<Miniscript<Pk, Ctx>>,
        Arc<Miniscript<Pk, Ctx>>,
    ),
    // Disjunctions
    /// `[E] [W] BOOLOR`
    OrB(Arc<Miniscript<Pk, Ctx>>, Arc<Miniscript<Pk, Ctx>>),
    /// `[E] IFDUP NOTIF [T]/[E] ENDIF`
    OrD(Arc<Miniscript<Pk, Ctx>>, Arc<Miniscript<Pk, Ctx>>),
    /// `[E] NOTIF [V] ENDIF`
    OrC(Arc<Miniscript<Pk, Ctx>>, Arc<Miniscript<Pk, Ctx>>),
    /// `IF [various] ELSE [various] ENDIF`
    OrI(Arc<Miniscript<Pk, Ctx>>, Arc<Miniscript<Pk, Ctx>>),
    // Thresholds
    /// `[E] ([W] ADD)* k EQUAL`
    Thresh(usize, Vec<Arc<Miniscript<Pk, Ctx>>>),
    /// `k (<key>)* n CHECKMULTISIG`
    Multi(usize, Vec<Pk>),
    /// `<key> CHECKSIG (<key> CHECKSIGADD)*(n-1) k NUMEQUAL`
    MultiA(usize, Vec<Pk>),
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
#[derive(Debug)]
struct TerminalStack<Pk: MiniscriptKey, Ctx: ScriptContext>(Vec<Miniscript<Pk, Ctx>>);

impl<Pk: MiniscriptKey, Ctx: ScriptContext> TerminalStack<Pk, Ctx> {
    ///Wrapper around self.0.pop()
    fn pop(&mut self) -> Option<Miniscript<Pk, Ctx>> {
        self.0.pop()
    }

    ///reduce, type check and push a 0-arg node
    fn reduce0(&mut self, ms: Terminal<Pk, Ctx>) -> Result<(), Error> {
        let ty = Type::type_check(&ms, return_none)?;
        let ext = ExtData::type_check(&ms, return_none)?;
        let ms = Miniscript {
            node: ms,
            ty,
            ext,
            phantom: PhantomData,
        };
        Ctx::check_global_validity(&ms)?;
        self.0.push(ms);
        Ok(())
    }

    ///reduce, type check and push a 1-arg node
    fn reduce1<F>(&mut self, wrap: F) -> Result<(), Error>
    where
        F: FnOnce(Arc<Miniscript<Pk, Ctx>>) -> Terminal<Pk, Ctx>,
    {
        let top = self.pop().unwrap();
        let wrapped_ms = wrap(Arc::new(top));

        let ty = Type::type_check(&wrapped_ms, return_none)?;
        let ext = ExtData::type_check(&wrapped_ms, return_none)?;
        let ms = Miniscript {
            node: wrapped_ms,
            ty,
            ext,
            phantom: PhantomData,
        };
        Ctx::check_global_validity(&ms)?;
        self.0.push(ms);
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

        let ty = Type::type_check(&wrapped_ms, return_none)?;
        let ext = ExtData::type_check(&wrapped_ms, return_none)?;
        let ms = Miniscript {
            node: wrapped_ms,
            ty,
            ext,
            phantom: PhantomData,
        };
        Ctx::check_global_validity(&ms)?;
        self.0.push(ms);
        Ok(())
    }
}

/// Parse a script fragment into an `Miniscript`
#[allow(unreachable_patterns)]
pub fn parse<Ctx: ScriptContext>(
    tokens: &mut TokenIter,
) -> Result<Miniscript<Ctx::Key, Ctx>, Error> {
    let mut non_term = Vec::with_capacity(tokens.len());
    let mut term = TerminalStack(Vec::with_capacity(tokens.len()));

    // top level cannot be swap, must be B
    non_term.push(NonTerm::MaybeAndV);
    non_term.push(NonTerm::Expression);
    loop {
        match non_term.pop() {
            Some(NonTerm::Expression) => {
                match_token!(
                    tokens,
                    // pubkey
                    Tk::Bytes33(pk) => {
                        let ret = Ctx::Key::from_slice(pk)
                            .map_err(|e| Error::PubKeyCtxError(e, Ctx::name_str()))?;
                        term.reduce0(Terminal::PkK(ret))?
                    },
                    Tk::Bytes65(pk) => {
                        let ret = Ctx::Key::from_slice(pk)
                            .map_err(|e| Error::PubKeyCtxError(e, Ctx::name_str()))?;
                        term.reduce0(Terminal::PkK(ret))?
                    },
                    // Note this does not collide with hash32 because they always followed by equal
                    // and would be parsed in different branch. If we get a naked Bytes32, it must be
                    // a x-only key
                    // In miniscript spec, bytes32 only occurs at three places.
                    // - during parsing XOnly keys in Pk fragment
                    // - during parsing XOnly keys in MultiA fragment
                    // - checking for 32 bytes hashlocks (sha256/hash256)
                    // The second case(MultiA) is disambiguated using NumEqual which is not used anywhere in miniscript
                    // The third case can only occur hashlocks is disambiguated because hashlocks start from equal, and
                    // it is impossible for any K type fragment to be followed by EQUAL in miniscript spec. Thus, EQUAL
                    // after bytes32 means bytes32 is in a hashlock
                    // Finally for the first case, K being parsed as a solo expression is a Pk type
                    Tk::Bytes32(pk) => {
                        let ret = Ctx::Key::from_slice(pk).map_err(|e| Error::PubKeyCtxError(e, Ctx::name_str()))?;
                        term.reduce0(Terminal::PkK(ret))?
                    },
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
                            Tk::Hash20(hash) => match_token!(
                                tokens,
                                Tk::Hash160 => match_token!(
                                    tokens,
                                    Tk::Dup => {
                                        term.reduce0(Terminal::RawPkH(
                                            hash160::Hash::from_slice(hash).expect("valid size")
                                        ))?
                                    },
                                    Tk::Verify, Tk::Equal, Tk::Num(32), Tk::Size => {
                                        non_term.push(NonTerm::Verify);
                                        term.reduce0(Terminal::Hash160(
                                            hash160::Hash::from_slice(hash).expect("valid size")
                                        ))?
                                    },
                                ),
                                Tk::Ripemd160, Tk::Verify, Tk::Equal, Tk::Num(32), Tk::Size => {
                                    non_term.push(NonTerm::Verify);
                                    term.reduce0(Terminal::Ripemd160(
                                        ripemd160::Hash::from_slice(hash).expect("valid size")
                                    ))?
                                },
                            ),
                            // Tk::Hash20(hash),
                            Tk::Bytes32(hash) => match_token!(
                                tokens,
                                Tk::Sha256, Tk::Verify, Tk::Equal, Tk::Num(32), Tk::Size => {
                                    non_term.push(NonTerm::Verify);
                                    term.reduce0(Terminal::Sha256(
                                        sha256::Hash::from_slice(hash).expect("valid size")
                                    ))?
                                },
                                Tk::Hash256, Tk::Verify, Tk::Equal, Tk::Num(32), Tk::Size => {
                                    non_term.push(NonTerm::Verify);
                                    term.reduce0(Terminal::Hash256(
                                        hash256::Hash::from_slice(hash).expect("valid size")
                                    ))?
                                },
                            ),
                            Tk::Num(k) => {
                                non_term.push(NonTerm::Verify);
                                non_term.push(NonTerm::ThreshW {
                                    k: k as usize,
                                    n: 0
                                });
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
                        => term.reduce0(Terminal::Older(Sequence::from_consensus(n)))?,
                    Tk::CheckLockTimeVerify, Tk::Num(n)
                        => term.reduce0(Terminal::After(LockTime::from_consensus(n).into()))?,
                    // hashlocks
                    Tk::Equal => match_token!(
                        tokens,
                        Tk::Bytes32(hash) => match_token!(
                            tokens,
                            Tk::Sha256,
                            Tk::Verify,
                            Tk::Equal,
                            Tk::Num(32),
                            Tk::Size => term.reduce0(Terminal::Sha256(
                                sha256::Hash::from_slice(hash).expect("valid size")
                            ))?,
                            Tk::Hash256,
                            Tk::Verify,
                            Tk::Equal,
                            Tk::Num(32),
                            Tk::Size => term.reduce0(Terminal::Hash256(
                                hash256::Hash::from_slice(hash).expect("valid size")
                            ))?,
                        ),
                        Tk::Hash20(hash) => match_token!(
                            tokens,
                            Tk::Ripemd160,
                            Tk::Verify,
                            Tk::Equal,
                            Tk::Num(32),
                            Tk::Size => term.reduce0(Terminal::Ripemd160(
                                ripemd160::Hash::from_slice(hash).expect("valid size")
                            ))?,
                            Tk::Hash160,
                            Tk::Verify,
                            Tk::Equal,
                            Tk::Num(32),
                            Tk::Size => term.reduce0(Terminal::Hash160(
                                hash160::Hash::from_slice(hash).expect("valid size")
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
                    // most other fragments
                    Tk::Num(0) => term.reduce0(Terminal::False)?,
                    Tk::Num(1) => term.reduce0(Terminal::True)?,
                    Tk::EndIf => {
                        non_term.push(NonTerm::EndIf);
                        non_term.push(NonTerm::MaybeAndV);
                        non_term.push(NonTerm::Expression);
                    },
                    // boolean conjunctions and disjunctions
                    Tk::BoolAnd => {
                        non_term.push(NonTerm::AndB);
                        non_term.push(NonTerm::Expression);
                        non_term.push(NonTerm::WExpression);
                    },
                    Tk::BoolOr => {
                        non_term.push(NonTerm::OrB);
                        non_term.push(NonTerm::Expression);
                        non_term.push(NonTerm::WExpression);
                    },
                    // CHECKMULTISIG based multisig
                    Tk::CheckMultiSig, Tk::Num(n) => {
                        if n as usize > MAX_PUBKEYS_PER_MULTISIG {
                            return Err(Error::CmsTooManyKeys(n));
                        }
                        let mut keys = Vec::with_capacity(n as usize);
                        for _ in 0..n {
                            match_token!(
                                tokens,
                                Tk::Bytes33(pk) => keys.push(<Ctx::Key>::from_slice(pk)
                                    .map_err(|e| Error::PubKeyCtxError(e, Ctx::name_str()))?),
                                Tk::Bytes65(pk) => keys.push(<Ctx::Key>::from_slice(pk)
                                    .map_err(|e| Error::PubKeyCtxError(e, Ctx::name_str()))?),
                            );
                        }
                        let k = match_token!(
                            tokens,
                            Tk::Num(k) => k,
                        );
                        keys.reverse();
                        term.reduce0(Terminal::Multi(k as usize, keys))?;
                    },
                    // MultiA
                    Tk::NumEqual, Tk::Num(k) => {
                        // Check size before allocating keys
                        if k > MAX_BLOCK_WEIGHT/32 {
                            return Err(Error::MultiATooManyKeys(MAX_BLOCK_WEIGHT/32))
                        }
                        let mut keys = Vec::with_capacity(k as usize); // atleast k capacity
                        while tokens.peek() == Some(&Tk::CheckSigAdd) {
                            match_token!(
                                tokens,
                                Tk::CheckSigAdd, Tk::Bytes32(pk) => keys.push(<Ctx::Key>::from_slice(pk)
                                    .map_err(|e| Error::PubKeyCtxError(e, Ctx::name_str()))?),
                            );
                        }
                        // Last key must be with a CheckSig
                        match_token!(
                            tokens,
                            Tk::CheckSig, Tk::Bytes32(pk) => keys.push(<Ctx::Key>::from_slice(pk)
                                .map_err(|e| Error::PubKeyCtxError(e, Ctx::name_str()))?),
                        );
                        keys.reverse();
                        term.reduce0(Terminal::MultiA(k as usize, keys))?;
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
            Some(NonTerm::Swap) => {
                // Handle `SWAP` prefixing
                match_token!(
                    tokens,
                    Tk::Swap => {},
                );
                term.reduce1(Terminal::Swap)?;
                // Swap must be always be terminating a NonTerm as it cannot be in and_v
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
                    ty,
                    ext,
                    phantom: PhantomData,
                });
            }
            Some(NonTerm::ThreshW { n, k }) => {
                match_token!(
                    tokens,
                    Tk::Add => {
                        non_term.push(NonTerm::ThreshW { n: n + 1, k });
                        non_term.push(NonTerm::WExpression);
                    },
                    x => {
                        tokens.un_next(x);
                        non_term.push(NonTerm::ThreshE { n: n + 1, k });
                        non_term.push(NonTerm::Expression);
                    },
                );
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
            Some(NonTerm::WExpression) => {
                // W expression must be either from swap or Fromaltstack
                match_token!(tokens,
                    Tk::FromAltStack => { non_term.push(NonTerm::Alt);},
                    tok => { tokens.un_next(tok); non_term.push(NonTerm::Swap);},);
                non_term.push(NonTerm::MaybeAndV);
                non_term.push(NonTerm::Expression);
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
        None
        | Some(&Tk::If)
        | Some(&Tk::NotIf)
        | Some(&Tk::Else)
        | Some(&Tk::ToAltStack)
        | Some(&Tk::Swap) => false,
        _ => true,
    }
}
