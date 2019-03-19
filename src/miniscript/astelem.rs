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

use super::Error;
use policy::AbstractPolicy;
use miniscript::lex::{Token, TokenIter};
use expression;
use errstr;

/// Trait describing an AST element which is instantiated with a
/// `PublicKey`. Such elements are in bijection with fragments
/// of Bitcoin Script; this trait describes various conversions that are
/// needed by the Script parser.
pub trait AstElem: fmt::Display {
    /// Attempt cast into E
    fn into_e(self: Box<Self>) -> Rc<E<PublicKey>> { panic!("invalid conversion to E") }
    /// Attempt cast into Q
    fn into_q(self: Box<Self>) -> Rc<Q<PublicKey>> { panic!("invalid conversion to Q") }
    /// Attempt cast into W
    fn into_w(self: Box<Self>) -> Rc<W<PublicKey>> { panic!("invalid conversion to W") }
    /// Attempt cast into F
    fn into_f(self: Box<Self>) -> Rc<F<PublicKey>> { panic!("invalid conversion to F") }
    /// Attempt cast into V
    fn into_v(self: Box<Self>) -> Rc<V<PublicKey>> { panic!("invalid conversion to V") }
    /// Attempt cast into T
    fn into_t(self: Box<Self>) -> Rc<T<PublicKey>> { panic!("invalid conversion to T") }

    /// Is the element castable to E?
    fn is_e(&self) -> bool { false }
    /// Is the element castable to Q?
    fn is_q(&self) -> bool { false }
    /// Is the element castable to W?
    fn is_w(&self) -> bool { false }
    /// Is the element castable to F?
    fn is_f(&self) -> bool { false }
    /// Is the element castable to V?
    fn is_v(&self) -> bool { false }
    /// Is the element castable to T?
    fn is_t(&self) -> bool { false }

    /// Serialize the element as a fragment of Bitcoin Script. The inverse function, from Script to
    /// an AST element, is implemented in the `parse` module.
    fn serialize(&self, builder: script::Builder) -> script::Builder;
}

/// Expression that may be satisfied or dissatisfied; both cases must
/// be non-malleable.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum E<P> {
    // base cases
    /// `<pk> CHECKSIG`
    CheckSig(P),
    /// `<k> <pk...> <len(pk)> CHECKMULTISIG`
    CheckMultiSig(usize, Vec<P>),
    /// `DUP IF <n> CSV DROP ENDIF`
    Time(u32),
    // thresholds
    /// `<E> <W> ADD ... <W> ADD <k> EQUAL`
    Threshold(usize, Rc<E<P>>, Vec<Rc<W<P>>>),
    // and
    /// `<E> <W> BOOLAND`
    ParallelAnd(Rc<E<P>>, Rc<W<P>>),
    /// `<E> NOTIF 0 ELSE <F> ENDIF`
    CascadeAnd(Rc<E<P>>, Rc<F<P>>),
    // or
    /// `<E> <W> BOOLOR`
    ParallelOr(Rc<E<P>>, Rc<W<P>>),
    /// `<E> IFDUP NOTIF <E> ENDIF`
    CascadeOr(Rc<E<P>>, Rc<E<P>>),
    /// `IF <E> ELSE <F> ENDIF`
    SwitchOrLeft(Rc<E<P>>, Rc<F<P>>),
    /// `NOTIF <E> ELSE <F> ENDIF`
    SwitchOrRight(Rc<E<P>>, Rc<F<P>>),
    // casts
    /// `NOTIF <F> ELSE 0 ENDIF`
    Likely(Rc<F<P>>),
    /// `IF <F> ELSE 0 ENDIF`
    Unlikely(Rc<F<P>>),
}

/// Expression that must be satisfied and must leave a public key on the stack
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Q<P> {
    /// <pk>
    Pubkey(P),
    /// <V> <Q>
    And(Rc<V<P>>, Rc<Q<P>>),
    /// IF <Q> ELSE <Q> ENDIF
    Or(Rc<Q<P>>, Rc<Q<P>>),
}

/// Wrapped expression, used as helper for the parallel operations above
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum W<P> {
    /// `SWAP <pk> CHECKSIG`
    CheckSig(P),
    /// `SWAP SIZE 0NOTEQUAL IF SIZE 32 EQUALVERIFY SHA256 <hash> EQUALVERIFY 1 ENDIF`
    HashEqual(sha256::Hash),
    /// `SWAP DUP IF <n> OP_CSV OP_DROP ENDIF`
    Time(u32),
    /// `TOALTSTACK <E> FROMALTSTACK`
    CastE(Rc<E<P>>),
}

/// Expression that must succeed and will leave a 1 on the stack after consuming its inputs
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum F<P> {
    /// `<pk> CHECKSIGVERIFY 1`
    CheckSig(P),
    /// `<k> <pk...> <len(pk)> CHECKMULTISIGVERIFY 1`
    CheckMultiSig(usize, Vec<P>),
    /// `<n> CSV 0NOTEQUAL`
    Time(u32),
    /// `SIZE 32 EQUALVERIFY SHA256 <hash> EQUALVERIFY 1`
    HashEqual(sha256::Hash),
    /// `<E> <W> ADD ... <W> ADD <k> EQUALVERIFY 1`
    Threshold(usize, Rc<E<P>>, Vec<Rc<W<P>>>),
    /// `<V> <F>`
    And(Rc<V<P>>, Rc<F<P>>),
    /// `<E> NOTIF <V> ENDIF 1`
    CascadeOr(Rc<E<P>>, Rc<V<P>>),
    /// `IF <F> ELSE <F> ENDIF`
    SwitchOr(Rc<F<P>>, Rc<F<P>>),
    /// `IF <V> ELSE <V> ENDIF 1`
    SwitchOrV(Rc<V<P>>, Rc<V<P>>),
    /// `IF <Q> ELSE <Q> ENDIF CHECKSIGVERIFY 1`
    DelayedOr(Rc<Q<P>>, Rc<Q<P>>),
}

/// Expression that must succeed and will leave nothing on the stack after consuming its inputs
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum V<P> {
    /// `<pk> CHECKSIGVERIFY`
    CheckSig(P),
    /// `<k> <pk...> <len(pk)> CHECKMULTISIGVERIFY`
    CheckMultiSig(usize, Vec<P>),
    /// `<n> CSV DROP`
    Time(u32),
    /// `SIZE 32 EQUALVERIFY SHA256 <hash> EQUALVERIFY`
    HashEqual(sha256::Hash),
    /// `<E> <W> ADD ... <W> ADD <k> EQUALVERIFY`
    Threshold(usize, Rc<E<P>>, Vec<Rc<W<P>>>),
    /// `<V> <V>`
    And(Rc<V<P>>, Rc<V<P>>),
    /// `<E> NOTIF <V> ENDIF`
    CascadeOr(Rc<E<P>>, Rc<V<P>>),
    /// `IF <V> ELSE <V> ENDIF`
    SwitchOr(Rc<V<P>>, Rc<V<P>>),
    /// `IF <T> ELSE <T> ENDIF VERIFY`
    SwitchOrT(Rc<T<P>>, Rc<T<P>>),
    /// `IF <Q> ELSE <Q> ENDIF CHECKSIGVERIFY`
    DelayedOr(Rc<Q<P>>, Rc<Q<P>>),
}

/// "Top" expression, which might succeed or not, or fail or not. Occurs only at the top of a
/// script, such that its failure will fail the entire thing even if it returns a 0.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum T<P> {
    /// `<n> CSV`
    Time(u32),
    /// `SIZE 32 EQUALVERIFY SHA256 <hash> EQUAL`
    HashEqual(sha256::Hash),
    /// `<V> <T>`
    And(Rc<V<P>>, Rc<T<P>>),
    /// `<E> <W> BOOLOR`
    ParallelOr(Rc<E<P>>, Rc<W<P>>),
    /// `<E> IFDUP NOTIF <T> ENDIF`
    CascadeOr(Rc<E<P>>, Rc<T<P>>),
    /// `<E> NOTIF <V> ENDIF 1`
    CascadeOrV(Rc<E<P>>, Rc<V<P>>),
    /// `IF <T> ELSE <T> ENDIF`
    SwitchOr(Rc<T<P>>, Rc<T<P>>),
    /// `IF <V> ELSE <V> ENDIF 1`
    SwitchOrV(Rc<V<P>>, Rc<V<P>>),
    /// `IF <Q> ELSE <Q> ENDIF CHECKSIG`
    DelayedOr(Rc<Q<P>>, Rc<Q<P>>),
    /// `<E>`
    CastE(E<P>),
}

// *** Conversions
impl<P> E<P> {
    pub fn translate<Func, Q, Error>(&self, translatefn: &Func) -> Result<E<Q>, Error>
        where Func: Fn(&P) -> Result<Q, Error>
    {
        match *self {
            E::CheckSig(ref p) => Ok(E::CheckSig(translatefn(p)?)),
            E::CheckMultiSig(k, ref pks) => {
                let mut ret = Vec::with_capacity(pks.len());
                for pk in pks {
                    ret.push(translatefn(pk)?);
                }
                Ok(E::CheckMultiSig(k, ret))
            }
            E::Time(n) => Ok(E::Time(n)),
            E::Threshold(k, ref sube, ref subw) => {
                let mut ret = Vec::with_capacity(subw.len());
                for sub in subw {
                    ret.push(Rc::new(sub.translate(translatefn)?));
                }
                Ok(E::Threshold(k, Rc::new(sube.translate(translatefn)?), ret))
            }
            E::ParallelAnd(ref left, ref right) => Ok(E::ParallelAnd(
                Rc::new(left.translate(translatefn)?),
                Rc::new(right.translate(translatefn)?),
            )),
            E::CascadeAnd(ref left, ref right) => Ok(E::CascadeAnd(
                Rc::new(left.translate(translatefn)?),
                Rc::new(right.translate(translatefn)?),
            )),
            E::ParallelOr(ref left, ref right) => Ok(E::ParallelOr(
                Rc::new(left.translate(translatefn)?),
                Rc::new(right.translate(translatefn)?),
            )),
            E::CascadeOr(ref left, ref right) => Ok(E::CascadeOr(
                Rc::new(left.translate(translatefn)?),
                Rc::new(right.translate(translatefn)?),
            )),
            E::SwitchOrLeft(ref left, ref right) => Ok(E::SwitchOrLeft(
                Rc::new(left.translate(translatefn)?),
                Rc::new(right.translate(translatefn)?),
            )),
            E::SwitchOrRight(ref left, ref right) => Ok(E::SwitchOrRight(
                Rc::new(left.translate(translatefn)?),
                Rc::new(right.translate(translatefn)?),
            )),
            E::Likely(ref sub) => Ok(E::Likely(Rc::new(sub.translate(translatefn)?))),
            E::Unlikely(ref sub) => Ok(E::Unlikely(Rc::new(sub.translate(translatefn)?))),
        }
    }
}

impl<P: Clone> E<P> {
    /// Abstract the script into an "abstract policy" which can be filtered and analyzed
    pub fn abstract_policy(&self) -> AbstractPolicy<P> {
        match *self {
            E::CheckSig(ref p) => AbstractPolicy::Key(p.clone()),
            E::CheckMultiSig(k, ref keys) => {
                AbstractPolicy::Threshold(
                    k,
                    keys
                        .iter()
                        .map(|key| AbstractPolicy::Key(key.clone()))
                        .collect(),
                )
            },
            E::Time(k) => AbstractPolicy::Time(k),
            E::Threshold(k, ref sube, ref subs) => AbstractPolicy::Threshold(
                k,
                Some(sube)
                    .iter()
                    .map(|sub| sub.abstract_policy())
                    .chain(subs
                        .iter()
                        .map(|sub| sub.abstract_policy())
                    )
                    .collect(),
            ),
            E::ParallelAnd(ref left, ref right) => AbstractPolicy::And(
                Box::new(left.abstract_policy()),
                Box::new(right.abstract_policy()),
            ),
            E::CascadeAnd(ref left, ref right) => AbstractPolicy::And(
                Box::new(left.abstract_policy()),
                Box::new(right.abstract_policy()),
            ),
            E::ParallelOr(ref left, ref right) => AbstractPolicy::Or(
                Box::new(left.abstract_policy()),
                Box::new(right.abstract_policy()),
            ),
            E::CascadeOr(ref left, ref right) => AbstractPolicy::Or(
                Box::new(left.abstract_policy()),
                Box::new(right.abstract_policy()),
            ),
            E::SwitchOrLeft(ref left, ref right) => AbstractPolicy::Or(
                Box::new(left.abstract_policy()),
                Box::new(right.abstract_policy()),
            ),
            E::SwitchOrRight(ref left, ref right) => AbstractPolicy::Or(
                Box::new(left.abstract_policy()),
                Box::new(right.abstract_policy()),
            ),
            E::Likely(ref sub) | E::Unlikely(ref sub) => sub.abstract_policy(),
        }
    }
}

impl<P> Q<P> {
    pub fn translate<Func, PP, Error>(&self, translatefn: &Func) -> Result<Q<PP>, Error>
        where Func: Fn(&P) -> Result<PP, Error>
    {
        match *self {
            Q::Pubkey(ref p) => Ok(Q::Pubkey(translatefn(p)?)),
            Q::And(ref left, ref right) => Ok(Q::And(
                Rc::new(left.translate(translatefn)?),
                Rc::new(right.translate(translatefn)?),
            )),
            Q::Or(ref left, ref right) => Ok(Q::Or(
                Rc::new(left.translate(translatefn)?),
                Rc::new(right.translate(translatefn)?),
            )),
        }
    }
}

impl<P: Clone> Q<P> {
    /// Abstract the script into an "abstract policy" which can be filtered and analyzed
    pub fn abstract_policy(&self) -> AbstractPolicy<P> {
        match *self {
            Q::Pubkey(ref p) => AbstractPolicy::Key(p.clone()),
            Q::And(ref left, ref right) => AbstractPolicy::And(
                Box::new(left.abstract_policy()),
                Box::new(right.abstract_policy()),
            ),
            Q::Or(ref left, ref right) => AbstractPolicy::Or(
                Box::new(left.abstract_policy()),
                Box::new(right.abstract_policy()),
            ),
        }
    }
}

impl<P> W<P> {
    pub fn translate<Func, Q, Error>(&self, translatefn: &Func) -> Result<W<Q>, Error>
        where Func: Fn(&P) -> Result<Q, Error>
    {
        match *self {
            W::CheckSig(ref p) => Ok(W::CheckSig(translatefn(p)?)),
            W::Time(n) => Ok(W::Time(n)),
            W::HashEqual(ref h) => Ok(W::HashEqual(*h)),
            W::CastE(ref e) => Ok(W::CastE(Rc::new(e.translate(translatefn)?))),
        }
    }
}

impl<P: Clone> W<P> {
    /// Abstract the script into an "abstract policy" which can be filtered and analyzed
    pub fn abstract_policy(&self) -> AbstractPolicy<P> {
        match *self {
            W::CheckSig(ref p) => AbstractPolicy::Key(p.clone()),
            W::HashEqual(hash) => AbstractPolicy::Hash(hash),
            W::Time(k) => AbstractPolicy::Time(k),
            W::CastE(ref e) => e.abstract_policy(),
        }
    }
}

impl<P> F<P> {
    pub fn translate<Func, Q, Error>(&self, translatefn: &Func) -> Result<F<Q>, Error>
        where Func: Fn(&P) -> Result<Q, Error>
    {
        match *self {
            F::CheckSig(ref p) => Ok(F::CheckSig(translatefn(p)?)),
            F::CheckMultiSig(k, ref pks) => {
                let mut ret = Vec::with_capacity(pks.len());
                for pk in pks {
                    ret.push(translatefn(pk)?);
                }
                Ok(F::CheckMultiSig(k, ret))
            }
            F::Time(n) => Ok(F::Time(n)),
            F::HashEqual(ref h) => Ok(F::HashEqual(*h)),
            F::Threshold(k, ref sube, ref subw) => {
                let mut ret = Vec::with_capacity(subw.len());
                for sub in subw {
                    ret.push(Rc::new(sub.translate(translatefn)?));
                }
                Ok(F::Threshold(k, Rc::new(sube.translate(translatefn)?), ret))
            }
            F::And(ref left, ref right) => Ok(F::And(
                Rc::new(left.translate(translatefn)?),
                Rc::new(right.translate(translatefn)?),
            )),
            F::CascadeOr(ref left, ref right) => Ok(F::CascadeOr(
                Rc::new(left.translate(translatefn)?),
                Rc::new(right.translate(translatefn)?),
            )),
            F::SwitchOr(ref left, ref right) => Ok(F::SwitchOr(
                Rc::new(left.translate(translatefn)?),
                Rc::new(right.translate(translatefn)?),
            )),
            F::SwitchOrV(ref left, ref right) => Ok(F::SwitchOrV(
                Rc::new(left.translate(translatefn)?),
                Rc::new(right.translate(translatefn)?),
            )),
            F::DelayedOr(ref left, ref right) => Ok(F::DelayedOr(
                Rc::new(left.translate(translatefn)?),
                Rc::new(right.translate(translatefn)?),
            )),
        }
    }
}

impl<P: Clone> F<P> {
    /// Abstract the script into an "abstract policy" which can be filtered and analyzed
    pub fn abstract_policy(&self) -> AbstractPolicy<P> {
        match *self {
            F::CheckSig(ref p) => AbstractPolicy::Key(p.clone()),
            F::CheckMultiSig(k, ref keys) => {
                AbstractPolicy::Threshold(
                    k,
                    keys
                        .iter()
                        .map(|key| AbstractPolicy::Key(key.clone()))
                        .collect(),
                )
            },
            F::Time(k) => AbstractPolicy::Time(k),
            F::HashEqual(hash) => AbstractPolicy::Hash(hash),
            F::Threshold(k, ref sube, ref subs) => AbstractPolicy::Threshold(
                k,
                Some(sube)
                    .iter()
                    .map(|sub| sub.abstract_policy())
                    .chain(subs
                        .iter()
                        .map(|sub| sub.abstract_policy())
                    )
                    .collect(),
            ),
            F::And(ref left, ref right) => AbstractPolicy::And(
                Box::new(left.abstract_policy()),
                Box::new(right.abstract_policy()),
            ),
            F::CascadeOr(ref left, ref right) => AbstractPolicy::Or(
                Box::new(left.abstract_policy()),
                Box::new(right.abstract_policy()),
            ),
            F::SwitchOr(ref left, ref right) => AbstractPolicy::Or(
                Box::new(left.abstract_policy()),
                Box::new(right.abstract_policy()),
            ),
            F::SwitchOrV(ref left, ref right) => AbstractPolicy::Or(
                Box::new(left.abstract_policy()),
                Box::new(right.abstract_policy()),
            ),
            F::DelayedOr(ref left, ref right) => AbstractPolicy::Or(
                Box::new(left.abstract_policy()),
                Box::new(right.abstract_policy()),
            ),
        }
    }
}

impl<P> V<P> {
    pub fn translate<Func, Q, Error>(&self, translatefn: &Func) -> Result<V<Q>, Error>
        where Func: Fn(&P) -> Result<Q, Error>
    {
        match *self {
            V::CheckSig(ref p) => Ok(V::CheckSig(translatefn(p)?)),
            V::CheckMultiSig(k, ref pks) => {
                let mut ret = Vec::with_capacity(pks.len());
                for pk in pks {
                    ret.push(translatefn(pk)?);
                }
                Ok(V::CheckMultiSig(k, ret))
            }
            V::Time(n) => Ok(V::Time(n)),
            V::HashEqual(ref h) => Ok(V::HashEqual(*h)),
            V::Threshold(k, ref sube, ref subw) => {
                let mut ret = Vec::with_capacity(subw.len());
                for sub in subw {
                    ret.push(Rc::new(sub.translate(translatefn)?));
                }
                Ok(V::Threshold(k, Rc::new(sube.translate(translatefn)?), ret))
            }
            V::And(ref left, ref right) => Ok(V::And(
                Rc::new(left.translate(translatefn)?),
                Rc::new(right.translate(translatefn)?),
            )),
            V::CascadeOr(ref left, ref right) => Ok(V::CascadeOr(
                Rc::new(left.translate(translatefn)?),
                Rc::new(right.translate(translatefn)?),
            )),
            V::SwitchOr(ref left, ref right) => Ok(V::SwitchOr(
                Rc::new(left.translate(translatefn)?),
                Rc::new(right.translate(translatefn)?),
            )),
            V::SwitchOrT(ref left, ref right) => Ok(V::SwitchOrT(
                Rc::new(left.translate(translatefn)?),
                Rc::new(right.translate(translatefn)?),
            )),
            V::DelayedOr(ref left, ref right) => Ok(V::DelayedOr(
                Rc::new(left.translate(translatefn)?),
                Rc::new(right.translate(translatefn)?),
            )),
        }
    }
}

impl<P: Clone> V<P> {
    /// Abstract the script into an "abstract policy" which can be filtered and analyzed
    pub fn abstract_policy(&self) -> AbstractPolicy<P> {
        match *self {
            V::CheckSig(ref p) => AbstractPolicy::Key(p.clone()),
            V::CheckMultiSig(k, ref keys) => {
                AbstractPolicy::Threshold(
                    k,
                    keys
                        .iter()
                        .map(|key| AbstractPolicy::Key(key.clone()))
                        .collect(),
                )
            },
            V::Time(k) => AbstractPolicy::Time(k),
            V::HashEqual(hash) => AbstractPolicy::Hash(hash),
            V::Threshold(k, ref sube, ref subs) => AbstractPolicy::Threshold(
                k,
                Some(sube)
                    .iter()
                    .map(|sub| sub.abstract_policy())
                    .chain(subs
                        .iter()
                        .map(|sub| sub.abstract_policy())
                    )
                    .collect(),
            ),
            V::And(ref left, ref right) => AbstractPolicy::And(
                Box::new(left.abstract_policy()),
                Box::new(right.abstract_policy()),
            ),
            V::CascadeOr(ref left, ref right) => AbstractPolicy::Or(
                Box::new(left.abstract_policy()),
                Box::new(right.abstract_policy()),
            ),
            V::SwitchOr(ref left, ref right) => AbstractPolicy::Or(
                Box::new(left.abstract_policy()),
                Box::new(right.abstract_policy()),
            ),
            V::SwitchOrT(ref left, ref right) => AbstractPolicy::Or(
                Box::new(left.abstract_policy()),
                Box::new(right.abstract_policy()),
            ),
            V::DelayedOr(ref left, ref right) => AbstractPolicy::Or(
                Box::new(left.abstract_policy()),
                Box::new(right.abstract_policy()),
            ),
        }
    }
}

impl<P> T<P> {
    pub fn translate<Func, Q, Error>(&self, translatefn: &Func) -> Result<T<Q>, Error>
        where Func: Fn(&P) -> Result<Q, Error>
    {
        match *self {
            T::Time(n) => Ok(T::Time(n)),
            T::HashEqual(ref h) => Ok(T::HashEqual(*h)),
            T::And(ref left, ref right) => Ok(T::And(
                Rc::new(left.translate(translatefn)?),
                Rc::new(right.translate(translatefn)?),
            )),
            T::ParallelOr(ref left, ref right) => Ok(T::ParallelOr(
                Rc::new(left.translate(translatefn)?),
                Rc::new(right.translate(translatefn)?),
            )),
            T::CascadeOr(ref left, ref right) => Ok(T::CascadeOr(
                Rc::new(left.translate(translatefn)?),
                Rc::new(right.translate(translatefn)?),
            )),
            T::CascadeOrV(ref left, ref right) => Ok(T::CascadeOrV(
                Rc::new(left.translate(translatefn)?),
                Rc::new(right.translate(translatefn)?),
            )),
            T::SwitchOr(ref left, ref right) => Ok(T::SwitchOr(
                Rc::new(left.translate(translatefn)?),
                Rc::new(right.translate(translatefn)?),
            )),
            T::SwitchOrV(ref left, ref right) => Ok(T::SwitchOrV(
                Rc::new(left.translate(translatefn)?),
                Rc::new(right.translate(translatefn)?),
            )),
            T::DelayedOr(ref left, ref right) => Ok(T::DelayedOr(
                Rc::new(left.translate(translatefn)?),
                Rc::new(right.translate(translatefn)?),
            )),
            T::CastE(ref e) => e.translate(translatefn).map(T::CastE),
        }
    }
}

impl<P: Clone> T<P> {
    /// Abstract the script into an "abstract policy" which can be filtered and analyzed
    pub fn abstract_policy(&self) -> AbstractPolicy<P> {
        match *self {
            T::Time(k) => AbstractPolicy::Time(k),
            T::HashEqual(hash) => AbstractPolicy::Hash(hash),
            T::And(ref left, ref right) => AbstractPolicy::And(
                Box::new(left.abstract_policy()),
                Box::new(right.abstract_policy()),
            ),
            T::ParallelOr(ref left, ref right) => AbstractPolicy::Or(
                Box::new(left.abstract_policy()),
                Box::new(right.abstract_policy()),
            ),
            T::CascadeOr(ref left, ref right) => AbstractPolicy::Or(
                Box::new(left.abstract_policy()),
                Box::new(right.abstract_policy()),
            ),
            T::CascadeOrV(ref left, ref right) => AbstractPolicy::Or(
                Box::new(left.abstract_policy()),
                Box::new(right.abstract_policy()),
            ),
            T::SwitchOr(ref left, ref right) => AbstractPolicy::Or(
                Box::new(left.abstract_policy()),
                Box::new(right.abstract_policy()),
            ),
            T::SwitchOrV(ref left, ref right) => AbstractPolicy::Or(
                Box::new(left.abstract_policy()),
                Box::new(right.abstract_policy()),
            ),
            T::DelayedOr(ref left, ref right) => AbstractPolicy::Or(
                Box::new(left.abstract_policy()),
                Box::new(right.abstract_policy()),
            ),
            T::CastE(ref e) => e.abstract_policy(),
        }
    }
}

// *** Deserialization from expression language
impl<P: str::FromStr> expression::FromTree for Rc<E<P>>
    where <P as str::FromStr>::Err: ToString,
{
    fn from_tree(top: &expression::Tree) -> Result<Rc<E<P>>, Error> {
        Ok(Rc::new(match (top.name, top.args.len()) {
            ("pk", 1) => expression::terminal(
                &top.args[0],
                |x| P::from_str(x).map(E::CheckSig)
            ),
            ("multi", n) => {
                let k = expression::terminal(&top.args[0], expression::parse_num)? as usize;
                if n == 0 || k > n - 1 {
                    return Err(errstr("higher threshold than there were keys in multi"));
                }

                let pks: Result<Vec<P>, _> = top.args[1..].iter().map(|sub|
                    expression::terminal(sub, P::from_str)
                ).collect();

                pks.map(|pks| E::CheckMultiSig(k, pks))
            }
            ("time", 1) => expression::terminal(
                &top.args[0],
                |x| expression::parse_num(x).map(E::Time)
            ),
            ("thres", n) => {
                let k = expression::terminal(&top.args[0], expression::parse_num)? as usize;
                if n == 0 || k > n - 1 {
                    return Err(errstr("higher threshold than there were keys in multi"));
                }
                if n == 1 {
                    return Err(errstr("empty multisigs not allowed in descriptors"));
                }

                let e: Rc<E<P>> = expression::FromTree::from_tree(&top.args[1])?;
                let w: Result<Vec<Rc<W<P>>>, _> = top.args[2..].iter().map(|sub|
                    expression::FromTree::from_tree(sub)
                ).collect();

                w.map(|ws| E::Threshold(k, e, ws))
            }
            ("and_p", 2) => expression::binary(top, E::ParallelAnd),
            ("and_c", 2) => expression::binary(top, E::CascadeAnd),
            ("or_p", 2) => expression::binary(top, E::ParallelOr),
            ("or_c", 2) => expression::binary(top, E::CascadeOr),
            ("or_s", 2) => expression::binary(top, E::SwitchOrLeft),
            ("or_a", 2) => expression::binary(top, E::SwitchOrRight),
            ("lift_l", 1) => expression::unary(top, E::Likely),
            ("lift_u", 1) => expression::unary(top, E::Unlikely),
            _ => Err(Error::Unexpected(format!("{}({} args) while parsing E", top.name, top.args.len()))),
        }?))
    }
}

impl<P: str::FromStr> expression::FromTree for Rc<Q<P>>
    where <P as str::FromStr>::Err: ToString,
{
    fn from_tree(top: &expression::Tree) -> Result<Rc<Q<P>>, Error> {
        Ok(Rc::new(match (top.name, top.args.len()) {
            ("pk", 1) => expression::terminal(
                &top.args[0],
                |x| P::from_str(x).map(Q::Pubkey)
            ),
            ("and_p", 2) => expression::binary(top, Q::And),
            ("or_s", 2) => expression::binary(top, Q::Or),
            _ => Err(Error::Unexpected(format!("{}({} args) while parsing Q", top.name, top.args.len()))),
        }?))
    }
}

impl<P: str::FromStr> expression::FromTree for Rc<W<P>>
    where <P as str::FromStr>::Err: ToString,
{
    fn from_tree(top: &expression::Tree) -> Result<Rc<W<P>>, Error> {
        Ok(Rc::new(match (top.name, top.args.len()) {
            ("pk", 1) => expression::terminal(
                &top.args[0],
                |x| P::from_str(x).map(W::CheckSig)
            ),
            ("time", 1) => expression::terminal(
                &top.args[0],
                |x| expression::parse_num(x).map(W::Time)
            ),
            ("hash", 1) => expression::terminal(
                &top.args[0],
                |x| sha256::Hash::from_hex(x).map(W::HashEqual)
            ),
            _ => {
                let e: Rc<E<P>> = expression::FromTree::from_tree(top)?;
                Ok(W::CastE(e))
            }
        }?))
    }
}

impl<P: str::FromStr> expression::FromTree for Rc<F<P>>
    where <P as str::FromStr>::Err: ToString,
{
    fn from_tree(top: &expression::Tree) -> Result<Rc<F<P>>, Error> {
        Ok(Rc::new(match (top.name, top.args.len()) {
            ("pk", 1) => expression::terminal(
                &top.args[0],
                |x| P::from_str(x).map(F::CheckSig)
            ),
            ("multi", n) => {
                let k = expression::terminal(&top.args[0], expression::parse_num)? as usize;
                if n == 0 || k > n - 1 {
                    return Err(errstr("higher threshold than there were keys in multi"));
                }

                let pks: Result<Vec<P>, _> = top.args[1..].iter().map(|sub|
                    expression::terminal(sub, P::from_str)
                ).collect();

                pks.map(|pks| F::CheckMultiSig(k, pks))
            }
            ("time", 1) => expression::terminal(
                &top.args[0],
                |x| expression::parse_num(x).map(F::Time)
            ),
            ("hash", 1) => expression::terminal(
                &top.args[0],
                |x| sha256::Hash::from_hex(x).map(F::HashEqual)
            ),
            ("thres", n) => {
                let k = expression::terminal(&top.args[0], expression::parse_num)? as usize;
                if n == 0 || k > n - 1 {
                    return Err(errstr("higher threshold than there were keys in multi"));
                }
                if n == 1 {
                    return Err(errstr("empty multisigs not allowed in descriptors"));
                }

                let e: Rc<E<P>> = expression::FromTree::from_tree(&top.args[1])?;
                let w: Result<Vec<Rc<W<P>>>, _> = top.args[2..].iter().map(|sub|
                    expression::FromTree::from_tree(sub)
                ).collect();

                w.map(|ws| F::Threshold(k, e, ws))
            }
            ("and_p", 2) => expression::binary(top, F::And),
            ("or_v", 2) => expression::binary(top, F::CascadeOr),
            ("or_s", 2) => expression::binary(top, F::SwitchOr),
            ("or_a", 2) => expression::binary(top, F::SwitchOrV),
            ("or_d", 2) => expression::binary(top, F::DelayedOr),
            _ => Err(Error::Unexpected(format!("{}({} args) while parsing F", top.name, top.args.len()))),
        }?))
    }
}

impl<P: str::FromStr> expression::FromTree for Rc<V<P>>
    where <P as str::FromStr>::Err: ToString,
{
    fn from_tree(top: &expression::Tree) -> Result<Rc<V<P>>, Error> {
        Ok(Rc::new(match (top.name, top.args.len()) {
            ("pk", 1) => expression::terminal(
                &top.args[0],
                |x| P::from_str(x).map(V::CheckSig)
            ),
            ("multi", n) => {
                let k = expression::terminal(&top.args[0], expression::parse_num)? as usize;
                if n == 0 || k > n - 1 {
                    return Err(errstr("higher threshold than there were keys in multi"));
                }

                let pks: Result<Vec<P>, _> = top.args[1..].iter().map(|sub|
                    expression::terminal(sub, P::from_str)
                ).collect();

                pks.map(|pks| V::CheckMultiSig(k, pks))
            }
            ("time", 1) => expression::terminal(
                &top.args[0],
                |x| expression::parse_num(x).map(V::Time)
            ),
            ("hash", 1) => expression::terminal(
                &top.args[0],
                |x| sha256::Hash::from_hex(x).map(V::HashEqual)
            ),
            ("thres", n) => {
                let k = expression::terminal(&top.args[0], expression::parse_num)? as usize;
                if n == 0 || k > n - 1 {
                    return Err(errstr("higher threshold than there were keys in multi"));
                }
                if n == 1 {
                    return Err(errstr("empty multisigs not allowed in descriptors"));
                }

                let e: Rc<E<P>> = expression::FromTree::from_tree(&top.args[1])?;
                let w: Result<Vec<Rc<W<P>>>, _> = top.args[2..].iter().map(|sub|
                    expression::FromTree::from_tree(sub)
                ).collect();

                w.map(|ws| V::Threshold(k, e, ws))
            }
            ("and_p", 2) => expression::binary(top, V::And),
            ("or_v", 2) => expression::binary(top, V::CascadeOr),
            ("or_s", 2) => expression::binary(top, V::SwitchOr),
            ("or_a", 2) => expression::binary(top, V::SwitchOrT),
            ("or_d", 2) => expression::binary(top, V::DelayedOr),
            _ => Err(Error::Unexpected(format!("{}({} args) while parsing V", top.name, top.args.len()))),
        }?))
    }
}

impl<P: str::FromStr> expression::FromTree for Rc<T<P>>
    where <P as str::FromStr>::Err: ToString,
{
    fn from_tree(top: &expression::Tree) -> Result<Rc<T<P>>, Error> {
        Ok(Rc::new(match (top.name, top.args.len()) {
            ("time", 1) => expression::terminal(
                &top.args[0],
                |x| expression::parse_num(x).map(T::Time)
            ),
            ("hash", 1) => expression::terminal(
                &top.args[0],
                |x| sha256::Hash::from_hex(x).map(T::HashEqual)
            ),
            ("and_p", 2) => expression::binary(top, T::And),
            ("or_p", 2) => expression::binary(top, T::ParallelOr),
            ("or_c", 2) => expression::binary(top, T::CascadeOr),
            ("or_v", 2) => expression::binary(top, T::CascadeOrV),
            ("or_s", 2) => expression::binary(top, T::SwitchOr),
            ("or_a", 2) => expression::binary(top, T::SwitchOrV),
            ("or_d", 2) => expression::binary(top, T::DelayedOr),
            _ => {
                let e: Rc<E<P>> = expression::FromTree::from_tree(top)?;
                Ok(T::CastE(Rc::try_unwrap(e).ok().unwrap()))
            }
        }?))
    }
}

// *** Parser trait implementation
impl AstElem for E<PublicKey> {
    fn into_e(self: Box<E<PublicKey>>) -> Rc<E<PublicKey>> { Rc::new(*self) }
    fn into_t(self: Box<E<PublicKey>>) -> Rc<T<PublicKey>> {
        let unboxed = *self; // need this variable, cannot directly match on *self, see https://github.com/rust-lang/rust/issues/16223
        match unboxed {
            E::ParallelOr(l, r) => Rc::new(T::ParallelOr(l, r)),
            x => Rc::new(T::CastE(x))
        }
    }
    fn is_e(&self) -> bool { true }
    fn is_t(&self) -> bool { true }

    fn serialize(&self, mut builder: script::Builder) -> script::Builder {
        match *self {
            E::CheckSig(ref pk) => {
                builder.push_key(&pk)
                       .push_opcode(opcodes::all::OP_CHECKSIG)
            }
            E::CheckMultiSig(k, ref pks) => {
                builder = builder.push_int(k as i64);
                for pk in pks {
                    builder = builder.push_key(&pk);
                }
                builder.push_int(pks.len() as i64)
                       .push_opcode(opcodes::all::OP_CHECKMULTISIG)
            }
            E::Time(n) => {
                builder.push_opcode(opcodes::all::OP_DUP)
                       .push_opcode(opcodes::all::OP_IF)
                       .push_int(n as i64)
                       .push_opcode(opcodes::OP_CSV)
                       .push_opcode(opcodes::all::OP_DROP)
                       .push_opcode(opcodes::all::OP_ENDIF)
            }
            E::Threshold(k, ref e, ref ws) => {
                builder = e.serialize(builder);
                for w in ws {
                    builder = w.serialize(builder).push_opcode(opcodes::all::OP_ADD);
                }
                builder.push_int(k as i64)
                       .push_opcode(opcodes::all::OP_EQUAL)
            }
            E::ParallelAnd(ref left, ref right) => {
                builder = left.serialize(builder);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::all::OP_BOOLAND)
            }
            E::CascadeAnd(ref left, ref right) => {
                builder = left.serialize(builder);
                builder = builder.push_opcode(opcodes::all::OP_NOTIF)
                                 .push_int(0)
                                 .push_opcode(opcodes::all::OP_ELSE);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::all::OP_ENDIF)
            }
            E::ParallelOr(ref left, ref right) => {
                builder = left.serialize(builder);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::all::OP_BOOLOR)
            }
            E::CascadeOr(ref left, ref right) => {
                builder = left.serialize(builder);
                builder = builder.push_opcode(opcodes::all::OP_IFDUP)
                                 .push_opcode(opcodes::all::OP_NOTIF);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::all::OP_ENDIF)
            }
            E::SwitchOrLeft(ref left, ref right) => {
                builder = builder.push_opcode(opcodes::all::OP_IF);
                builder = left.serialize(builder);
                builder = builder.push_opcode(opcodes::all::OP_ELSE);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::all::OP_ENDIF)
            }
            E::SwitchOrRight(ref left, ref right) => {
                builder = builder.push_opcode(opcodes::all::OP_NOTIF);
                builder = left.serialize(builder);
                builder = builder.push_opcode(opcodes::all::OP_ELSE);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::all::OP_ENDIF)
            }
            E::Likely(ref fexpr) => {
                builder = builder.push_opcode(opcodes::all::OP_NOTIF);
                builder = fexpr.serialize(builder);
                builder.push_opcode(opcodes::all::OP_ELSE)
                       .push_int(0)
                       .push_opcode(opcodes::all::OP_ENDIF)
            }
            E::Unlikely(ref fexpr) => {
                builder = builder.push_opcode(opcodes::all::OP_IF);
                builder = fexpr.serialize(builder);
                builder.push_opcode(opcodes::all::OP_ELSE)
                       .push_int(0)
                       .push_opcode(opcodes::all::OP_ENDIF)
            }
        }
    }
}

impl AstElem for Q<PublicKey> {
    fn into_q(self: Box<Q<PublicKey>>) -> Rc<Q<PublicKey>> { Rc::new(*self) }
    fn is_q(&self) -> bool { true }

    fn serialize(&self, mut builder: script::Builder) -> script::Builder {
        match *self {
            Q::Pubkey(pk) => {
                builder.push_key(&pk)
            }
            Q::And(ref left, ref right) => {
                builder = left.serialize(builder);
                right.serialize(builder)
            }
            Q::Or(ref left, ref right) => {
                builder = builder.push_opcode(opcodes::all::OP_IF);
                builder = left.serialize(builder);
                builder = builder.push_opcode(opcodes::all::OP_ELSE);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::all::OP_ENDIF)
            }
        }
    }
}

impl AstElem for W<PublicKey> {
    fn into_w(self: Box<W<PublicKey>>) -> Rc<W<PublicKey>> { Rc::new(*self) }
    fn is_w(&self) -> bool { true }

    fn serialize(&self, mut builder: script::Builder) -> script::Builder {
        match *self {
            W::CheckSig(pk) => {
                builder.push_opcode(opcodes::all::OP_SWAP)
                       .push_key(&pk)
                       .push_opcode(opcodes::all::OP_CHECKSIG)
            }
            W::HashEqual(hash) => {
                builder.push_opcode(opcodes::all::OP_SWAP)
                       .push_opcode(opcodes::all::OP_SIZE)
                       .push_opcode(opcodes::all::OP_0NOTEQUAL)
                       .push_opcode(opcodes::all::OP_IF)
                       .push_opcode(opcodes::all::OP_SIZE)
                       .push_int(32)
                       .push_opcode(opcodes::all::OP_EQUALVERIFY)
                       .push_opcode(opcodes::all::OP_SHA256)
                       .push_slice(&hash[..])
                       .push_opcode(opcodes::all::OP_EQUALVERIFY)
                       .push_int(1)
                       .push_opcode(opcodes::all::OP_ENDIF)
            }
            W::Time(n) => {
                builder.push_opcode(opcodes::all::OP_SWAP)
                       .push_opcode(opcodes::all::OP_DUP)
                       .push_opcode(opcodes::all::OP_IF)
                       .push_int(n as i64)
                       .push_opcode(opcodes::OP_CSV)
                       .push_opcode(opcodes::all::OP_DROP)
                       .push_opcode(opcodes::all::OP_ENDIF)
            }
            W::CastE(ref expr) => {
                builder = builder.push_opcode(opcodes::all::OP_TOALTSTACK);
                expr.serialize(builder).push_opcode(opcodes::all::OP_FROMALTSTACK)
            }
        }
    }
}

impl AstElem for F<PublicKey> {
    fn into_f(self: Box<F<PublicKey>>) -> Rc<F<PublicKey>> { Rc::new(*self) }
    fn is_f(&self) -> bool { true }

    fn is_t(&self) -> bool {
        match *self {
            F::CascadeOr(..) | F::SwitchOrV(..) => true,
            _ => false,
        }
    }
    fn into_t(self: Box<F<PublicKey>>) -> Rc<T<PublicKey>> {
        let unboxed = *self; // need this variable, cannot directly match on *self, see https://github.com/rust-lang/rust/issues/16223
        match unboxed {
            F::CascadeOr(l, r) => Rc::new(T::CascadeOrV(l, r)),
            F::SwitchOrV(l, r) => Rc::new(T::SwitchOrV(l, r)),
            x => panic!("{} is not a T", x),
        }
    }

    fn serialize(&self, mut builder: script::Builder) -> script::Builder {
        match *self {
            F::CheckSig(ref pk) => {
                builder.push_key(&pk)
                       .push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
                       .push_int(1)
            }
            F::CheckMultiSig(k, ref pks) => {
                builder = builder.push_int(k as i64);
                for pk in pks {
                    builder = builder.push_key(&pk);
                }
                builder.push_int(pks.len() as i64)
                       .push_opcode(opcodes::all::OP_CHECKMULTISIGVERIFY)
                       .push_int(1)
            }
            F::Time(n) => {
                builder.push_int(n as i64)
                       .push_opcode(opcodes::OP_CSV)
                       .push_opcode(opcodes::all::OP_0NOTEQUAL)
            }
            F::HashEqual(hash) => {
                builder.push_opcode(opcodes::all::OP_SIZE)
                       .push_int(32)
                       .push_opcode(opcodes::all::OP_EQUALVERIFY)
                       .push_opcode(opcodes::all::OP_SHA256)
                       .push_slice(&hash[..])
                       .push_opcode(opcodes::all::OP_EQUALVERIFY)
                       .push_int(1)
            }
            F::Threshold(k, ref e, ref ws) => {
                builder = e.serialize(builder);
                for w in ws {
                    builder = w.serialize(builder).push_opcode(opcodes::all::OP_ADD);
                }
                builder.push_int(k as i64)
                       .push_opcode(opcodes::all::OP_EQUALVERIFY)
                       .push_int(1)
            }
            F::And(ref left, ref right) => {
                builder = left.serialize(builder);
                right.serialize(builder)
            }
            F::SwitchOr(ref left, ref right) => {
                builder = builder.push_opcode(opcodes::all::OP_IF);
                builder = left.serialize(builder);
                builder = builder.push_opcode(opcodes::all::OP_ELSE);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::all::OP_ENDIF)
            }
            F::SwitchOrV(ref left, ref right) => {
                builder = builder.push_opcode(opcodes::all::OP_IF);
                builder = left.serialize(builder);
                builder = builder.push_opcode(opcodes::all::OP_ELSE);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::all::OP_ENDIF)
                       .push_int(1)
            }
            F::CascadeOr(ref left, ref right) => {
                builder = left.serialize(builder);
                builder = builder.push_opcode(opcodes::all::OP_NOTIF);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::all::OP_ENDIF)
                       .push_int(1)
            }
            F::DelayedOr(ref left, ref right) => {
                builder = builder.push_opcode(opcodes::all::OP_IF);
                builder = left.serialize(builder);
                builder = builder.push_opcode(opcodes::all::OP_ELSE);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::all::OP_ENDIF)
                       .push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
                       .push_int(1)
            }
        }
    }
}

impl AstElem for V<PublicKey> {
    fn into_v(self: Box<V<PublicKey>>) -> Rc<V<PublicKey>> { Rc::new(*self) }
    fn is_v(&self) -> bool { true }

    fn serialize(&self, mut builder: script::Builder) -> script::Builder {
        match *self {
            V::CheckSig(ref pk) => {
                builder.push_key(&pk)
                       .push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
            }
            V::CheckMultiSig(k, ref pks) => {
                builder = builder.push_int(k as i64);
                for pk in pks {
                    builder = builder.push_key(&pk);
                }
                builder.push_int(pks.len() as i64)
                       .push_opcode(opcodes::all::OP_CHECKMULTISIGVERIFY)
            }
            V::Time(n) => {
                builder.push_int(n as i64)
                       .push_opcode(opcodes::OP_CSV)
                       .push_opcode(opcodes::all::OP_DROP)
            }
            V::HashEqual(hash) => {
                builder.push_opcode(opcodes::all::OP_SIZE)
                       .push_int(32)
                       .push_opcode(opcodes::all::OP_EQUALVERIFY)
                       .push_opcode(opcodes::all::OP_SHA256)
                       .push_slice(&hash[..])
                       .push_opcode(opcodes::all::OP_EQUALVERIFY)
            }
            V::Threshold(k, ref e, ref ws) => {
                builder = e.serialize(builder);
                for w in ws {
                    builder = w.serialize(builder).push_opcode(opcodes::all::OP_ADD);
                }
                builder.push_int(k as i64)
                       .push_opcode(opcodes::all::OP_EQUALVERIFY)
            }
            V::And(ref left, ref right) => {
                builder = left.serialize(builder);
                right.serialize(builder)
            }
            V::SwitchOr(ref left, ref right) => {
                builder = builder.push_opcode(opcodes::all::OP_IF);
                builder = left.serialize(builder);
                builder = builder.push_opcode(opcodes::all::OP_ELSE);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::all::OP_ENDIF)
            }
            V::SwitchOrT(ref left, ref right) => {
                builder = builder.push_opcode(opcodes::all::OP_IF);
                builder = left.serialize(builder);
                builder = builder.push_opcode(opcodes::all::OP_ELSE);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::all::OP_ENDIF)
                       .push_opcode(opcodes::all::OP_VERIFY)
            }
            V::CascadeOr(ref left, ref right) => {
                builder = left.serialize(builder);
                builder = builder.push_opcode(opcodes::all::OP_NOTIF);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::all::OP_ENDIF)
            }
            V::DelayedOr(ref left, ref right) => {
                builder = builder.push_opcode(opcodes::all::OP_IF);
                builder = left.serialize(builder);
                builder = builder.push_opcode(opcodes::all::OP_ELSE);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::all::OP_ENDIF)
                       .push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
            }
        }
    }
}

impl AstElem for T<PublicKey> {
    fn into_t(self: Box<T<PublicKey>>) -> Rc<T<PublicKey>> { Rc::new(*self) }
    fn is_t(&self) -> bool { true }

    fn serialize(&self, mut builder: script::Builder) -> script::Builder {
        match *self {
            T::Time(n) => {
                builder.push_int(n as i64)
                       .push_opcode(opcodes::OP_CSV)
            }
            T::HashEqual(hash) => {
                builder.push_opcode(opcodes::all::OP_SIZE)
                       .push_int(32)
                       .push_opcode(opcodes::all::OP_EQUALVERIFY)
                       .push_opcode(opcodes::all::OP_SHA256)
                       .push_slice(&hash[..])
                       .push_opcode(opcodes::all::OP_EQUAL)
            }
            T::And(ref vexpr, ref top) => {
                builder = vexpr.serialize(builder);
                top.serialize(builder)
            }
            T::ParallelOr(ref left, ref right) => {
                builder = left.serialize(builder);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::all::OP_BOOLOR)
            }
            T::CascadeOr(ref left, ref right) => {
                builder = left.serialize(builder);
                builder = builder.push_opcode(opcodes::all::OP_IFDUP)
                                 .push_opcode(opcodes::all::OP_NOTIF);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::all::OP_ENDIF)
            }
            T::CascadeOrV(ref left, ref right) => {
                builder = left.serialize(builder);
                builder = builder.push_opcode(opcodes::all::OP_NOTIF);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::all::OP_ENDIF)
                       .push_int(1)
            }
            T::SwitchOr(ref left, ref right) => {
                builder = builder.push_opcode(opcodes::all::OP_IF);
                builder = left.serialize(builder);
                builder = builder.push_opcode(opcodes::all::OP_ELSE);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::all::OP_ENDIF)
            }
            T::SwitchOrV(ref left, ref right) => {
                builder = builder.push_opcode(opcodes::all::OP_IF);
                builder = left.serialize(builder);
                builder = builder.push_opcode(opcodes::all::OP_ELSE);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::all::OP_ENDIF)
                       .push_int(1)
            }
            T::DelayedOr(ref left, ref right) => {
                builder = builder.push_opcode(opcodes::all::OP_IF);
                builder = left.serialize(builder);
                builder = builder.push_opcode(opcodes::all::OP_ELSE);
                builder = right.serialize(builder);
                builder.push_opcode(opcodes::all::OP_ENDIF)
                       .push_opcode(opcodes::all::OP_CHECKSIG)
            }
            T::CastE(ref expr) => expr.serialize(builder),
        }
    }
}

// *** Debug/Display impls - these are generic over any kind of public key
impl<P: fmt::Debug> fmt::Debug for E<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            E::CheckSig(ref p) => write!(f, "E.pk({:?})", p),
            E::CheckMultiSig(k, ref ps) => {
                write!(f, "E.multi({}", k)?;
                for p in ps {
                    write!(f, ",{:?}", p)?;
                }
                f.write_str(")")
            }
            E::Time(n) => write!(f, "E.time({})", n),

            E::Threshold(k, ref e, ref subs) => {
                write!(f, "E.thres({},{:?}", k, e)?;
                for sub in subs {
                    write!(f, ",{:?}", sub)?;
                }
                f.write_str(")")
            }
            E::ParallelAnd(ref l, ref r) => write!(f, "E.and_p({:?},{:?})", l, r),
            E::CascadeAnd(ref l, ref r) => write!(f, "E.and_c({:?},{:?})", l, r),
            E::ParallelOr(ref left, ref right) => write!(f, "E.or_p({:?},{:?})", left, right),
            E::CascadeOr(ref left, ref right) => write!(f, "E.or_c({:?},{:?})", left, right),
            E::SwitchOrLeft(ref left, ref right) => write!(f, "E.or_s({:?},{:?})", left, right),
            E::SwitchOrRight(ref left, ref right) => write!(f, "E.or_a({:?},{:?})", left, right),

            E::Likely(ref fexpr) => write!(f, "E.lift_l({:?})", fexpr),
            E::Unlikely(ref fexpr) => write!(f, "E.lift_u({:?})", fexpr),
        }
    }
}

impl<P: fmt::Display> fmt::Display for E<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            E::CheckSig(ref p) => write!(f, "pk({})", p),
            E::CheckMultiSig(k, ref ps) => {
                write!(f, "multi({}", k)?;
                for p in ps {
                    write!(f, ",{}", p)?;
                }
                f.write_str(")")
            }
            E::Time(n) => write!(f, "time({})", n),

            E::Threshold(k, ref e, ref subs) => {
                write!(f, "thres({},{}", k, e)?;
                for sub in subs {
                    write!(f, ",{}", sub)?;
                }
                f.write_str(")")
            }
            E::ParallelAnd(ref l, ref r) => write!(f, "and_p({},{})", l, r),
            E::CascadeAnd(ref l, ref r) => write!(f, "and_c({},{})", l, r),
            E::ParallelOr(ref left, ref right) => write!(f, "or_p({},{})", left, right),
            E::CascadeOr(ref left, ref right) => write!(f, "or_c({},{})", left, right),
            E::SwitchOrLeft(ref left, ref right) => write!(f, "or_s({},{})", left, right),
            E::SwitchOrRight(ref left, ref right) => write!(f, "or_a({},{})", left, right),

            E::Likely(ref fexpr) => write!(f, "lift_l({})", fexpr),
            E::Unlikely(ref fexpr) => write!(f, "lift_u({})", fexpr),
        }
    }
}

impl<P: fmt::Debug> fmt::Debug for Q<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Q::Pubkey(ref p) => write!(f, "Q.pk({:?})", p),
            Q::And(ref l, ref r) => write!(f, "Q.and_p({:?},{:?})", l, r),
            Q::Or(ref l, ref r) => write!(f, "Q.or_s({:?},{:?})", l, r),
        }
    }
}

impl<P: fmt::Display> fmt::Display for Q<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Q::Pubkey(ref p) => write!(f, "pk({})", p),
            Q::And(ref l, ref r) => write!(f, "and_p({},{})", l, r),
            Q::Or(ref l, ref r) => write!(f, "or_s({},{})", l, r),
        }
    }
}

impl<P: fmt::Debug> fmt::Debug for W<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            W::CheckSig(ref p) => write!(f, "W.pk({:?})", p),
            W::HashEqual(ref h) => write!(f, "W.hash({:x})", h),
            W::Time(n) => write!(f, "W.time({})", n),
            W::CastE(ref e) => write!(f, "W{:?}", e),
        }
    }
}

impl<P: fmt::Display> fmt::Display for W<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            W::CheckSig(ref p) => write!(f, "pk({})", p),
            W::HashEqual(ref h) => write!(f, "hash({:x})", h),
            W::Time(n) => write!(f, "time({})", n),
            W::CastE(ref e) => write!(f, "{}", e),
        }
    }
}

impl<P: fmt::Debug> fmt::Debug for F<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            F::CheckSig(ref p) => write!(f, "F.pk({:?})", p),
            F::CheckMultiSig(k, ref ps) => {
                write!(f, "F.multi({}", k)?;
                for p in ps {
                    write!(f, ",{:?}", p)?;
                }
                f.write_str(")")
            }
            F::Time(n) => write!(f, "F.time({})", n),
            F::HashEqual(ref h) => write!(f, "F.hash({:x})", h),

            F::Threshold(k, ref e, ref subs) => {
                write!(f, "F.thres({},{:?}", k, e)?;
                for sub in subs {
                    write!(f, ",{:?}", sub)?;
                }
                f.write_str(")")
            }
            F::And(ref left, ref right) => write!(f, "F.and_p({:?},{:?})", left, right),
            F::CascadeOr(ref l, ref r) => write!(f, "F.or_v({:?},{:?})", l, r),
            F::SwitchOr(ref l, ref r) => write!(f, "F.or_s({:?},{:?})", l, r),
            F::SwitchOrV(ref l, ref r) => write!(f, "F.or_a({:?},{:?})", l, r),
            F::DelayedOr(ref l, ref r) => write!(f, "F.or_d({:?},{:?})", l, r),
        }
    }
}

impl<P: fmt::Display> fmt::Display for F<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            F::CheckSig(ref p) => write!(f, "pk({})", p),
            F::CheckMultiSig(k, ref ps) => {
                write!(f, "multi({}", k)?;
                for p in ps {
                    write!(f, ",{}", p)?;
                }
                f.write_str(")")
            }
            F::Time(n) => write!(f, "time({})", n),
            F::HashEqual(ref h) => write!(f, "hash({:x})", h),

            F::Threshold(k, ref e, ref subs) => {
                write!(f, "thres({},{}", k, e)?;
                for sub in subs {
                    write!(f, ",{}", sub)?;
                }
                f.write_str(")")
            }
            F::And(ref left, ref right) => write!(f, "and_p({},{})", left, right),
            F::CascadeOr(ref l, ref r) => write!(f, "or_v({},{})", l, r),
            F::SwitchOr(ref l, ref r) => write!(f, "or_s({},{})", l, r),
            F::SwitchOrV(ref l, ref r) => write!(f, "or_a({},{})", l, r),
            F::DelayedOr(ref l, ref r) => write!(f, "or_d({},{})", l, r),
        }
    }
}

impl<P: fmt::Debug> fmt::Debug for V<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            V::CheckSig(ref p) => write!(f, "V.pk({:?})", p),
            V::CheckMultiSig(k, ref ps) => {
                write!(f, "V.multi({}", k)?;
                for p in ps {
                    write!(f, ",{:?}", p)?;
                }
                f.write_str(")")
            }
            V::Time(n) => write!(f, "V.time({})", n),
            V::HashEqual(ref h) => write!(f, "V.hash({:x})", h),

            V::Threshold(k, ref e, ref subs) => {
                write!(f, "V.thres({},{:?}", k, e)?;
                for sub in subs {
                    write!(f, ",{:?}", sub)?;
                }
                f.write_str(")")
            }
            V::And(ref left, ref right) => write!(f, "V.and_p({:?},{:?})", left, right),
            V::CascadeOr(ref l, ref r) => write!(f, "V.or_v({:?},{:?})", l, r),
            V::SwitchOr(ref l, ref r) => write!(f, "V.or_s({:?},{:?})", l, r),
            V::SwitchOrT(ref l, ref r) => write!(f, "V.or_a({:?},{:?})", l, r),
            V::DelayedOr(ref l, ref r) => write!(f, "V.or_d({:?},{:?})", l, r),
        }
    }
}

impl<P: fmt::Display> fmt::Display for V<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            V::CheckSig(ref p) => write!(f, "pk({})", p),
            V::CheckMultiSig(k, ref ps) => {
                write!(f, "multi({}", k)?;
                for p in ps {
                    write!(f, ",{}", p)?;
                }
                f.write_str(")")
            }
            V::Time(n) => write!(f, "time({})", n),
            V::HashEqual(ref h) => write!(f, "hash({:x})", h),

            V::Threshold(k, ref e, ref subs) => {
                write!(f, "thres({},{}", k, e)?;
                for sub in subs {
                    write!(f, ",{}", sub)?;
                }
                f.write_str(")")
            }
            V::And(ref left, ref right) => write!(f, "and_p({},{})", left, right),
            V::CascadeOr(ref l, ref r) => write!(f, "or_v({},{})", l, r),
            V::SwitchOr(ref l, ref r) => write!(f, "or_s({},{})", l, r),
            V::SwitchOrT(ref l, ref r) => write!(f, "or_a({},{})", l, r),
            V::DelayedOr(ref l, ref r) => write!(f, "or_d({},{})", l, r),
        }
    }
}

impl<P: fmt::Debug> fmt::Debug for T<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            T::CastE(ref x) => write!(f, "T{:?}", x),

            T::Time(n) => write!(f, "T.time({})", n),
            T::HashEqual(ref h) => write!(f, "T.hash({:x})", h),

            T::And(ref left, ref right) => write!(f, "T.and_p({:?},{:?})", left, right),
            T::ParallelOr(ref left, ref right) => write!(f, "T.or_p({:?},{:?})", left, right),
            T::CascadeOr(ref left, ref right) => write!(f, "T.or_c({:?},{:?})", left, right),
            T::CascadeOrV(ref left, ref right) => write!(f, "T.or_v({:?},{:?})", left, right),
            T::SwitchOr(ref left, ref right) => write!(f, "T.or_s({:?},{:?})", left, right),
            T::SwitchOrV(ref left, ref right) => write!(f, "T.or_a({:?},{:?})", left, right),
            T::DelayedOr(ref left, ref right) => write!(f, "T.or_d({:?},{:?})", left, right),
        }
    }
}

impl<P: fmt::Display> fmt::Display for T<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            T::CastE(ref x) => write!(f, "{}", x),

            T::Time(n) => write!(f, "time({})", n),
            T::HashEqual(ref h) => write!(f, "hash({:x})", h),

            T::And(ref left, ref right) => write!(f, "and_p({},{})", left, right),
            T::ParallelOr(ref left, ref right) => write!(f, "or_p({},{})", left, right),
            T::CascadeOr(ref left, ref right) => write!(f, "or_c({},{})", left, right),
            T::CascadeOrV(ref left, ref right) => write!(f, "or_v({},{})", left, right),
            T::SwitchOr(ref left, ref right) => write!(f, "or_s({},{})", left, right),
            T::SwitchOrV(ref left, ref right) => write!(f, "or_a({},{})", left, right),
            T::DelayedOr(ref left, ref right) => write!(f, "or_d({},{})", left, right),
        }
    }
}

// *** Actual Parser

macro_rules! into_fn(
    (E) => (AstElem::into_e);
    (Q) => (AstElem::into_q);
    (W) => (AstElem::into_w);
    (V) => (AstElem::into_v);
    (F) => (AstElem::into_f);
    (T) => (AstElem::into_t);
);

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
                let mut ret: Result<Box<AstElem>, Error> = Err(Error::Unexpected(tok.to_string()));
                $(
                $tokens.un_next(tok);
                let subexpr = parse_subexpression($tokens)?;
                ret =
                $(if is_fn!($parse_expected)(&*subexpr) {
                    let $name = into_fn!($parse_expected)(subexpr);
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


/// Parse a subexpression that is -not- a wexpr (wexpr is special-cased
/// to avoid splitting expr into expr0 and exprn in the AST structure).
pub fn parse_subexpression(tokens: &mut TokenIter) -> Result<Box<AstElem>, Error> {
    if let Some(tok) = tokens.next() {
        tokens.un_next(tok);
    }
    let ret: Result<Box<AstElem>, Error> = parse_tree!(tokens,
        Token::BoolAnd => {
            #subexpression
            W: wexpr => {
                #subexpression
                E: expr => {
                    Ok(Box::new(E::ParallelAnd(expr, wexpr)))
                }
            }
        },
        Token::BoolOr => {
            #subexpression
            W: wexpr => {
                #subexpression
                E: expr => {
                    Ok(Box::new(E::ParallelOr(expr, wexpr)))
                }
            }
        },
        Token::Equal => {
            Token::Sha256Hash(hash), Token::Sha256, Token::EqualVerify, Token::Number(32), Token::Size => {
                Ok(Box::new(T::HashEqual(hash)))
            },
            Token::Number(k) => {{
                let mut ws = vec![];
                let e;
                loop {
                    match tokens.next() {
                        Some(Token::Add) => {
                            let next_sub = parse_subexpression(tokens)?;
                            if next_sub.is_w() {
                                ws.push(next_sub.into_w());
                            } else {
                                return Err(Error::Unexpected(next_sub.to_string()));
                            }
                        }
                        Some(x) => {
                            tokens.un_next(x);
                            let next_sub = parse_subexpression(tokens)?;
                            if next_sub.is_e() {
                                e = next_sub.into_e();
                                break;
                            } else {
                                return Err(Error::Unexpected(next_sub.to_string()));
                            }
                        }
                        None => return Err(Error::UnexpectedStart)
                    }
                }
                Ok(Box::new(E::Threshold(k as usize, e, ws)))
            }}
        },
        Token::EqualVerify => {
            Token::Sha256Hash(hash), Token::Sha256, Token::EqualVerify, Token::Number(32), Token::Size => {
                Ok(Box::new(V::HashEqual(hash)))
            },
            Token::Number(k) => {{
                let mut ws = vec![];
                let e;
                loop {
                    let next_sub = parse_subexpression(tokens)?;
                    if next_sub.is_w() {
                        ws.push(next_sub.into_w());
                    } else if next_sub.is_e() {
                        e = next_sub.into_e();
                        break;
                    } else {
                        return Err(Error::Unexpected(next_sub.to_string()));
                    }
                }
                Ok(Box::new(V::Threshold(k as usize, e, ws)))
            }}
        },
        Token::CheckSig => {
            Token::Pubkey(pk) => {{
                match tokens.next() {
                    Some(Token::Swap) => Ok(Box::new(W::CheckSig(pk))),
                    Some(x) => {
                        tokens.un_next(x);
                        Ok(Box::new(E::CheckSig(pk)))
                    }
                    None => Ok(Box::new(E::CheckSig(pk))),
                }
            }},
            Token::EndIf => {
                #subexpression
                Q: right => {
                    Token::Else => {
                        #subexpression
                        Q: left, Token::If => {
                            Ok(Box::new(T::DelayedOr(left, right)))
                        }
                    }
                }
            }
        },
        Token::CheckSigVerify => {
            Token::Pubkey(pk) => {
                Ok(Box::new(V::CheckSig(pk)))
            },
            Token::EndIf => {
                #subexpression
                Q: right => {
                    Token::Else => {
                        #subexpression
                        Q: left, Token::If => {
                            Ok(Box::new(V::DelayedOr(left, right)))
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
            Ok(Box::new(E::CheckMultiSig(k as usize, pks)))
        }},
        Token::CheckMultiSigVerify => {{
            let n = expect_token!(tokens, Token::Number(n) => { n });
            let mut pks = vec![];
            for _ in 0..n {
                pks.push(expect_token!(tokens, Token::Pubkey(pk) => { pk }));
            }
            pks.reverse();
            let k = expect_token!(tokens, Token::Number(n) => { n });
            Ok(Box::new(V::CheckMultiSig(k as usize, pks)))
        }},
        Token::ZeroNotEqual, Token::CheckSequenceVerify => {
            Token::Number(n) => {
                Ok(Box::new(F::Time(n)))
            }
        },
        Token::CheckSequenceVerify => {
            Token::Number(n) => {
                Ok(Box::new(T::Time(n)))
            }
        },
        Token::FromAltStack => {
            #subexpression
            E: expr, Token::ToAltStack => {
                Ok(Box::new(W::CastE(expr)))
            }
        },
        Token::Drop, Token::CheckSequenceVerify => {
            Token::Number(n) => {
                Ok(Box::new(V::Time(n)))
            }
        },
        Token::EndIf => {
            Token::Drop, Token::CheckSequenceVerify => {
                Token::Number(n), Token::If, Token::Dup => {{
                    match tokens.next() {
                        Some(Token::Swap) => Ok(Box::new(W::Time(n))),
                        Some(x) => {
                            tokens.un_next(x);
                            Ok(Box::new(E::Time(n)))
                        }
                        None => Ok(Box::new(E::Time(n)))
                    }
                }}
            },
            Token::Number(0), Token::Else => {
                #subexpression
                F: right => {
                    Token::If => {
                        Ok(Box::new(E::Unlikely(right)))
                    },
                    Token::NotIf => {
                        Ok(Box::new(E::Likely(right)))
                    }
                }
            }
            #subexpression
            Q: right => {
                Token::Else => {
                    #subexpression
                    Q: left, Token::If => {
                        Ok(Box::new(Q::Or(left, right)))
                    }
                }
            },
            F: right => {
                Token::If, Token::ZeroNotEqual, Token::Size, Token::Swap => {{
                    if let F::HashEqual(hash) = *right {
                        Ok(Box::new(W::HashEqual(hash)))
                    } else {
                        Err(Error::Unexpected(right.to_string()))
                    }
                }},
                Token::Else => {
                    Token::Number(0), Token::NotIf => {
                        #subexpression
                        E: left => {
                            Ok(Box::new(E::CascadeAnd(left, right)))
                        }
                    }
                    #subexpression
                    F: left, Token::If => {
                        Ok(Box::new(F::SwitchOr(left, right)))
                    },
                    E: left => {
                        Token::If => {
                            Ok(Box::new(E::SwitchOrLeft(left, right)))
                        },
                        Token::NotIf => {
                            Ok(Box::new(E::SwitchOrRight(left, right)))
                        }
                    }
                }
            },
            V: right => {
                Token::Else => {
                    #subexpression
                    V: left, Token::If => {
                        Ok(Box::new(V::SwitchOr(left, right)))
                    }
                },
                Token::NotIf => {
                    #subexpression
                    E: left => {
                        Ok(Box::new(V::CascadeOr(left, right)))
                    }
                }
            },
            T: right => {
                Token::Else => {
                    #subexpression
                    T: left, Token::If => {
                        Ok(Box::new(T::SwitchOr(left, right)))
                    }
                },
                Token::NotIf, Token::IfDup => {
                    #subexpression
                    E: left => {
                        Ok(Box::new(T::CascadeOr(left, right)))
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
                        Ok(Box::new(V::SwitchOrT(left, right)))
                    }
                }
            }
        },
        Token::Number(1) => {
            #subexpression
            V: vexpr => {{
                let unboxed = (*vexpr).clone();
                match unboxed {
                    V::CheckSig(pk) => Ok(Box::new(F::CheckSig(pk))),
                    V::CheckMultiSig(k, keys) => Ok(Box::new(F::CheckMultiSig(k, keys))),
                    V::HashEqual(hash) => Ok(Box::new(F::HashEqual(hash))),
                    V::Threshold(k, e, ws) => Ok(Box::new(F::Threshold(k, e, ws))),
                    V::CascadeOr(left, right) => Ok(Box::new(F::CascadeOr(left, right))),
                    V::SwitchOr(left, right) => Ok(Box::new(F::SwitchOrV(left, right))),
                    V::DelayedOr(left, right) => Ok(Box::new(F::DelayedOr(left, right))),
                    x => Err(Error::Unexpected(x.to_string())),
                }
            }}
        },
        Token::Pubkey(pk) => {
            Ok(Box::new(Q::Pubkey(pk)))
        }
    );

    if let Ok(ret) = ret {
        // vexpr [tfvq]expr AND
        if ret.is_t() || ret.is_f() || ret.is_v() || ret.is_q() {
            match tokens.peek() {
                None | Some(&Token::If) | Some(&Token::NotIf) | Some(&Token::Else) => Ok(ret),
                _ => {
                    let left = parse_subexpression(tokens)?;
                    let left = if left.is_v() {
                        left.into_v()
                    } else {
                        return Err(Error::Unexpected(left.to_string()))
                    };

                    if ret.is_t() {
                        let right = ret.into_t();
                        Ok(Box::new(T::And(left, right)))
                    } else if ret.is_q() {
                        let right = ret.into_q();
                        Ok(Box::new(Q::And(left, right)))
                    } else if ret.is_f() {
                        let right = ret.into_f();
                        Ok(Box::new(F::And(left, right)))
                    } else if ret.is_v() {
                        let right = ret.into_v();
                        Ok(Box::new(V::And(left, right)))
                    } else {
                        unreachable!()
                    }
                }
            }
        } else {
            Ok(ret)
        }
    } else {
        ret
    }
}

