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

use std::{fmt, str};

use bitcoin;
use bitcoin::blockdata::{opcodes, script};
use bitcoin_hashes::hex::FromHex;
use bitcoin_hashes::sha256;

use Error;
use errstr;
use expression;
use policy::AbstractPolicy;

/// All AST elements
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum AstElem<P> {
    // public key check
    /// `<key> CHECKSIG`
    Pk(P),
    /// `<key> CHECKSIGVERIFY`
    PkV(P),
    /// `<key>`
    PkQ(P),
    /// `SWAP <key> CHECKSIG`
    PkW(P),
    // multiple public key check
    /// `<k> <keys...> <n> CHECKMULTISIG`
    Multi(usize, Vec<P>),
    /// `<k> <keys...> <n> CHECKMULTISIGVERIFY`
    MultiV(usize, Vec<P>),
    // timelocks
    /// `<n> CHECKSEQUENCEVERIFY`
    TimeT(u32),
    /// `<n> CHECKSEQUENCEVERIFY DROP`
    TimeV(u32),
    /// `<n> CHECKSEQUENCEVERIFY 0NOTEQUAL`
    TimeF(u32),
    /// `DUP IF <n> CHECKSEQUENCEVERIFY DROP ENDIF`
    Time(u32),
    /// `SWAP DUP IF <n> CHECKSEQUENCEVERIFY DROP ENDIF`
    TimeW(u32),
    // hashlocks
    /// `SIZE 32 EQUALVERIFY SHA256 <hash> EQUAL`
    HashT(sha256::Hash),
    /// `SIZE 32 EQUALVERIFY SHA256 <hash> EQUALVERIFY`
    HashV(sha256::Hash),
    /// `SWAP SIZE 0NOTEQUAL IF SIZE 32 EQUALVERIFY SHA256 <hash> EQUALVERIFY 1 ENDIF`
    HashW(sha256::Hash),
    // wrappers
    /// `<V> 1`
    True(Box<AstElem<P>>),
    /// `TAS <E> FAS`
    Wrap(Box<AstElem<P>>),
    /// `NOTIF <F> ELSE 0 ENDIF`
    Likely(Box<AstElem<P>>),
    /// `IF <F> ELSE 0 ENDIF`
    Unlikely(Box<AstElem<P>>),
    // conjunctions
    /// `<V> <T/V/F/Q>`
    AndCat(Box<AstElem<P>>, Box<AstElem<P>>),
    /// `<E> <W> BOOLAND`
    AndBool(Box<AstElem<P>>, Box<AstElem<P>>),
    /// `<E> NOTIF 0 ELSE <F> ENDIF`
    AndCasc(Box<AstElem<P>>, Box<AstElem<P>>),
    // disjunctions
    /// `<E> <W> BoolOr`
    OrBool(Box<AstElem<P>>, Box<AstElem<P>>),
    /// `<E> IFDUP NOTIF <T/E> ENDIF`
    OrCasc(Box<AstElem<P>>, Box<AstElem<P>>),
    /// `<E> NOTIF <V> ENDIF`
    OrCont(Box<AstElem<P>>, Box<AstElem<P>>),
    /// `IF <Q> ELSE <Q> ENDIF CHECKSIG`
    OrKey(Box<AstElem<P>>, Box<AstElem<P>>),
    /// `IF <Q> ELSE <Q> ENDIF CHECKSIGVERIFY`
    OrKeyV(Box<AstElem<P>>, Box<AstElem<P>>),
    /// `IF <sub1> ELSE <sub2> ENDIF` for many choices of `sub1` and `sub2`
    OrIf(Box<AstElem<P>>, Box<AstElem<P>>),
    /// `IF <T> ELSE <T> ENDIF VERIFY`
    OrIfV(Box<AstElem<P>>, Box<AstElem<P>>),
    /// `NOTIF <F> ELSE <E> ENDIF`
    OrNotif(Box<AstElem<P>>, Box<AstElem<P>>),
    // thresholds
    /// `<E> (<W> ADD)* <n> EQUAL`
    Thresh(usize, Vec<AstElem<P>>),
    /// `<E> (<W> ADD)* <n> EQUALVERIFY`
    ThreshV(usize, Vec<AstElem<P>>),
}

impl<P> AstElem<P> {
    /// Does the element satisfy the "expression" calling convention?
    pub fn is_e(&self) -> bool {
        match *self {
            AstElem::Pk(..) => true,
            AstElem::Multi(..) => true,
            AstElem::Time(..) => true,
            AstElem::Likely(ref sub) => sub.is_f(),
            AstElem::Unlikely(ref sub) => sub.is_f(),
            AstElem::AndBool(ref left, ref right) => left.is_e() && right.is_w(),
            AstElem::AndCasc(ref left, ref right) => left.is_e() && right.is_f(),
            AstElem::OrBool(ref left, ref right) => left.is_e() && right.is_w(),
            AstElem::OrCasc(ref left, ref right) => left.is_e() && right.is_e(),
            AstElem::OrKey(ref left, ref right) => left.is_q() && right.is_q(),
            AstElem::OrIf(ref left, ref right) => left.is_f() && right.is_e(),
            AstElem::OrNotif(ref left, ref right) => left.is_f() && right.is_e(),
            AstElem::Thresh(_, ref subs) => {
                !subs.is_empty() &&
                    subs[0].is_e() &&
                    subs[1..].iter().all(|x| x.is_w())
            },
            _ => false,
        }
    }

    /// Does the element satisfy the "queue" calling convention?
    pub fn is_q(&self) -> bool {
        match *self {
            AstElem::PkQ(..) => true,
            AstElem::AndCat(ref left, ref right) => left.is_v() && right.is_q(),
            AstElem::OrIf(ref left, ref right) => left.is_q() && right.is_q(),
            _ => false,
        }
    }

    /// Does the element satisfy the "wrapped" calling convention?
    pub fn is_w(&self) -> bool {
        match *self {
            AstElem::PkW(..) => true,
            AstElem::TimeW(..) => true,
            AstElem::HashW(..) => true,
            AstElem::Wrap(ref sub) => sub.is_e(),
            _ => false,
        }
    }

    /// Does the element satisfy the "forced" calling convention?
    pub fn is_f(&self) -> bool {
        match *self {
            AstElem::TimeF(..) => true,
            AstElem::True(ref sub) => sub.is_v(),
            AstElem::AndCat(ref left, ref right) => left.is_v() && right.is_f(),
            AstElem::OrIf(ref left, ref right) => left.is_f() && right.is_f(),
            _ => false,
        }
    }

    /// Does the element satisfy the "verify" calling convention?
    pub fn is_v(&self) -> bool {
        match *self {
            AstElem::PkV(..) => true,
            AstElem::MultiV(..) => true,
            AstElem::TimeV(..) => true,
            AstElem::HashV(..) => true,
            AstElem::AndCat(ref left, ref right) => left.is_v() && right.is_v(),
            AstElem::OrCont(ref left, ref right) => left.is_e() && right.is_v(),
            AstElem::OrKeyV(ref left, ref right) => left.is_q() && right.is_q(),
            AstElem::OrIf(ref left, ref right) => left.is_v() && right.is_v(),
            AstElem::OrIfV(ref left, ref right) => left.is_t() && right.is_t(),
            AstElem::ThreshV(_, ref subs) => {
                !subs.is_empty() &&
                    subs[0].is_e() &&
                    subs[1..].iter().all(|x| x.is_w())
            },
            _ => false,
        }
    }


    /// Does the element satisfy the "toplevel" calling convention?
    pub fn is_t(&self) -> bool {
        match *self {
            AstElem::Pk(..) => true,
            AstElem::Multi(..) => true,
            AstElem::TimeT(..) => true,
            AstElem::HashT(..) => true,
            AstElem::True(ref sub) => sub.is_v(),
            AstElem::AndCat(ref left, ref right) => left.is_v() && right.is_t(),
            AstElem::OrBool(ref left, ref right) => left.is_e() && right.is_w(),
            AstElem::OrCasc(ref left, ref right) => left.is_e() && right.is_t(),
            AstElem::OrKey(ref left, ref right) => left.is_q() && right.is_q(),
            AstElem::OrIf(ref left, ref right) => left.is_t() && right.is_t(),
            AstElem::Thresh(_, ref subs) => {
                !subs.is_empty() &&
                    subs[0].is_e() &&
                    subs[1..].iter().all(|x| x.is_w())
            },
            _ => false,
        }
    }

    /// Convert an AST element with one public key type to one of another
    /// public key type
    pub fn translate<Func, Q, Error>(
        &self,
        translatefn: &mut Func,
    ) -> Result<AstElem<Q>, Error>
        where Func: FnMut(&P) -> Result<Q, Error>,
    {
        Ok(match *self {
            AstElem::Pk(ref p) => AstElem::Pk(translatefn(p)?),
            AstElem::PkV(ref p) => AstElem::PkV(translatefn(p)?),
            AstElem::PkQ(ref p) => AstElem::PkQ(translatefn(p)?),
            AstElem::PkW(ref p) => AstElem::PkW(translatefn(p)?),
            AstElem::Multi(k, ref keys) => {
                let keys: Result<Vec<Q>, _> = keys
                    .iter()
                    .map(translatefn)
                    .collect();
                AstElem::Multi(k, keys?)
            },
            AstElem::MultiV(k, ref keys) => {
                let keys: Result<Vec<Q>, _> = keys
                    .iter()
                    .map(translatefn)
                    .collect();
                AstElem::MultiV(k, keys?)
            },
            AstElem::TimeT(t) => AstElem::TimeT(t),
            AstElem::TimeV(t) => AstElem::TimeV(t),
            AstElem::TimeF(t) => AstElem::TimeF(t),
            AstElem::Time(t) => AstElem::Time(t),
            AstElem::TimeW(t) => AstElem::TimeW(t),
            AstElem::HashT(t) => AstElem::HashT(t),
            AstElem::HashV(t) => AstElem::HashV(t),
            AstElem::HashW(t) => AstElem::HashW(t),
            AstElem::True(ref sub) => AstElem::True(
                Box::new(sub.translate(translatefn)?),
            ),
            AstElem::Wrap(ref sub) => AstElem::Wrap(
                Box::new(sub.translate(translatefn)?),
            ),
            AstElem::Likely(ref sub) => AstElem::Likely(
                Box::new(sub.translate(translatefn)?),
            ),
            AstElem::Unlikely(ref sub) => AstElem::Unlikely(
                Box::new(sub.translate(translatefn)?),
            ),
            AstElem::AndCat(ref left, ref right) => AstElem::AndCat(
                Box::new(left.translate(translatefn)?),
                Box::new(right.translate(translatefn)?),
            ),
            AstElem::AndBool(ref left, ref right) => AstElem::AndBool(
                Box::new(left.translate(translatefn)?),
                Box::new(right.translate(translatefn)?),
            ),
            AstElem::AndCasc(ref left, ref right) => AstElem::AndCasc(
                Box::new(left.translate(translatefn)?),
                Box::new(right.translate(translatefn)?),
            ),
            AstElem::OrBool(ref left, ref right) => AstElem::OrBool(
                Box::new(left.translate(translatefn)?),
                Box::new(right.translate(translatefn)?),
            ),
            AstElem::OrCasc(ref left, ref right) => AstElem::OrCasc(
                Box::new(left.translate(translatefn)?),
                Box::new(right.translate(translatefn)?),
            ),
            AstElem::OrCont(ref left, ref right) => AstElem::OrCont(
                Box::new(left.translate(translatefn)?),
                Box::new(right.translate(translatefn)?),
            ),
            AstElem::OrKey(ref left, ref right) => AstElem::OrKey(
                Box::new(left.translate(translatefn)?),
                Box::new(right.translate(translatefn)?),
            ),
            AstElem::OrKeyV(ref left, ref right) => AstElem::OrKeyV(
                Box::new(left.translate(translatefn)?),
                Box::new(right.translate(translatefn)?),
            ),
            AstElem::OrIf(ref left, ref right) => AstElem::OrIf(
                Box::new(left.translate(translatefn)?),
                Box::new(right.translate(translatefn)?),
            ),
            AstElem::OrIfV(ref left, ref right) => AstElem::OrIfV(
                Box::new(left.translate(translatefn)?),
                Box::new(right.translate(translatefn)?),
            ),
            AstElem::OrNotif(ref left, ref right) => AstElem::OrNotif(
                Box::new(left.translate(translatefn)?),
                Box::new(right.translate(translatefn)?),
            ),
            AstElem::Thresh(k, ref subs) => {
                let subs: Result<Vec<AstElem<Q>>, _> = subs
                    .iter()
                    .map(|s| s.translate(translatefn))
                    .collect();
                AstElem::Thresh(k, subs?)
            },
            AstElem::ThreshV(k, ref subs) => {
                let subs: Result<Vec<AstElem<Q>>, _> = subs
                    .iter()
                    .map(|s| s.translate(translatefn))
                    .collect();
                AstElem::ThreshV(k, subs?)
            },
        })
    }
}

impl<P: fmt::Debug> fmt::Debug for AstElem<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("[")?;
        if self.is_e() {
            f.write_str("E")?;
        }
        if self.is_q() {
            f.write_str("Q")?;
        }
        if self.is_w() {
            f.write_str("W")?;
        }
        if self.is_f() {
            f.write_str("F")?;
        }
        if self.is_v() {
            f.write_str("V")?;
        }
        if self.is_t() {
            f.write_str("T")?;
        }
        f.write_str("]")?;
        match *self {
            AstElem::Pk(ref pk) => write!(f, "pk({:?})", pk),
            AstElem::PkV(ref pk) => write!(f, "pk_v({:?})", pk),
            AstElem::PkQ(ref pk) => write!(f, "pk_q({:?})", pk),
            AstElem::PkW(ref pk) => write!(f, "pk_w({:?})", pk),
            AstElem::Multi(k, ref pks) => {
                write!(f, "multi({}", k)?;
                for p in pks {
                    write!(f, ",{:?}", p)?;
                }
                f.write_str(")")
            },
            AstElem::MultiV(k, ref pks) => {
                write!(f, "multi_v({}", k)?;
                for p in pks {
                    write!(f, ",{:?}", p)?;
                }
                f.write_str(")")
            },
            AstElem::TimeT(t) => write!(f, "time_t({})", t),
            AstElem::TimeV(t) => write!(f, "time_v({})", t),
            AstElem::TimeF(t) => write!(f, "time_f({})", t),
            AstElem::Time(t) => write!(f, "time({})", t),
            AstElem::TimeW(t) => write!(f, "time_w({})", t),
            AstElem::HashT(h) => write!(f, "hash_t({})", h),
            AstElem::HashV(h) => write!(f, "hash_v({})", h),
            AstElem::HashW(h) => write!(f, "hash_w({})", h),
            AstElem::True(ref sub) => write!(f, "true({:?})", sub),
            AstElem::Wrap(ref sub) => write!(f, "wrap({:?})", sub),
            AstElem::Likely(ref sub) => write!(f, "likely({:?})", sub),
            AstElem::Unlikely(ref sub) => write!(f, "unlikely({:?})", sub),
            AstElem::AndCat(ref left, ref right) => write!(f, "and_cat({:?},{:?})", left, right),
            AstElem::AndBool(ref left, ref right) => write!(f, "and_bool({:?},{:?})", left, right),
            AstElem::AndCasc(ref left, ref right) => write!(f, "and_casc({:?},{:?})", left, right),
            AstElem::OrBool(ref left, ref right) => write!(f, "or_bool({:?},{:?})", left, right),
            AstElem::OrCasc(ref left, ref right) => write!(f, "or_casc({:?},{:?})", left, right),
            AstElem::OrCont(ref left, ref right) => write!(f, "or_cont({:?},{:?})", left, right),
            AstElem::OrKey(ref left, ref right) => write!(f, "or_key({:?},{:?})", left, right),
            AstElem::OrKeyV(ref left, ref right) => write!(f, "or_key_v({:?},{:?})", left, right),
            AstElem::OrIf(ref left, ref right) => write!(f, "or_if({:?},{:?})", left, right),
            AstElem::OrIfV(ref left, ref right) => write!(f, "or_if_v({:?},{:?})", left, right),
            AstElem::OrNotif(ref left, ref right) => write!(f, "or_notif({:?},{:?})", left, right),
            AstElem::Thresh(k, ref subs) => {
                write!(f, "thres({}", k)?;
                for s in subs {
                    write!(f, ",{:?}", s)?;
                }
                f.write_str(")")
            },
            AstElem::ThreshV(k, ref subs) => {
                write!(f, "thres_v({}", k)?;
                for s in subs {
                    write!(f, ",{:?}", s)?;
                }
                f.write_str(")")
            },
        }
    }
}

impl<P: fmt::Display> fmt::Display for AstElem<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AstElem::Pk(ref pk) => write!(f, "pk({})", pk),
            AstElem::PkV(ref pk) => write!(f, "pk_v({})", pk),
            AstElem::PkQ(ref pk) => write!(f, "pk_q({})", pk),
            AstElem::PkW(ref pk) => write!(f, "pk_w({})", pk),
            AstElem::Multi(k, ref pks) => {
                write!(f, "multi({}", k)?;
                for p in pks {
                    write!(f, ",{}", p)?;
                }
                f.write_str(")")
            },
            AstElem::MultiV(k, ref pks) => {
                write!(f, "multi_v({}", k)?;
                for p in pks {
                    write!(f, ",{}", p)?;
                }
                f.write_str(")")
            },
            AstElem::TimeT(t) => write!(f, "time_t({})", t),
            AstElem::TimeV(t) => write!(f, "time_v({})", t),
            AstElem::TimeF(t) => write!(f, "time_f({})", t),
            AstElem::Time(t) => write!(f, "time({})", t),
            AstElem::TimeW(t) => write!(f, "time_w({})", t),
            AstElem::HashT(h) => write!(f, "hash_t({})", h),
            AstElem::HashV(h) => write!(f, "hash_v({})", h),
            AstElem::HashW(h) => write!(f, "hash_w({})", h),
            AstElem::True(ref sub) => write!(f, "true({})", sub),
            AstElem::Wrap(ref sub) => write!(f, "wrap({})", sub),
            AstElem::Likely(ref sub) => write!(f, "likely({})", sub),
            AstElem::Unlikely(ref sub) => write!(f, "unlikely({})", sub),
            AstElem::AndCat(ref left, ref right) => write!(f, "and_cat({},{})", left, right),
            AstElem::AndBool(ref left, ref right) => write!(f, "and_bool({},{})", left, right),
            AstElem::AndCasc(ref left, ref right) => write!(f, "and_casc({},{})", left, right),
            AstElem::OrBool(ref left, ref right) => write!(f, "or_bool({},{})", left, right),
            AstElem::OrCasc(ref left, ref right) => write!(f, "or_casc({},{})", left, right),
            AstElem::OrCont(ref left, ref right) => write!(f, "or_cont({},{})", left, right),
            AstElem::OrKey(ref left, ref right) => write!(f, "or_key({},{})", left, right),
            AstElem::OrKeyV(ref left, ref right) => write!(f, "or_key_v({},{})", left, right),
            AstElem::OrIf(ref left, ref right) => write!(f, "or_if({},{})", left, right),
            AstElem::OrIfV(ref left, ref right) => write!(f, "or_if_v({},{})", left, right),
            AstElem::OrNotif(ref left, ref right) => write!(f, "or_notif({},{})", left, right),
            AstElem::Thresh(k, ref subs) => {
                write!(f, "thres({}", k)?;
                for s in subs {
                    write!(f, ",{}", s)?;
                }
                f.write_str(")")
            },
            AstElem::ThreshV(k, ref subs) => {
                write!(f, "thres_v({}", k)?;
                for s in subs {
                    write!(f, ",{}", s)?;
                }
                f.write_str(")")
            },
        }
    }
}

impl<P: Clone> AstElem<P> {
    /// Abstract the script into an "abstract policy" which can be filtered and analyzed
    pub fn abstract_policy(&self) -> AbstractPolicy<P> {
        match *self {
            AstElem::Pk(ref p) |
            AstElem::PkV(ref p) |
            AstElem::PkQ(ref p) |
            AstElem::PkW(ref p) => AbstractPolicy::Key(p.clone()),
            AstElem::Multi(k, ref keys) |
            AstElem::MultiV(k, ref keys) => {
                AbstractPolicy::Threshold(
                    k,
                    keys
                        .iter()
                        .map(|key| AbstractPolicy::Key(key.clone()))
                        .collect(),
                )
            },
            AstElem::TimeT(t) |
            AstElem::TimeV(t) |
            AstElem::TimeF(t) |
            AstElem::Time(t) |
            AstElem::TimeW(t) => AbstractPolicy::Time(t),
            AstElem::HashT(h) |
            AstElem::HashV(h) |
            AstElem::HashW(h) => AbstractPolicy::Hash(h),
            AstElem::True(ref sub) |
            AstElem::Wrap(ref sub) |
            AstElem::Likely(ref sub) |
            AstElem::Unlikely(ref sub) => sub.abstract_policy(),
            AstElem::AndCat(ref left, ref right) |
            AstElem::AndBool(ref left, ref right) |
            AstElem::AndCasc(ref left, ref right) => AbstractPolicy::And(
                Box::new(left.abstract_policy()),
                Box::new(right.abstract_policy()),
            ),
            AstElem::OrBool(ref left, ref right) |
            AstElem::OrCasc(ref left, ref right) |
            AstElem::OrCont(ref left, ref right) |
            AstElem::OrKey(ref left, ref right) |
            AstElem::OrKeyV(ref left, ref right) |
            AstElem::OrIf(ref left, ref right) |
            AstElem::OrIfV(ref left, ref right) |
            AstElem::OrNotif(ref left, ref right) => AbstractPolicy::Or(
                Box::new(left.abstract_policy()),
                Box::new(right.abstract_policy()),
            ),
            AstElem::Thresh(k, ref subs) |
            AstElem::ThreshV(k, ref subs) => AbstractPolicy::Threshold(
                k,
                subs.iter()
                    .map(|sub| sub.abstract_policy())
                    .collect(),
            ),
        }
    }

    /// Return a list of all public keys which might contribute to satisfaction of the scriptpubkey
    pub fn public_keys(&self) -> Vec<P> {
        match *self {
            AstElem::Pk(ref p) |
            AstElem::PkV(ref p) |
            AstElem::PkQ(ref p) |
            AstElem::PkW(ref p) => vec![p.clone()],
            AstElem::Multi(_, ref keys) |
            AstElem::MultiV(_, ref keys) => keys.clone(),
            AstElem::TimeT(..) |
            AstElem::TimeV(..) |
            AstElem::TimeF(..) |
            AstElem::Time(..) |
            AstElem::TimeW(..) => vec![],
            AstElem::HashT(..) |
            AstElem::HashV(..) |
            AstElem::HashW(..) => vec![],
            AstElem::True(ref sub) |
            AstElem::Wrap(ref sub) |
            AstElem::Likely(ref sub) |
            AstElem::Unlikely(ref sub) => sub.public_keys(),
            AstElem::AndCat(ref left, ref right) |
            AstElem::AndBool(ref left, ref right) |
            AstElem::AndCasc(ref left, ref right) => {
                let mut ret = left.public_keys();
                ret.extend(right.public_keys());
                ret
            },
            AstElem::OrBool(ref left, ref right) |
            AstElem::OrCasc(ref left, ref right) |
            AstElem::OrCont(ref left, ref right) |
            AstElem::OrKey(ref left, ref right) |
            AstElem::OrKeyV(ref left, ref right) |
            AstElem::OrIf(ref left, ref right) |
            AstElem::OrIfV(ref left, ref right) |
            AstElem::OrNotif(ref left, ref right) => {
                let mut ret = left.public_keys();
                ret.extend(right.public_keys());
                ret
            },
            AstElem::Thresh(_, ref subs) |
            AstElem::ThreshV(_, ref subs) => {
                let mut ret = vec![];
                for sub in subs {
                    ret.extend(sub.public_keys());
                }
                ret
            },
        }
    }
}

impl<P: str::FromStr> expression::FromTree for Box<AstElem<P>>
    where <P as str::FromStr>::Err: ToString,
{
    fn from_tree(top: &expression::Tree) -> Result<Box<AstElem<P>>, Error> {
        Ok(Box::new(expression::FromTree::from_tree(top)?))
    }
}

impl<P: str::FromStr> expression::FromTree for AstElem<P>
    where <P as str::FromStr>::Err: ToString,
{
    fn from_tree(top: &expression::Tree) -> Result<AstElem<P>, Error> {
        match (top.name, top.args.len()) {
            ("pk", 1) => expression::terminal(
                &top.args[0],
                |x| P::from_str(x).map(AstElem::Pk)
            ),
            ("pk_v", 1) => expression::terminal(
                &top.args[0],
                |x| P::from_str(x).map(AstElem::PkV)
            ),
            ("pk_q", 1) => expression::terminal(
                &top.args[0],
                |x| P::from_str(x).map(AstElem::PkQ)
            ),
            ("pk_w", 1) => expression::terminal(
                &top.args[0],
                |x| P::from_str(x).map(AstElem::PkW)
            ),
            ("multi", n) => {
                let k = expression::terminal(&top.args[0], expression::parse_num)? as usize;
                if n == 0 || k > n - 1 {
                    return Err(errstr("higher threshold than there were keys in multi"));
                }

                let pks: Result<Vec<P>, _> = top.args[1..].iter().map(|sub|
                    expression::terminal(sub, P::from_str)
                ).collect();

                pks.map(|pks| AstElem::Multi(k, pks))
            },
            ("multi_v", n) => {
                let k = expression::terminal(&top.args[0], expression::parse_num)? as usize;
                if n == 0 || k > n - 1 {
                    return Err(errstr("higher threshold than there were keys in multi"));
                }

                let pks: Result<Vec<P>, _> = top.args[1..].iter().map(|sub|
                    expression::terminal(sub, P::from_str)
                ).collect();

                pks.map(|pks| AstElem::MultiV(k, pks))
            },
            ("time_t", 1) => expression::terminal(
                &top.args[0],
                |x| expression::parse_num(x).map(AstElem::TimeT)
            ),
            ("time_v", 1) => expression::terminal(
                &top.args[0],
                |x| expression::parse_num(x).map(AstElem::TimeV)
            ),
            ("time_f", 1) => expression::terminal(
                &top.args[0],
                |x| expression::parse_num(x).map(AstElem::TimeF)
            ),
            ("time", 1) => expression::terminal(
                &top.args[0],
                |x| expression::parse_num(x).map(AstElem::Time)
            ),
            ("time_w", 1) => expression::terminal(
                &top.args[0],
                |x| expression::parse_num(x).map(AstElem::TimeW)
            ),
            ("hash_t", 1) => expression::terminal(
                &top.args[0],
                |x| sha256::Hash::from_hex(x).map(AstElem::HashT)
            ),
            ("hash_v", 1) => expression::terminal(
                &top.args[0],
                |x| sha256::Hash::from_hex(x).map(AstElem::HashV)
            ),
            ("hash_w", 1) => expression::terminal(
                &top.args[0],
                |x| sha256::Hash::from_hex(x).map(AstElem::HashW)
            ),
            ("true", 1) => expression::unary(top, AstElem::True),
            ("wrap", 1) => expression::unary(top, AstElem::Wrap),
            ("likely", 1) => expression::unary(top, AstElem::Likely),
            ("unlikely", 1) => expression::unary(top, AstElem::Unlikely),
            ("and_cat", 2) => expression::binary(top, AstElem::AndCat),
            ("and_bool", 2) => expression::binary(top, AstElem::AndBool),
            ("and_casc", 2) => expression::binary(top, AstElem::AndCasc),
            ("or_bool", 2) => expression::binary(top, AstElem::OrBool),
            ("or_casc", 2) => expression::binary(top, AstElem::OrCasc),
            ("or_cont", 2) => expression::binary(top, AstElem::OrCont),
            ("or_key", 2) => expression::binary(top, AstElem::OrKey),
            ("or_key_v", 2) => expression::binary(top, AstElem::OrKeyV),
            ("or_if", 2) => expression::binary(top, AstElem::OrIf),
            ("or_if_v", 2) => expression::binary(top, AstElem::OrIfV),
            ("or_notif", 2) => expression::binary(top, AstElem::OrNotif),
            ("thres", n) => {
                let k = expression::terminal(&top.args[0], expression::parse_num)? as usize;
                if n == 0 || k > n - 1 {
                    return Err(errstr("higher threshold than there are subexpressions"));
                }
                if n == 1 {
                    return Err(errstr("empty thresholds not allowed in descriptors"));
                }

                let subs: Result<Vec<AstElem<P>>, _> = top.args[1..].iter().map(|sub|
                    expression::FromTree::from_tree(sub)
                ).collect();

                Ok(AstElem::Thresh(k, subs?))
            },
            ("thres_v", n) => {
                let k = expression::terminal(&top.args[0], expression::parse_num)? as usize;
                if n == 0 || k > n - 1 {
                    return Err(errstr("higher threshold than there are subexpressions"));
                }
                if n == 1 {
                    return Err(errstr("empty thresholds not allowed in descriptors"));
                }

                let subs: Result<Vec<AstElem<P>>, _> = top.args[1..].iter().map(|sub|
                    expression::FromTree::from_tree(sub)
                ).collect();

                Ok(AstElem::ThreshV(k, subs?))
            },
            _ => Err(Error::Unexpected(format!(
                "{}({} args) while parsing Miniscript",
                top.name,
                top.args.len(),
            ))),
        }
    }
}

impl AstElem<bitcoin::PublicKey> {
    /// Encode the element as a fragment of Bitcoin Script. The inverse
    /// function, from Script to an AST element, is implemented in the
    /// `parse` module.
    pub fn encode(&self, mut builder: script::Builder) -> script::Builder {
        match *self {
            AstElem::Pk(ref pk) => {
                builder
                    .push_key(pk)
                    .push_opcode(opcodes::all::OP_CHECKSIG)
            },
            AstElem::PkV(ref pk) => {
                builder
                    .push_key(pk)
                    .push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
            },
            AstElem::PkQ(ref pk) => builder.push_key(pk),
            AstElem::PkW(ref pk) => {
                builder
                    .push_opcode(opcodes::all::OP_SWAP)
                    .push_key(pk)
                    .push_opcode(opcodes::all::OP_CHECKSIG)
            },
            AstElem::Multi(k, ref pks) => {
                builder = builder.push_int(k as i64);
                for pk in pks {
                    builder = builder.push_key(pk);
                }
                builder
                    .push_int(pks.len() as i64)
                    .push_opcode(opcodes::all::OP_CHECKMULTISIG)
            },
            AstElem::MultiV(k, ref pks) => {
                builder = builder.push_int(k as i64);
                for pk in pks {
                    builder = builder.push_key(pk);
                }
                builder
                    .push_int(pks.len() as i64)
                    .push_opcode(opcodes::all::OP_CHECKMULTISIGVERIFY)
            },
            AstElem::TimeT(t) => {
                builder
                    .push_int(t as i64)
                    .push_opcode(opcodes::OP_CSV)
            },
            AstElem::TimeV(t) => {
                builder
                    .push_int(t as i64)
                    .push_opcode(opcodes::OP_CSV)
                    .push_opcode(opcodes::all::OP_DROP)
            },
            AstElem::TimeF(t) => {
                builder
                    .push_int(t as i64)
                    .push_opcode(opcodes::OP_CSV)
                    .push_opcode(opcodes::all::OP_0NOTEQUAL)
            },
            AstElem::Time(t) => {
                builder
                .push_opcode(opcodes::all::OP_DUP)
                .push_opcode(opcodes::all::OP_IF)
                .push_int(t as i64)
                .push_opcode(opcodes::OP_CSV)
                .push_opcode(opcodes::all::OP_DROP)
                .push_opcode(opcodes::all::OP_ENDIF)
            },
            AstElem::TimeW(t) => {
                builder
                    .push_opcode(opcodes::all::OP_SWAP)
                    .push_opcode(opcodes::all::OP_DUP)
                    .push_opcode(opcodes::all::OP_IF)
                    .push_int(t as i64)
                    .push_opcode(opcodes::OP_CSV)
                    .push_opcode(opcodes::all::OP_DROP)
                    .push_opcode(opcodes::all::OP_ENDIF)
            },
            AstElem::HashT(h) => {
                builder
                    .push_opcode(opcodes::all::OP_SIZE)
                    .push_int(32)
                    .push_opcode(opcodes::all::OP_EQUALVERIFY)
                    .push_opcode(opcodes::all::OP_SHA256)
                    .push_slice(&h[..])
                    .push_opcode(opcodes::all::OP_EQUAL)
            },
            AstElem::HashV(h) => {
                builder
                    .push_opcode(opcodes::all::OP_SIZE)
                    .push_int(32)
                    .push_opcode(opcodes::all::OP_EQUALVERIFY)
                    .push_opcode(opcodes::all::OP_SHA256)
                    .push_slice(&h[..])
                    .push_opcode(opcodes::all::OP_EQUALVERIFY)
            },
            AstElem::HashW(h) => {
                builder
                    .push_opcode(opcodes::all::OP_SWAP)
                    .push_opcode(opcodes::all::OP_SIZE)
                    .push_opcode(opcodes::all::OP_0NOTEQUAL)
                    .push_opcode(opcodes::all::OP_IF)
                    .push_opcode(opcodes::all::OP_SIZE)
                    .push_int(32)
                    .push_opcode(opcodes::all::OP_EQUALVERIFY)
                    .push_opcode(opcodes::all::OP_SHA256)
                    .push_slice(&h[..])
                    .push_opcode(opcodes::all::OP_EQUALVERIFY)
                    .push_opcode(opcodes::all::OP_PUSHNUM_1)
                    .push_opcode(opcodes::all::OP_ENDIF)
            },
            AstElem::True(ref sub) => {
                sub.encode(builder)
                    .push_opcode(opcodes::all::OP_PUSHNUM_1)
            },
            AstElem::Wrap(ref sub) => {
                sub.encode(
                    builder.push_opcode(opcodes::all::OP_TOALTSTACK)
                ).push_opcode(opcodes::all::OP_FROMALTSTACK)
            },
            AstElem::Likely(ref sub) => {
                sub.encode(
                    builder.push_opcode(opcodes::all::OP_NOTIF)
                ).push_opcode(opcodes::all::OP_ELSE)
                    .push_opcode(opcodes::all::OP_PUSHBYTES_0)
                    .push_opcode(opcodes::all::OP_ENDIF)
            },
            AstElem::Unlikely(ref sub) => {
                sub.encode(
                    builder.push_opcode(opcodes::all::OP_IF)
                ).push_opcode(opcodes::all::OP_ELSE)
                    .push_opcode(opcodes::all::OP_PUSHBYTES_0)
                    .push_opcode(opcodes::all::OP_ENDIF)
            },
            AstElem::AndCat(ref left, ref right) => {
                right.encode(left.encode(builder))
            },
            AstElem::AndBool(ref left, ref right) => {
                right.encode(left.encode(builder))
                    .push_opcode(opcodes::all::OP_BOOLAND)
            },
            AstElem::AndCasc(ref left, ref right) => {
                builder = left.encode(builder)
                    .push_opcode(opcodes::all::OP_NOTIF)
                    .push_opcode(opcodes::all::OP_PUSHBYTES_0)
                    .push_opcode(opcodes::all::OP_ELSE);
                right.encode(builder)
                    .push_opcode(opcodes::all::OP_ENDIF)
            },
            AstElem::OrBool(ref left, ref right) => {
                right.encode(left.encode(builder))
                    .push_opcode(opcodes::all::OP_BOOLOR)
            },
            AstElem::OrCasc(ref left, ref right) => {
                builder = left.encode(builder)
                    .push_opcode(opcodes::all::OP_IFDUP)
                    .push_opcode(opcodes::all::OP_NOTIF);
                right.encode(builder)
                    .push_opcode(opcodes::all::OP_ENDIF)
            },
            AstElem::OrCont(ref left, ref right) => {
                builder = left.encode(builder)
                    .push_opcode(opcodes::all::OP_NOTIF);
                right.encode(builder)
                    .push_opcode(opcodes::all::OP_ENDIF)
            },
            AstElem::OrKey(ref left, ref right) => {
                builder = builder.push_opcode(opcodes::all::OP_IF);
                builder = left.encode(builder)
                    .push_opcode(opcodes::all::OP_ELSE);
                right.encode(builder)
                    .push_opcode(opcodes::all::OP_ENDIF)
                    .push_opcode(opcodes::all::OP_CHECKSIG)
            },
            AstElem::OrKeyV(ref left, ref right) => {
                builder = builder.push_opcode(opcodes::all::OP_IF);
                builder = left.encode(builder)
                    .push_opcode(opcodes::all::OP_ELSE);
                right.encode(builder)
                    .push_opcode(opcodes::all::OP_ENDIF)
                    .push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
            },
            AstElem::OrIf(ref left, ref right) => {
                builder = builder.push_opcode(opcodes::all::OP_IF);
                builder = left.encode(builder)
                    .push_opcode(opcodes::all::OP_ELSE);
                right.encode(builder)
                    .push_opcode(opcodes::all::OP_ENDIF)
            },
            AstElem::OrIfV(ref left, ref right) => {
                builder = builder.push_opcode(opcodes::all::OP_IF);
                builder = left.encode(builder)
                    .push_opcode(opcodes::all::OP_ELSE);
                right.encode(builder)
                    .push_opcode(opcodes::all::OP_ENDIF)
                    .push_opcode(opcodes::all::OP_VERIFY)
            },
            AstElem::OrNotif(ref left, ref right) => {
                builder = builder.push_opcode(opcodes::all::OP_NOTIF);
                builder = left.encode(builder)
                    .push_opcode(opcodes::all::OP_ELSE);
                right.encode(builder)
                    .push_opcode(opcodes::all::OP_ENDIF)
            },
            AstElem::Thresh(k, ref subs) => {
                for (n, sub) in subs.iter().enumerate() {
                    builder = sub.encode(builder);
                    if n > 0 {
                        builder = builder.push_opcode(opcodes::all::OP_EQUALVERIFY);
                    }
                }
                builder
                    .push_int(k as i64)
                    .push_opcode(opcodes::all::OP_EQUAL)
            },
            AstElem::ThreshV(k, ref subs) => {
                for (n, sub) in subs.iter().enumerate() {
                    builder = sub.encode(builder);
                    if n > 0 {
                        builder = builder.push_opcode(opcodes::all::OP_EQUALVERIFY);
                    }
                }
                builder
                    .push_int(k as i64)
                    .push_opcode(opcodes::all::OP_EQUALVERIFY)
            },
        }
    }
}

