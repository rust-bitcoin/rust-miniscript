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
//! Datatype describing a Miniscript "script fragment", which are the
//! building blocks of all Miniscripts. Each fragment has a unique
//! encoding in Bitcoin script, as well as a datatype. Full details
//! are given on the Miniscript website.

use std::{cmp, fmt, str};

use bitcoin::blockdata::{opcodes, script};
use bitcoin_hashes::hex::FromHex;
use bitcoin_hashes::{hash160, ripemd160, sha256, sha256d};

use Error;
use errstr;
use expression;
use script_num_size;
use ToPublicKey;
use ToPublicKeyHash;
use miniscript::types::{self, Property};

/// All AST elements
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AstElem<Pk, Pkh> {
    /// `1`
    True,
    /// `0`
    False,
    // pubkey checks
    /// `<key>`
    Pk(Pk),
    /// `DUP HASH160 <keyhash> EQUALVERIFY`
    PkH(Pkh),
    // timelocks
    /// `n CHECKSEQUENCEVERIFY`
    After(u32),
    /// `n CHECKLOCKTIMEVERIFY`
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
    Alt(Box<AstElem<Pk, Pkh>>),
    /// `SWAP [E1]`
    Swap(Box<AstElem<Pk, Pkh>>),
    /// `[Kt]/[Ke] CHECKSIG`
    Check(Box<AstElem<Pk, Pkh>>),
    /// `DUP IF [V] ENDIF`
    DupIf(Box<AstElem<Pk, Pkh>>),
    /// [T] VERIFY
    Verify(Box<AstElem<Pk, Pkh>>),
    /// SIZE 0NOTEQUAL IF [Fn] ENDIF
    NonZero(Box<AstElem<Pk, Pkh>>),
    /// [X] 0NOTEQUAL
    ZeroNotEqual(Box<AstElem<Pk, Pkh>>),
    // Conjunctions
    /// [V] [T]/[V]/[F]/[Kt]
    AndV(Box<AstElem<Pk, Pkh>>, Box<AstElem<Pk, Pkh>>),
    /// [E] [W] BOOLAND
    AndB(Box<AstElem<Pk, Pkh>>, Box<AstElem<Pk, Pkh>>),
    /// [various] NOTIF [various] ELSE [various] ENDIF
    AndOr(Box<AstElem<Pk, Pkh>>, Box<AstElem<Pk, Pkh>>, Box<AstElem<Pk, Pkh>>),
    // Disjunctions
    /// [E] [W] BOOLOR
    OrB(Box<AstElem<Pk, Pkh>>, Box<AstElem<Pk, Pkh>>),
    /// [E] IFDUP NOTIF [T]/[E] ENDIF
    OrD(Box<AstElem<Pk, Pkh>>, Box<AstElem<Pk, Pkh>>),
    /// [E] NOTIF [V] ENDIF
    OrC(Box<AstElem<Pk, Pkh>>, Box<AstElem<Pk, Pkh>>),
    /// IF [various] ELSE [various] ENDIF
    OrI(Box<AstElem<Pk, Pkh>>, Box<AstElem<Pk, Pkh>>),
    // Thresholds
    /// [E] ([W] ADD)* k EQUAL
    Thresh(usize, Vec<AstElem<Pk, Pkh>>),
    /// k (<key>)* n CHECKMULTISIG
    ThreshM(usize, Vec<Pk>),
}

impl<Pk, Pkh> AstElem<Pk, Pkh> {
    /// Internal helper function for displaying wrapper types; returns
    /// a character to display before the `:` as well as a reference
    /// to the wrapped type to allow easy recursion
    fn wrap_char(&self) -> Option<(char, &Box<Self>)> {
        match *self {
            AstElem::Alt(ref sub) => Some(('a', sub)),
            AstElem::Swap(ref sub) => Some(('s', sub)),
            AstElem::Check(ref sub) => Some(('c', sub)),
            AstElem::DupIf(ref sub) => Some(('d', sub)),
            AstElem::Verify(ref sub) => Some(('v', sub)),
            AstElem::NonZero(ref sub) => Some(('j', sub)),
            AstElem::ZeroNotEqual(ref sub) => Some(('u', sub)),
            _ => None,
        }
    }
}

impl<Pk, Pkh: Clone> AstElem<Pk, Pkh> {
    /// Convert an AST element with one public key type to one of another
    /// public key type
    pub fn translate_pk<Func, Q, Error>(
        &self,
        mut translatefn: Func,
    ) -> Result<AstElem<Q, Pkh>, Error>
        where Func: FnMut(&Pk) -> Result<Q, Error>,
    {
        Ok(match *self {
            AstElem::Pk(ref p) => AstElem::Pk(translatefn(p)?),
            AstElem::PkH(ref p) => AstElem::PkH(p.clone()),
            AstElem::After(n) => AstElem::After(n),
            AstElem::Older(n) => AstElem::Older(n),
            AstElem::Sha256(x) => AstElem::Sha256(x),
            AstElem::Hash256(x) => AstElem::Hash256(x),
            AstElem::Ripemd160(x) => AstElem::Ripemd160(x),
            AstElem::Hash160(x) => AstElem::Hash160(x),
            AstElem::True => AstElem::True,
            AstElem::False => AstElem::False,
            AstElem::Alt(ref sub) => AstElem::Alt(
                Box::new(sub.translate_pk(translatefn)?),
            ),
            AstElem::Swap(ref sub) => AstElem::Swap(
                Box::new(sub.translate_pk(translatefn)?),
            ),
            AstElem::Check(ref sub) => AstElem::Check(
                Box::new(sub.translate_pk(translatefn)?),
            ),
            AstElem::DupIf(ref sub) => AstElem::DupIf(
                Box::new(sub.translate_pk(translatefn)?),
            ),
            AstElem::Verify(ref sub) => AstElem::Verify(
                Box::new(sub.translate_pk(translatefn)?),
            ),
            AstElem::NonZero(ref sub) => AstElem::NonZero(
                Box::new(sub.translate_pk(translatefn)?),
            ),
            AstElem::ZeroNotEqual(ref sub) => AstElem::ZeroNotEqual(
                Box::new(sub.translate_pk(translatefn)?),
            ),
            AstElem::AndV(ref left, ref right) => AstElem::AndV(
                Box::new(left.translate_pk(&mut translatefn)?),
                Box::new(right.translate_pk(translatefn)?),
            ),
            AstElem::AndB(ref left, ref right) => AstElem::AndB(
                Box::new(left.translate_pk(&mut translatefn)?),
                Box::new(right.translate_pk(translatefn)?),
            ),
            AstElem::AndOr(ref a, ref b, ref c) => AstElem::AndOr(
                Box::new(a.translate_pk(&mut translatefn)?),
                Box::new(b.translate_pk(&mut translatefn)?),
                Box::new(c.translate_pk(translatefn)?),
            ),
            AstElem::OrB(ref left, ref right) => AstElem::OrB(
                Box::new(left.translate_pk(&mut translatefn)?),
                Box::new(right.translate_pk(translatefn)?),
            ),
            AstElem::OrD(ref left, ref right) => AstElem::OrD(
                Box::new(left.translate_pk(&mut translatefn)?),
                Box::new(right.translate_pk(translatefn)?),
            ),
            AstElem::OrC(ref left, ref right) => AstElem::OrC(
                Box::new(left.translate_pk(&mut translatefn)?),
                Box::new(right.translate_pk(translatefn)?),
            ),
            AstElem::OrI(ref left, ref right) => AstElem::OrI(
                Box::new(left.translate_pk(&mut translatefn)?),
                Box::new(right.translate_pk(translatefn)?),
            ),
            AstElem::Thresh(k, ref subs) => {
                let subs: Result<Vec<AstElem<Q, Pkh>>, _> = subs
                    .iter()
                    .map(|s| s.translate_pk(&mut translatefn))
                    .collect();
                AstElem::Thresh(k, subs?)
            },
            AstElem::ThreshM(k, ref keys) => {
                let keys: Result<Vec<Q>, _> = keys
                    .iter()
                    .map(&mut translatefn)
                    .collect();
                AstElem::ThreshM(k, keys?)
            }
        })
    }
}

impl<Pk: Clone, Pkh> AstElem<Pk, Pkh> {
    /// Convert an AST element with one public key hash type to one of another
    /// public key hash type
    pub fn translate_pkh<Func, Q, Error>(
        &self,
        mut translatefn: Func,
    ) -> Result<AstElem<Pk, Q>, Error>
        where Func: FnMut(&Pkh) -> Result<Q, Error>,
    {
        Ok(match *self {
            AstElem::Pk(ref p) => AstElem::Pk(p.clone()),
            AstElem::PkH(ref p) => AstElem::PkH(translatefn(p)?),
            AstElem::After(n) => AstElem::After(n),
            AstElem::Older(n) => AstElem::Older(n),
            AstElem::Sha256(x) => AstElem::Sha256(x),
            AstElem::Hash256(x) => AstElem::Hash256(x),
            AstElem::Ripemd160(x) => AstElem::Ripemd160(x),
            AstElem::Hash160(x) => AstElem::Hash160(x),
            AstElem::True => AstElem::True,
            AstElem::False => AstElem::False,
            AstElem::Alt(ref sub) => AstElem::Alt(
                Box::new(sub.translate_pkh(translatefn)?),
            ),
            AstElem::Swap(ref sub) => AstElem::Swap(
                Box::new(sub.translate_pkh(translatefn)?),
            ),
            AstElem::Check(ref sub) => AstElem::Check(
                Box::new(sub.translate_pkh(translatefn)?),
            ),
            AstElem::DupIf(ref sub) => AstElem::DupIf(
                Box::new(sub.translate_pkh(translatefn)?),
            ),
            AstElem::Verify(ref sub) => AstElem::Verify(
                Box::new(sub.translate_pkh(translatefn)?),
            ),
            AstElem::NonZero(ref sub) => AstElem::NonZero(
                Box::new(sub.translate_pkh(translatefn)?),
            ),
            AstElem::ZeroNotEqual(ref sub) => AstElem::ZeroNotEqual(
                Box::new(sub.translate_pkh(translatefn)?),
            ),
            AstElem::AndV(ref left, ref right) => AstElem::AndV(
                Box::new(left.translate_pkh(&mut translatefn)?),
                Box::new(right.translate_pkh(translatefn)?),
            ),
            AstElem::AndB(ref left, ref right) => AstElem::AndB(
                Box::new(left.translate_pkh(&mut translatefn)?),
                Box::new(right.translate_pkh(translatefn)?),
            ),
            AstElem::AndOr(ref a, ref b, ref c) => AstElem::AndOr(
                Box::new(a.translate_pkh(&mut translatefn)?),
                Box::new(b.translate_pkh(&mut translatefn)?),
                Box::new(c.translate_pkh(translatefn)?),
            ),
            AstElem::OrB(ref left, ref right) => AstElem::OrB(
                Box::new(left.translate_pkh(&mut translatefn)?),
                Box::new(right.translate_pkh(translatefn)?),
            ),
            AstElem::OrD(ref left, ref right) => AstElem::OrD(
                Box::new(left.translate_pkh(&mut translatefn)?),
                Box::new(right.translate_pkh(translatefn)?),
            ),
            AstElem::OrC(ref left, ref right) => AstElem::OrC(
                Box::new(left.translate_pkh(&mut translatefn)?),
                Box::new(right.translate_pkh(translatefn)?),
            ),
            AstElem::OrI(ref left, ref right) => AstElem::OrI(
                Box::new(left.translate_pkh(&mut translatefn)?),
                Box::new(right.translate_pkh(translatefn)?),
            ),
            AstElem::Thresh(k, ref subs) => {
                let subs: Result<Vec<AstElem<Pk, Q>>, _> = subs
                    .iter()
                    .map(|s| s.translate_pkh(&mut translatefn))
                    .collect();
                AstElem::Thresh(k, subs?)
            },
            AstElem::ThreshM(k, ref keys) => AstElem::ThreshM(k, keys.clone()),
        })
    }
}

impl<Pk, Pkh> fmt::Debug for AstElem<Pk, Pkh>
where
    Pk: Clone + fmt::Debug,
    Pkh: Clone + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("[")?;
        if let Ok(type_map) = types::Type::type_check(self, |_| None) {
            f.write_str(match type_map.corr.base {
                types::Base::B => "B",
                types::Base::K => "K",
                types::Base::V => "V",
                types::Base::W => "W",
            })?;
            fmt::Write::write_char(f, '/')?;
            f.write_str(match type_map.corr.input {
                types::Input::Zero => "z",
                types::Input::One => "o",
                types::Input::OneNonZero => "on",
                types::Input::Any => "",
                types::Input::AnyNonZero => "n",
            })?;
            if type_map.corr.dissatisfiable {
                fmt::Write::write_char(f, 'd')?;
            }
            if type_map.corr.unit {
                fmt::Write::write_char(f, 'u')?;
            }
            f.write_str(match type_map.mall.dissat {
                types::Dissat::None => "f",
                types::Dissat::Unique => "e",
                types::Dissat::Unknown => "",
            })?;
            if type_map.mall.safe {
                fmt::Write::write_char(f, 's')?;
            }
            if type_map.mall.non_malleable {
                fmt::Write::write_char(f, 'm')?;
            }
        } else {
            f.write_str("TYPECHECK FAILED")?;
        }
        f.write_str("]")?;
        if let Some((ch, sub)) = self.wrap_char() {
            fmt::Write::write_char(f, ch)?;
            if sub.wrap_char().is_none() {
                fmt::Write::write_char(f, ':')?;
            }
            write!(f, "{:?}", sub)
        } else {
            match *self {
                AstElem::Pk(ref pk) => write!(f, "pk({:?})", pk),
                AstElem::PkH(ref pkh) => write!(f, "pk_h({:?})", pkh),
                AstElem::After(t) => write!(f, "after({})", t),
                AstElem::Older(t) => write!(f, "older({})", t),
                AstElem::Sha256(h) => write!(f, "sha256({})", h),
                AstElem::Hash256(h) => write!(f, "hash256({})", h),
                AstElem::Ripemd160(h) => write!(f, "ripemd160({})", h),
                AstElem::Hash160(h) => write!(f, "hash160({})", h),
                AstElem::True => f.write_str("1"),
                AstElem::False => f.write_str("0"),
                AstElem::AndV(ref l, ref r) =>
                    write!(f, "and_v({:?},{:?})", l, r),
                AstElem::AndB(ref l, ref r) =>
                    write!(f, "and_b({:?},{:?})", l, r),
                AstElem::AndOr(ref a, ref b, ref c) =>
                    write!(f, "tern({:?},{:?},{:?})", a, c, b),
                AstElem::OrB(ref l, ref r) =>
                    write!(f, "or_b({:?},{:?})", l, r),
                AstElem::OrD(ref l, ref r) =>
                    write!(f, "or_d({:?},{:?})", l, r),
                AstElem::OrC(ref l, ref r) =>
                    write!(f, "or_c({:?},{:?})", l, r),
                AstElem::OrI(ref l, ref r) =>
                    write!(f, "or_i({:?},{:?})", l, r),
                AstElem::Thresh(k, ref subs) => {
                    write!(f, "thresh({}", k)?;
                    for s in subs {
                        write!(f, ",{:?}", s)?;
                    }
                    f.write_str(")")
                },
                AstElem::ThreshM(k, ref keys) => {
                    write!(f, "thresh_m({}", k)?;
                    for k in keys {
                        write!(f, "{:?},", k)?;
                    }
                    f.write_str(")")
                },
                _ => unreachable!(),
            }
        }
    }
}

impl<Pk: fmt::Display, Pkh: fmt::Display> fmt::Display for AstElem<Pk, Pkh> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AstElem::Pk(ref pk) => write!(f, "pk({})", pk),
            AstElem::PkH(ref pkh) => write!(f, "pk_h({})", pkh),
            AstElem::After(t) => write!(f, "after({})", t),
            AstElem::Older(t) => write!(f, "older({})", t),
            AstElem::Sha256(h) => write!(f, "sha256({})", h),
            AstElem::Hash256(h) => write!(f, "hash256({})", h),
            AstElem::Ripemd160(h) => write!(f, "ripemd160({})", h),
            AstElem::Hash160(h) => write!(f, "hash160({})", h),
            AstElem::True => f.write_str("1"),
            AstElem::False => f.write_str("0"),
            AstElem::AndV(ref l, ref r) => write!(f, "and_v({},{})", l, r),
            AstElem::AndB(ref l, ref r) => write!(f, "and_b({},{})", l, r),
            AstElem::AndOr(ref a, ref b, ref c) =>
                write!(f, "tern({},{},{})", a, c, b),
            AstElem::OrB(ref l, ref r) => write!(f, "or_b({},{})", l, r),
            AstElem::OrD(ref l, ref r) => write!(f, "or_d({},{})", l, r),
            AstElem::OrC(ref l, ref r) => write!(f, "or_c({},{})", l, r),
            AstElem::OrI(ref l, ref r) => write!(f, "or_i({},{})", l, r),
            AstElem::Thresh(k, ref subs) => {
                write!(f, "thresh({}", k)?;
                for s in subs {
                    write!(f, ",{}", s)?;
                }
                f.write_str(")")
            },
            AstElem::ThreshM(k, ref keys) => {
                write!(f, "thresh_m({}", k)?;
                for k in keys {
                    write!(f, ",{}", k)?;
                }
                f.write_str(")")
            },
            // wrappers
            _ => {
                if let Some((ch, sub)) = self.wrap_char() {
                    fmt::Write::write_char(f, ch)?;
                    if sub.wrap_char().is_none() {
                        fmt::Write::write_char(f, ':')?;
                    }
                    write!(f, "{}", sub)
                } else {
                    unreachable!();
                }
            },
        }
    }
}

impl<Pk, Pkh> expression::FromTree for Box<AstElem<Pk, Pkh>> where
    Pk: str::FromStr,
    Pkh: str::FromStr,
    <Pk as str::FromStr>::Err: ToString,
    <Pkh as str::FromStr>::Err: ToString,
{
    fn from_tree(top: &expression::Tree) -> Result<Box<AstElem<Pk, Pkh>>, Error> {
        Ok(Box::new(expression::FromTree::from_tree(top)?))
    }
}

impl<Pk, Pkh> expression::FromTree for AstElem<Pk, Pkh> where
    Pk: str::FromStr,
    Pkh: str::FromStr,
    <Pk as str::FromStr>::Err: ToString,
    <Pkh as str::FromStr>::Err: ToString,
{
    fn from_tree(top: &expression::Tree) -> Result<AstElem<Pk, Pkh>, Error> {
        let frag_name;
        let frag_wrap;
        let mut name_split = top.name.split(':');
        match (name_split.next(), name_split.next(), name_split.next()) {
            (None, _, _) => {
                frag_name = "";
                frag_wrap = "";
            },
            (Some(name), None, _) => {
                frag_name = name;
                frag_wrap = "";
            },
            (Some(wrap), Some(name), None) => {
                frag_name = name;
                frag_wrap = wrap;
            },
            (Some(_), Some(_), Some(_)) => {
                return Err(Error::MultiColon(top.name.to_owned()));
            },
        }
        let mut unwrapped = match (frag_name, top.args.len()) {
            ("pk", 1) => expression::terminal(
                &top.args[0],
                |x| Pk::from_str(x).map(AstElem::Pk)
            ),
            ("pk_h", 1) => expression::terminal(
                &top.args[0],
                |x| Pkh::from_str(x).map(AstElem::PkH)
            ),
            ("after", 1) => expression::terminal(
                &top.args[0],
                |x| expression::parse_num(x).map(AstElem::After)
            ),
            ("older", 1) => expression::terminal(
                &top.args[0],
                |x| expression::parse_num(x).map(AstElem::Older)
            ),
            ("sha256", 1) => expression::terminal(
                &top.args[0],
                |x| sha256::Hash::from_hex(x).map(AstElem::Sha256)
            ),
            ("hash256", 1) => expression::terminal(
                &top.args[0],
                |x| sha256d::Hash::from_hex(x).map(AstElem::Hash256)
            ),
            ("ripemd160", 1) => expression::terminal(
                &top.args[0],
                |x| ripemd160::Hash::from_hex(x).map(AstElem::Ripemd160)
            ),
            ("hash160", 1) => expression::terminal(
                &top.args[0],
                |x| hash160::Hash::from_hex(x).map(AstElem::Hash160)
            ),
            ("true", 0) => Ok(AstElem::True),
            ("and_v", 2) => {
                let expr = expression::binary(top, AstElem::AndV)?;
                if let AstElem::AndV(_, ref right) = expr {
                    if let AstElem::True = **right {
                        return Err(Error::NonCanonicalTrue);
                    }
                }
                Ok(expr)
            },
            ("and_b", 2) => expression::binary(top, AstElem::AndB),
            ("tern", 3) => Ok(AstElem::AndOr(
                expression::FromTree::from_tree(&top.args[0])?,
                expression::FromTree::from_tree(&top.args[2])?,
                expression::FromTree::from_tree(&top.args[1])?,
            )),
            ("or_b", 2) => expression::binary(top, AstElem::OrB),
            ("or_d", 2) => expression::binary(top, AstElem::OrD),
            ("or_c", 2) => expression::binary(top, AstElem::OrC),
            ("or_i", 2) => expression::binary(top, AstElem::OrI),
            ("thresh", n) => {
                let k = expression::terminal(&top.args[0], expression::parse_num)? as usize;
                if n == 0 || k > n - 1 {
                    return Err(errstr("higher threshold than there are subexpressions"));
                }
                if n == 1 {
                    return Err(errstr("empty thresholds not allowed in descriptors"));
                }

                let subs: Result<Vec<AstElem<Pk, Pkh>>, _> = top.args[1..].iter().map(|sub|
                    expression::FromTree::from_tree(sub)
                ).collect();

                Ok(AstElem::Thresh(k, subs?))
            },
            ("thresh_m", n) => {
                let k = expression::terminal(&top.args[0], expression::parse_num)? as usize;
                if n == 0 || k > n - 1 {
                    return Err(errstr("higher threshold than there were keys in multi"));
                }

                let pks: Result<Vec<Pk>, _> = top.args[1..].iter().map(|sub|
                    expression::terminal(sub, Pk::from_str)
                ).collect();

                pks.map(|pks| AstElem::ThreshM(k, pks))
            },
            _ => Err(Error::Unexpected(format!(
                "{}({} args) while parsing Miniscript",
                top.name,
                top.args.len(),
            ))),
        }?;
        for ch in frag_wrap.chars().rev() {
            match ch {
                'a' => unwrapped = AstElem::Alt(Box::new(unwrapped)),
                's' => unwrapped = AstElem::Swap(Box::new(unwrapped)),
                'c' => unwrapped = AstElem::Check(Box::new(unwrapped)),
                'd' => unwrapped = AstElem::DupIf(Box::new(unwrapped)),
                'v' => unwrapped = AstElem::Verify(Box::new(unwrapped)),
                'j' => unwrapped = AstElem::NonZero(Box::new(unwrapped)),
                'u' => unwrapped = AstElem::ZeroNotEqual(Box::new(unwrapped)),
                x => return Err(Error::UnknownWrapper(x)),
            }
        }
        Ok(unwrapped)
    }
}

/// Helper trait to add a `push_astelem` method to `script::Builder`
trait PushAstElem<Pk, Pkh> {
    fn push_astelem(self, ast: &AstElem<Pk, Pkh>) -> Self;
}

trait BadTrait {
    fn push_verify(self) -> Self;
}

impl<Pk, Pkh> PushAstElem<Pk, Pkh> for script::Builder where
    Pk: ToPublicKey,
    Pkh: ToPublicKeyHash
{
    fn push_astelem(self, ast: &AstElem<Pk, Pkh>) -> Self {
        ast.encode(self)
    }
}

impl BadTrait for script::Builder {
    fn push_verify(self) -> Self {
        // FIXME
        use std::mem;
        unsafe {
            let mut v: Vec<u8> = mem::transmute(self);
            match v.pop() {
                None => v.push(0x69),
                Some(0x87) => v.push(0x88),
                Some(0x9c) => v.push(0x9d),
                Some(0xac) => v.push(0xad),
                Some(0xae) => v.push(0xaf),
                Some(x) => {
                    v.push(x);
                    v.push(0x69);
                }
            }
            mem::transmute(v)
        }
    }
}

impl<Pk: ToPublicKey, Pkh: ToPublicKeyHash> AstElem<Pk, Pkh> {
    /// Encode the element as a fragment of Bitcoin Script. The inverse
    /// function, from Script to an AST element, is implemented in the
    /// `parse` module.
    pub fn encode(&self, mut builder: script::Builder) -> script::Builder {
        match *self {
            AstElem::Pk(ref pk) => builder.push_key(&pk.to_public_key()),
            AstElem::PkH(ref hash) => builder
                .push_opcode(opcodes::all::OP_DUP)
                .push_opcode(opcodes::all::OP_HASH160)
                .push_slice(&hash.to_public_key_hash()[..])
                .push_opcode(opcodes::all::OP_EQUALVERIFY),
            AstElem::After(t) => builder
                .push_int(t as i64)
                .push_opcode(opcodes::OP_CSV),
            AstElem::Older(t) => builder
                .push_int(t as i64)
                .push_opcode(opcodes::OP_CLTV),
            AstElem::Sha256(h) => builder
                .push_opcode(opcodes::all::OP_SIZE)
                .push_int(32)
                .push_opcode(opcodes::all::OP_EQUALVERIFY)
                .push_opcode(opcodes::all::OP_SHA256)
                .push_slice(&h[..])
                .push_opcode(opcodes::all::OP_EQUAL),
            AstElem::Hash256(h) => builder
                .push_opcode(opcodes::all::OP_SIZE)
                .push_int(32)
                .push_opcode(opcodes::all::OP_EQUALVERIFY)
                .push_opcode(opcodes::all::OP_HASH256)
                .push_slice(&h[..])
                .push_opcode(opcodes::all::OP_EQUAL),
            AstElem::Ripemd160(h) => builder
                .push_opcode(opcodes::all::OP_SIZE)
                .push_int(32)
                .push_opcode(opcodes::all::OP_EQUALVERIFY)
                .push_opcode(opcodes::all::OP_RIPEMD160)
                .push_slice(&h[..])
                .push_opcode(opcodes::all::OP_EQUAL),
            AstElem::Hash160(h) => builder
                .push_opcode(opcodes::all::OP_SIZE)
                .push_int(32)
                .push_opcode(opcodes::all::OP_EQUALVERIFY)
                .push_opcode(opcodes::all::OP_HASH160)
                .push_slice(&h[..])
                .push_opcode(opcodes::all::OP_EQUAL),
            AstElem::True => builder.push_opcode(opcodes::OP_TRUE),
            AstElem::False => builder.push_opcode(opcodes::OP_FALSE),
            AstElem::Alt(ref sub) => builder
                .push_opcode(opcodes::all::OP_TOALTSTACK)
                .push_astelem(sub)
                .push_opcode(opcodes::all::OP_FROMALTSTACK),
            AstElem::Swap(ref sub) => builder
                .push_opcode(opcodes::all::OP_SWAP)
                .push_astelem(sub),
            AstElem::Check(ref sub) => builder
                .push_astelem(sub)
                .push_opcode(opcodes::all::OP_CHECKSIG),
            AstElem::DupIf(ref sub) => builder
                .push_opcode(opcodes::all::OP_DUP)
                .push_opcode(opcodes::all::OP_IF)
                .push_astelem(sub)
                .push_opcode(opcodes::all::OP_ENDIF),
            AstElem::Verify(ref sub) => builder
                .push_astelem(sub)
                .push_verify(),
            AstElem::NonZero(ref sub) => builder
                .push_opcode(opcodes::all::OP_SIZE)
                .push_opcode(opcodes::all::OP_0NOTEQUAL)
                .push_opcode(opcodes::all::OP_IF)
                .push_astelem(sub)
                .push_opcode(opcodes::all::OP_ENDIF),
            AstElem::ZeroNotEqual(ref sub) => builder
                .push_astelem(sub)
                .push_opcode(opcodes::all::OP_0NOTEQUAL),
            AstElem::AndV(ref left, ref right) => builder
                .push_astelem(left)
                .push_astelem(right),
            AstElem::AndB(ref left, ref right) => builder
                .push_astelem(left)
                .push_astelem(right)
                .push_opcode(opcodes::all::OP_BOOLAND),
            AstElem::AndOr(ref a, ref b, ref c) => builder
                .push_astelem(a)
                .push_opcode(opcodes::all::OP_NOTIF)
                .push_astelem(b)
                .push_opcode(opcodes::all::OP_ELSE)
                .push_astelem(c)
                .push_opcode(opcodes::all::OP_ENDIF),
            AstElem::OrB(ref left, ref right) => builder
                .push_astelem(left)
                .push_astelem(right)
                .push_opcode(opcodes::all::OP_BOOLOR),
            AstElem::OrD(ref left, ref right) => builder
                .push_astelem(left)
                .push_opcode(opcodes::all::OP_IFDUP)
                .push_opcode(opcodes::all::OP_NOTIF)
                .push_astelem(right)
                .push_opcode(opcodes::all::OP_ENDIF),
            AstElem::OrC(ref left, ref right) => builder
                .push_astelem(left)
                .push_opcode(opcodes::all::OP_NOTIF)
                .push_astelem(right)
                .push_opcode(opcodes::all::OP_ENDIF),
            AstElem::OrI(ref left, ref right) => builder
                .push_opcode(opcodes::all::OP_IF)
                .push_astelem(left)
                .push_opcode(opcodes::all::OP_ELSE)
                .push_astelem(right)
                .push_opcode(opcodes::all::OP_ENDIF),
            AstElem::Thresh(k, ref subs) => {
                builder = builder.push_astelem(&subs[0]);
                for sub in &subs[1..] {
                    builder = builder
                        .push_astelem(sub)
                        .push_opcode(opcodes::all::OP_ADD);
                }
                builder
                    .push_int(k as i64)
                    .push_opcode(opcodes::all::OP_EQUAL)
            },
            AstElem::ThreshM(k, ref keys) => {
                builder = builder.push_int(k as i64);
                for pk in keys {
                    builder = builder.push_key(&pk.to_public_key());
                }
                builder
                    .push_int(keys.len() as i64)
                    .push_opcode(opcodes::all::OP_CHECKMULTISIG)
            },
        }
    }

    /// Size, in bytes of the script-pubkey. If this Miniscript is used outside
    /// of segwit (e.g. in a bare or P2SH descriptor), this quantity should be
    /// multiplied by 4 to compute the weight.
    ///
    /// In general, it is not recommended to use this function directly, but
    /// to instead call the corresponding function on a `Descriptor`, which
    /// will handle the segwit/non-segwit technicalities for you.
    pub fn script_size(&self) -> usize {
        match *self {
            AstElem::Pk(ref pk) => pk.serialized_len(),
            AstElem::PkH(..) => 24,
            AstElem::After(n) => script_num_size(n as usize) + 1,
            AstElem::Older(n) => script_num_size(n as usize) + 1,
            AstElem::Sha256(..) => 33 + 6,
            AstElem::Hash256(..) => 33 + 6,
            AstElem::Ripemd160(..) => 21 + 6,
            AstElem::Hash160(..) => 21 + 6,
            AstElem::True => 1,
            AstElem::False => 1,
            AstElem::Alt(ref sub) => sub.script_size() + 2,
            AstElem::Swap(ref sub) => sub.script_size() + 1,
            AstElem::Check(ref sub) => sub.script_size() + 1,
            AstElem::DupIf(ref sub) => sub.script_size() + 3,
            AstElem::Verify(ref sub) => sub.script_size() +
                match **sub {
                    AstElem::Sha256(..) |
                    AstElem::Hash256(..) |
                    AstElem::Ripemd160(..) |
                    AstElem::Hash160(..) |
                    AstElem::Check(..) |
                    AstElem::ThreshM(..) => 0,
                    _ => 1,
                },
            AstElem::NonZero(ref sub) => sub.script_size() + 4,
            AstElem::ZeroNotEqual(ref sub) => sub.script_size() + 1,
            AstElem::AndV(ref l, ref r) => l.script_size() + r.script_size(),
            AstElem::AndB(ref l, ref r) => l.script_size() + r.script_size() + 1,
            AstElem::AndOr(ref a, ref b, ref c) => a.script_size()
                + b.script_size()
                + c.script_size()
                + 3,
            AstElem::OrB(ref l, ref r) => l.script_size() + r.script_size() + 1,
            AstElem::OrD(ref l, ref r) => l.script_size() + r.script_size() + 3,
            AstElem::OrC(ref l, ref r) => l.script_size() + r.script_size() + 2,
            AstElem::OrI(ref l, ref r) => l.script_size() + r.script_size() + 3,
            AstElem::Thresh(k, ref subs) => {
                assert!(!subs.is_empty(), "threshold must be nonempty");
                script_num_size(k) // k
                    + 1 // EQUAL
                    + subs.iter().map(|s| s.script_size()).sum::<usize>()
                    + subs.len() // ADD
                    - 1 // no ADD on first element
            }
            AstElem::ThreshM(k, ref pks) => script_num_size(k)
                + 1
                + script_num_size(pks.len())
                + pks.iter().map(ToPublicKey::serialized_len).sum::<usize>(),
        }
    }

    /// Maximum number of witness elements used to dissatisfy the Miniscript
    /// fragment. Used to estimate the weight of the `VarInt` that specifies
    /// this number in a serialized transaction.
    ///
    /// Will panic if the fragment is not an E, W or Ke.
    pub fn max_dissatisfaction_witness_elements(&self) -> Option<usize> {
        match *self {
            AstElem::Pk(..) => Some(1),
            AstElem::False => Some(0),
            AstElem::Alt(ref sub)
                | AstElem::Swap(ref sub)
                | AstElem::Check(ref sub)
                => sub.max_dissatisfaction_witness_elements(),
            AstElem::DupIf(..)
                | AstElem::NonZero(..) => Some(1),
            AstElem::AndB(ref l, ref r) => Some(
                l.max_dissatisfaction_witness_elements()?
                    + r.max_dissatisfaction_witness_elements()?
            ),
            AstElem::AndOr(ref a, _, ref c) => Some(
                a.max_dissatisfaction_witness_elements()?
                    + c.max_dissatisfaction_witness_elements()?
            ),
            AstElem::OrB(ref l, ref r)
                | AstElem::OrD(ref l, ref r) => Some(
                    l.max_dissatisfaction_witness_elements()?
                        + r.max_dissatisfaction_witness_elements()?
                ),
            AstElem::OrI(ref l, ref r) => match (
                l.max_dissatisfaction_witness_elements(),
                r.max_dissatisfaction_witness_elements(),
            ) {
                (None, Some(r)) => Some(1 + r),
                (Some(l), None) => Some(1 + l),
                (None, None) => None,
                (..) => panic!("tried to dissatisfy or_i with both branches being dissatisfiable"),
            },
            AstElem::Thresh(_, ref subs) => {
                let mut sum = 0;
                for sub in subs {
                    match sub.max_dissatisfaction_witness_elements() {
                        Some(s) => sum += s,
                        None => return None,
                    }
                }
                Some(sum)
            },
            AstElem::ThreshM(k, _) => Some(1 + k),
            _ => None,
        }
    }

    /// Maximum dissatisfaction cost, in bytes, of a Miniscript fragment,
    /// if it is possible to compute this. This function should probably
    /// not ever be used directly. It is called from `max_satisfaction_size`.
    ///
    /// Will panic if the fragment is not E, W or Ke
    pub fn max_dissatisfaction_size(&self, one_cost: usize) -> Option<usize> {
        match *self {
            AstElem::Pk(..) => Some(1),
            AstElem::False => Some(0),
            AstElem::Alt(ref sub)
                | AstElem::Swap(ref sub)
                | AstElem::Check(ref sub)
                => sub.max_dissatisfaction_size(one_cost),
            AstElem::DupIf(..)
                | AstElem::NonZero(..) => Some(1),
            AstElem::AndB(ref l, ref r) => Some(
                l.max_dissatisfaction_size(one_cost)?
                    + r.max_dissatisfaction_size(one_cost)?
            ),
            AstElem::AndOr(ref a, _, ref c) => Some(
                a.max_dissatisfaction_size(one_cost)?
                    + c.max_dissatisfaction_size(one_cost)?
            ),
            AstElem::OrB(ref l, ref r)
                | AstElem::OrD(ref l, ref r) => Some(
                    l.max_dissatisfaction_size(one_cost)?
                        + r.max_dissatisfaction_size(one_cost)?
                ),
            AstElem::OrI(ref l, ref r) => match (
                l.max_dissatisfaction_witness_elements(),
                r.max_dissatisfaction_witness_elements(),
            ) {
                (None, Some(r)) => Some(1 + r),
                (Some(l), None) => Some(one_cost + l),
                (None, None) => None,
                (..) => panic!("tried to dissatisfy or_i with both branches being dissatisfiable"),
            },
            AstElem::Thresh(_, ref subs) => {
                let mut sum = 0;
                for sub in subs {
                    match sub.max_dissatisfaction_size(one_cost) {
                        Some(s) => sum += s,
                        None => return None,
                    }
                }
                Some(sum)
            },
            AstElem::ThreshM(k, _) => Some(1 + k),
            _ => None,
        }
    }

    /// Maximum number of witness elements used to satisfy the Miniscript
    /// fragment. Used to estimate the weight of the `VarInt` that specifies
    /// this number in a serialized transaction.
    ///
    /// This number does not include the witness script itself, so 1 needs
    /// to be added to the final result.
    pub fn max_satisfaction_witness_elements(&self) -> usize {
        match *self {
            AstElem::Pk(..) => 1,
            AstElem::PkH(..) => 2,
            AstElem::After(..)
                | AstElem::Older(..) => 0,
            AstElem::Sha256(..)
                | AstElem::Hash256(..)
                | AstElem::Ripemd160(..)
                | AstElem::Hash160(..) => 1,
            AstElem::True => 0,
            AstElem::False => 0,
            AstElem::Alt(ref sub) |
            AstElem::Swap(ref sub) |
            AstElem::Check(ref sub) => sub.max_satisfaction_witness_elements(),
            AstElem::DupIf(ref sub) => 1 + sub.max_satisfaction_witness_elements(),
            AstElem::Verify(ref sub)
                | AstElem::NonZero(ref sub)
                | AstElem::ZeroNotEqual(ref sub)
                => sub.max_satisfaction_witness_elements(),
            AstElem::AndV(ref l, ref r)
                | AstElem::AndB(ref l, ref r)
                => l.max_satisfaction_witness_elements()
                    + r.max_satisfaction_witness_elements(),
            AstElem::AndOr(ref a, ref b, ref c) => cmp::max(
                a.max_satisfaction_witness_elements()
                    + c.max_satisfaction_witness_elements(),
                b.max_satisfaction_witness_elements(),
            ),
            AstElem::OrB(ref l, ref r) => cmp::max(
                l.max_satisfaction_witness_elements()
                    + r.max_dissatisfaction_witness_elements().unwrap(),
                l.max_dissatisfaction_witness_elements().unwrap() +
                    r.max_satisfaction_witness_elements(),
            ),
            AstElem::OrD(ref l, ref r) |
            AstElem::OrC(ref l, ref r) => cmp::max(
                l.max_satisfaction_witness_elements(),
                l.max_dissatisfaction_witness_elements().unwrap() +
                    r.max_satisfaction_witness_elements(),
            ),
            AstElem::OrI(ref l, ref r) => 1 + cmp::max(
                l.max_satisfaction_witness_elements(),
                r.max_satisfaction_witness_elements(),
            ),
            AstElem::Thresh(k, ref subs) => {
                let mut sub_n = subs
                    .iter()
                    .map(|sub| (
                        sub.max_satisfaction_witness_elements(),
                        sub.max_dissatisfaction_witness_elements().unwrap(),
                    ))
                    .collect::<Vec<(usize, usize)>>();
                sub_n.sort_by_key(|&(x, y)| x - y);
                sub_n
                    .iter()
                    .rev()
                    .enumerate()
                    .map(|(n, &(x, y))|
                        if n < k {
                            x
                        } else {
                            y
                        }
                    )
                    .sum::<usize>()
            },
            AstElem::ThreshM(k, _) => 1 + k,
        }
    }

    /// Maximum size, in bytes, of a satisfying witness. For Segwit outputs
    /// `one_cost` should be set to 2, since the number `1` requires two
    /// bytes to encode. For non-segwit outputs `one_cost` should be set to
    /// 1, since `OP_1` is available in scriptSigs.
    ///
    /// In general, it is not recommended to use this function directly, but
    /// to instead call the corresponding function on a `Descriptor`, which
    /// will handle the segwit/non-segwit technicalities for you.
    ///
    /// All signatures are assumed to be 73 bytes in size, including the
    /// length prefix (segwit) or push opcode (pre-segwit) and sighash
    /// postfix.
    ///
    /// This function may panic on misformed `Miniscript` objects which do not
    /// correspond to semantically sane Scripts. (Such scripts should be rejected
    /// at parse time. Any exceptions are bugs.)
    pub fn max_satisfaction_size(&self, one_cost: usize) -> usize {
        match *self {
            AstElem::Pk(..) => 73,
            AstElem::PkH(..) => 34 + 73,
            AstElem::After(..)
                | AstElem::Older(..) => 0,
            AstElem::Sha256(..)
                | AstElem::Hash256(..)
                | AstElem::Ripemd160(..)
                | AstElem::Hash160(..) => 33,
            AstElem::True => 0,
            AstElem::False => 0,
            AstElem::Alt(ref sub)
                | AstElem::Swap(ref sub)
                | AstElem::Check(ref sub)
                => sub.max_satisfaction_size(one_cost),
            AstElem::DupIf(ref sub)
                => one_cost + sub.max_satisfaction_size(one_cost),
            AstElem::Verify(ref sub)
                | AstElem::NonZero(ref sub)
                | AstElem::ZeroNotEqual(ref sub)
                => sub.max_satisfaction_size(one_cost),
            AstElem::AndV(ref l, ref r)
                | AstElem::AndB(ref l, ref r)
                => l.max_satisfaction_size(one_cost)
                    + r.max_satisfaction_size(one_cost),
            AstElem::AndOr(ref a, ref b, ref c) => cmp::max(
                a.max_satisfaction_size(one_cost)
                    + c.max_satisfaction_size(one_cost),
                b.max_satisfaction_size(one_cost),
            ),
            AstElem::OrB(ref l, ref r) => cmp::max(
                l.max_satisfaction_size(one_cost)
                    + r.max_dissatisfaction_size(one_cost).unwrap(),
                l.max_dissatisfaction_size(one_cost).unwrap()
                    + r.max_satisfaction_size(one_cost),
            ),
            AstElem::OrD(ref l, ref r) |
            AstElem::OrC(ref l, ref r) => cmp::max(
                l.max_satisfaction_size(one_cost),
                l.max_dissatisfaction_size(one_cost).unwrap()
                    + r.max_satisfaction_size(one_cost),
            ),
            AstElem::OrI(ref l, ref r) => cmp::max(
                one_cost + l.max_satisfaction_size(one_cost),
                1 + r.max_satisfaction_size(one_cost),
            ),
            AstElem::Thresh(k, ref subs) => {
                let mut sub_n = subs
                    .iter()
                    .map(|sub| (
                        sub.max_satisfaction_size(one_cost),
                        sub.max_dissatisfaction_size(one_cost).unwrap(),
                    ))
                    .collect::<Vec<(usize, usize)>>();
                sub_n.sort_by_key(|&(x, y)| x - y);
                sub_n
                    .iter()
                    .rev()
                    .enumerate()
                    .map(|(n, &(x, y))|
                        if n < k {
                            x
                        } else {
                            y
                        }
                    )
                    .sum::<usize>()
            },
            AstElem::ThreshM(k, _) => 1 + 73 * k,
        }
    }
}

