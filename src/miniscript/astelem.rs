// SPDX-License-Identifier: CC0-1.0

//! AST Elements
//!
//! Datatype describing a Miniscript "script fragment", which are the
//! building blocks of all Miniscripts. Each fragment has a unique
//! encoding in Bitcoin script, as well as a datatype. Full details
//! are given on the Miniscript website.

use core::fmt;
use core::str::FromStr;

use bitcoin::hashes::{hash160, Hash};
use bitcoin::{absolute, opcodes, script, Sequence};
use sync::Arc;

use crate::miniscript::context::SigType;
use crate::miniscript::types::{self, Property};
use crate::miniscript::ScriptContext;
use crate::plan::Assets;
use crate::prelude::*;
use crate::util::{asset_combination, get_combinations_product, k_of_n, MsKeyBuilder};
use crate::{
    errstr, expression, AbsLockTime, DescriptorPublicKey, Error, Miniscript, MiniscriptKey,
    Terminal, ToPublicKey,
};

impl<Pk: MiniscriptKey, Ctx: ScriptContext> Terminal<Pk, Ctx> {
    /// Internal helper function for displaying wrapper types; returns
    /// a character to display before the `:` as well as a reference
    /// to the wrapped type to allow easy recursion
    fn wrap_char(&self) -> Option<(char, &Arc<Miniscript<Pk, Ctx>>)> {
        match *self {
            Terminal::Alt(ref sub) => Some(('a', sub)),
            Terminal::Swap(ref sub) => Some(('s', sub)),
            Terminal::Check(ref sub) => Some(('c', sub)),
            Terminal::DupIf(ref sub) => Some(('d', sub)),
            Terminal::Verify(ref sub) => Some(('v', sub)),
            Terminal::NonZero(ref sub) => Some(('j', sub)),
            Terminal::ZeroNotEqual(ref sub) => Some(('n', sub)),
            Terminal::AndV(ref sub, ref r) if r.node == Terminal::True => Some(('t', sub)),
            Terminal::OrI(ref sub, ref r) if r.node == Terminal::False => Some(('u', sub)),
            Terminal::OrI(ref l, ref sub) if l.node == Terminal::False => Some(('l', sub)),
            _ => None,
        }
    }
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> fmt::Debug for Terminal<Pk, Ctx> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("[")?;
        if let Ok(type_map) = types::Type::type_check(self) {
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
            if sub.node.wrap_char().is_none() {
                fmt::Write::write_char(f, ':')?;
            }
            write!(f, "{:?}", sub)
        } else {
            match *self {
                Terminal::PkK(ref pk) => write!(f, "pk_k({:?})", pk),
                Terminal::PkH(ref pk) => write!(f, "pk_h({:?})", pk),
                Terminal::RawPkH(ref pkh) => write!(f, "expr_raw_pk_h({:?})", pkh),
                Terminal::After(t) => write!(f, "after({})", t),
                Terminal::Older(t) => write!(f, "older({})", t),
                Terminal::Sha256(ref h) => write!(f, "sha256({})", h),
                Terminal::Hash256(ref h) => write!(f, "hash256({})", h),
                Terminal::Ripemd160(ref h) => write!(f, "ripemd160({})", h),
                Terminal::Hash160(ref h) => write!(f, "hash160({})", h),
                Terminal::True => f.write_str("1"),
                Terminal::False => f.write_str("0"),
                Terminal::AndV(ref l, ref r) => write!(f, "and_v({:?},{:?})", l, r),
                Terminal::AndB(ref l, ref r) => write!(f, "and_b({:?},{:?})", l, r),
                Terminal::AndOr(ref a, ref b, ref c) => {
                    if c.node == Terminal::False {
                        write!(f, "and_n({:?},{:?})", a, b)
                    } else {
                        write!(f, "andor({:?},{:?},{:?})", a, b, c)
                    }
                }
                Terminal::OrB(ref l, ref r) => write!(f, "or_b({:?},{:?})", l, r),
                Terminal::OrD(ref l, ref r) => write!(f, "or_d({:?},{:?})", l, r),
                Terminal::OrC(ref l, ref r) => write!(f, "or_c({:?},{:?})", l, r),
                Terminal::OrI(ref l, ref r) => write!(f, "or_i({:?},{:?})", l, r),
                Terminal::Thresh(k, ref subs) => {
                    write!(f, "thresh({}", k)?;
                    for s in subs {
                        write!(f, ",{:?}", s)?;
                    }
                    f.write_str(")")
                }
                Terminal::Multi(k, ref keys) => {
                    write!(f, "multi({}", k)?;
                    for k in keys {
                        write!(f, ",{:?}", k)?;
                    }
                    f.write_str(")")
                }
                Terminal::MultiA(k, ref keys) => {
                    write!(f, "multi_a({}", k)?;
                    for k in keys {
                        write!(f, ",{}", k)?;
                    }
                    f.write_str(")")
                }
                _ => unreachable!(),
            }
        }
    }
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> fmt::Display for Terminal<Pk, Ctx> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Terminal::PkK(ref pk) => write!(f, "pk_k({})", pk),
            Terminal::PkH(ref pk) => write!(f, "pk_h({})", pk),
            Terminal::RawPkH(ref pkh) => write!(f, "expr_raw_pk_h({})", pkh),
            Terminal::After(t) => write!(f, "after({})", t),
            Terminal::Older(t) => write!(f, "older({})", t),
            Terminal::Sha256(ref h) => write!(f, "sha256({})", h),
            Terminal::Hash256(ref h) => write!(f, "hash256({})", h),
            Terminal::Ripemd160(ref h) => write!(f, "ripemd160({})", h),
            Terminal::Hash160(ref h) => write!(f, "hash160({})", h),
            Terminal::True => f.write_str("1"),
            Terminal::False => f.write_str("0"),
            Terminal::AndV(ref l, ref r) if r.node != Terminal::True => {
                write!(f, "and_v({},{})", l, r)
            }
            Terminal::AndB(ref l, ref r) => write!(f, "and_b({},{})", l, r),
            Terminal::AndOr(ref a, ref b, ref c) => {
                if c.node == Terminal::False {
                    write!(f, "and_n({},{})", a, b)
                } else {
                    write!(f, "andor({},{},{})", a, b, c)
                }
            }
            Terminal::OrB(ref l, ref r) => write!(f, "or_b({},{})", l, r),
            Terminal::OrD(ref l, ref r) => write!(f, "or_d({},{})", l, r),
            Terminal::OrC(ref l, ref r) => write!(f, "or_c({},{})", l, r),
            Terminal::OrI(ref l, ref r)
                if l.node != Terminal::False && r.node != Terminal::False =>
            {
                write!(f, "or_i({},{})", l, r)
            }
            Terminal::Thresh(k, ref subs) => {
                write!(f, "thresh({}", k)?;
                for s in subs {
                    write!(f, ",{}", s)?;
                }
                f.write_str(")")
            }
            Terminal::Multi(k, ref keys) => {
                write!(f, "multi({}", k)?;
                for k in keys {
                    write!(f, ",{}", k)?;
                }
                f.write_str(")")
            }
            Terminal::MultiA(k, ref keys) => {
                write!(f, "multi_a({}", k)?;
                for k in keys {
                    write!(f, ",{}", k)?;
                }
                f.write_str(")")
            }
            // wrappers
            _ => {
                if let Some((ch, sub)) = self.wrap_char() {
                    if ch == 'c' {
                        if let Terminal::PkK(ref pk) = sub.node {
                            // alias: pk(K) = c:pk_k(K)
                            return write!(f, "pk({})", pk);
                        } else if let Terminal::RawPkH(ref pkh) = sub.node {
                            // `RawPkH` is currently unsupported in the descriptor spec
                            // alias: pkh(K) = c:pk_h(K)
                            // We temporarily display there using raw_pkh, but these descriptors
                            // are not defined in the spec yet. These are prefixed with `expr`
                            // in the descriptor string.
                            // We do not support parsing these descriptors yet.
                            return write!(f, "expr_raw_pkh({})", pkh);
                        } else if let Terminal::PkH(ref pk) = sub.node {
                            // alias: pkh(K) = c:pk_h(K)
                            return write!(f, "pkh({})", pk);
                        }
                    }

                    fmt::Write::write_char(f, ch)?;
                    match sub.node.wrap_char() {
                        None => {
                            fmt::Write::write_char(f, ':')?;
                        }
                        // Add a ':' wrapper if there are other wrappers apart from c:pk_k()
                        // tvc:pk_k() -> tv:pk()
                        Some(('c', ms)) => match ms.node {
                            Terminal::PkK(_) | Terminal::PkH(_) | Terminal::RawPkH(_) => {
                                fmt::Write::write_char(f, ':')?
                            }
                            _ => {}
                        },
                        _ => {}
                    };
                    write!(f, "{}", sub)
                } else {
                    unreachable!();
                }
            }
        }
    }
}

impl_from_tree!(
    ;Ctx; ScriptContext,
    Arc<Terminal<Pk, Ctx>>,
    fn from_tree(top: &expression::Tree) -> Result<Arc<Terminal<Pk, Ctx>>, Error> {
        Ok(Arc::new(expression::FromTree::from_tree(top)?))
    }
);

impl_from_tree!(
    ;Ctx; ScriptContext,
    Terminal<Pk, Ctx>,
    fn from_tree(top: &expression::Tree) -> Result<Terminal<Pk, Ctx>, Error> {
        let mut aliased_wrap;
        let frag_name;
        let frag_wrap;
        let mut name_split = top.name.split(':');
        match (name_split.next(), name_split.next(), name_split.next()) {
            (None, _, _) => {
                frag_name = "";
                frag_wrap = "";
            }
            (Some(name), None, _) => {
                if name == "pk" {
                    frag_name = "pk_k";
                    frag_wrap = "c";
                } else if name == "pkh" {
                    frag_name = "pk_h";
                    frag_wrap = "c";
                } else {
                    frag_name = name;
                    frag_wrap = "";
                }
            }
            (Some(wrap), Some(name), None) => {
                if wrap.is_empty() {
                    return Err(Error::Unexpected(top.name.to_owned()));
                }
                if name == "pk" {
                    frag_name = "pk_k";
                    aliased_wrap = wrap.to_owned();
                    aliased_wrap.push('c');
                    frag_wrap = &aliased_wrap;
                } else if name == "pkh" {
                    frag_name = "pk_h";
                    aliased_wrap = wrap.to_owned();
                    aliased_wrap.push('c');
                    frag_wrap = &aliased_wrap;
                } else {
                    frag_name = name;
                    frag_wrap = wrap;
                }
            }
            (Some(_), Some(_), Some(_)) => {
                return Err(Error::MultiColon(top.name.to_owned()));
            }
        }
        let mut unwrapped = match (frag_name, top.args.len()) {
            ("expr_raw_pkh", 1) => expression::terminal(&top.args[0], |x| {
                hash160::Hash::from_str(x).map(Terminal::RawPkH)
            }),
            ("pk_k", 1) => {
                expression::terminal(&top.args[0], |x| Pk::from_str(x).map(Terminal::PkK))
            }
            ("pk_h", 1) => expression::terminal(&top.args[0], |x| Pk::from_str(x).map(Terminal::PkH)),
            ("after", 1) => expression::terminal(&top.args[0], |x| {
                expression::parse_num(x).map(|x| Terminal::After(AbsLockTime::from(absolute::LockTime::from_consensus(x))))
            }),
            ("older", 1) => expression::terminal(&top.args[0], |x| {
                expression::parse_num(x).map(|x| Terminal::Older(Sequence::from_consensus(x)))
            }),
            ("sha256", 1) => expression::terminal(&top.args[0], |x| {
                Pk::Sha256::from_str(x).map(Terminal::Sha256)
            }),
            ("hash256", 1) => expression::terminal(&top.args[0], |x| {
                Pk::Hash256::from_str(x).map(Terminal::Hash256)
            }),
            ("ripemd160", 1) => expression::terminal(&top.args[0], |x| {
                Pk::Ripemd160::from_str(x).map(Terminal::Ripemd160)
            }),
            ("hash160", 1) => expression::terminal(&top.args[0], |x| {
                Pk::Hash160::from_str(x).map(Terminal::Hash160)
            }),
            ("1", 0) => Ok(Terminal::True),
            ("0", 0) => Ok(Terminal::False),
            ("and_v", 2) => expression::binary(top, Terminal::AndV),
            ("and_b", 2) => expression::binary(top, Terminal::AndB),
            ("and_n", 2) => Ok(Terminal::AndOr(
                expression::FromTree::from_tree(&top.args[0])?,
                expression::FromTree::from_tree(&top.args[1])?,
                Arc::new(Miniscript::from_ast(Terminal::False)?),
            )),
            ("andor", 3) => Ok(Terminal::AndOr(
                expression::FromTree::from_tree(&top.args[0])?,
                expression::FromTree::from_tree(&top.args[1])?,
                expression::FromTree::from_tree(&top.args[2])?,
            )),
            ("or_b", 2) => expression::binary(top, Terminal::OrB),
            ("or_d", 2) => expression::binary(top, Terminal::OrD),
            ("or_c", 2) => expression::binary(top, Terminal::OrC),
            ("or_i", 2) => expression::binary(top, Terminal::OrI),
            ("thresh", n) => {
                if n == 0 {
                    return Err(errstr("no arguments given"));
                }
                let k = expression::terminal(&top.args[0], expression::parse_num)? as usize;
                if k > n - 1 {
                    return Err(errstr("higher threshold than there are subexpressions"));
                }
                if n == 1 {
                    return Err(errstr("empty thresholds not allowed in descriptors"));
                }

                let subs: Result<Vec<Arc<Miniscript<Pk, Ctx>>>, _> = top.args[1..]
                    .iter()
                    .map(expression::FromTree::from_tree)
                    .collect();

                Ok(Terminal::Thresh(k, subs?))
            }
            ("multi", n) | ("multi_a", n) => {
                if n == 0 {
                    return Err(errstr("no arguments given"));
                }
                let k = expression::terminal(&top.args[0], expression::parse_num)? as usize;
                if k > n - 1 {
                    return Err(errstr("higher threshold than there were keys in multi"));
                }

                let pks: Result<Vec<Pk>, _> = top.args[1..]
                    .iter()
                    .map(|sub| expression::terminal(sub, Pk::from_str))
                    .collect();

                if frag_name == "multi" {
                    pks.map(|pks| Terminal::Multi(k, pks))
                } else {
                    // must be multi_a
                    pks.map(|pks| Terminal::MultiA(k, pks))
                }
            }
            _ => Err(Error::Unexpected(format!(
                "{}({} args) while parsing Miniscript",
                top.name,
                top.args.len(),
            ))),
        }?;
        for ch in frag_wrap.chars().rev() {
            // Check whether the wrapper is valid under the current context
            let ms = Miniscript::from_ast(unwrapped)?;
            Ctx::check_global_validity(&ms)?;
            match ch {
                'a' => unwrapped = Terminal::Alt(Arc::new(ms)),
                's' => unwrapped = Terminal::Swap(Arc::new(ms)),
                'c' => unwrapped = Terminal::Check(Arc::new(ms)),
                'd' => unwrapped = Terminal::DupIf(Arc::new(ms)),
                'v' => unwrapped = Terminal::Verify(Arc::new(ms)),
                'j' => unwrapped = Terminal::NonZero(Arc::new(ms)),
                'n' => unwrapped = Terminal::ZeroNotEqual(Arc::new(ms)),
                't' => {
                    unwrapped = Terminal::AndV(
                        Arc::new(ms),
                        Arc::new(Miniscript::from_ast(Terminal::True)?),
                    )
                }
                'u' => {
                    unwrapped = Terminal::OrI(
                        Arc::new(ms),
                        Arc::new(Miniscript::from_ast(Terminal::False)?),
                    )
                }
                'l' => {
                    if ms.node == Terminal::False {
                        return Err(Error::LikelyFalse);
                    }
                    unwrapped = Terminal::OrI(
                        Arc::new(Miniscript::from_ast(Terminal::False)?),
                        Arc::new(ms),
                    )
                }
                x => return Err(Error::UnknownWrapper(x)),
            }
        }
        // Check whether the unwrapped miniscript is valid under the current context
        let ms = Miniscript::from_ast(unwrapped)?;
        Ctx::check_global_validity(&ms)?;
        Ok(ms.node)
    }
);

/// Helper trait to add a `push_astelem` method to `script::Builder`
trait PushAstElem<Pk: MiniscriptKey, Ctx: ScriptContext> {
    fn push_astelem(self, ast: &Miniscript<Pk, Ctx>) -> Self
    where
        Pk: ToPublicKey;
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> PushAstElem<Pk, Ctx> for script::Builder {
    fn push_astelem(self, ast: &Miniscript<Pk, Ctx>) -> Self
    where
        Pk: ToPublicKey,
    {
        ast.node.encode(self)
    }
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> Terminal<Pk, Ctx> {
    /// Encode the element as a fragment of Bitcoin Script. The inverse
    /// function, from Script to an AST element, is implemented in the
    /// `parse` module.
    pub fn encode(&self, mut builder: script::Builder) -> script::Builder
    where
        Pk: ToPublicKey,
    {
        match *self {
            Terminal::PkK(ref pk) => builder.push_ms_key::<_, Ctx>(pk),
            Terminal::PkH(ref pk) => builder
                .push_opcode(opcodes::all::OP_DUP)
                .push_opcode(opcodes::all::OP_HASH160)
                .push_ms_key_hash::<_, Ctx>(pk)
                .push_opcode(opcodes::all::OP_EQUALVERIFY),
            Terminal::RawPkH(ref hash) => builder
                .push_opcode(opcodes::all::OP_DUP)
                .push_opcode(opcodes::all::OP_HASH160)
                .push_slice(hash.to_byte_array())
                .push_opcode(opcodes::all::OP_EQUALVERIFY),
            Terminal::After(t) => builder
                .push_int(absolute::LockTime::from(t).to_consensus_u32() as i64)
                .push_opcode(opcodes::all::OP_CLTV),
            Terminal::Older(t) => builder
                .push_int(t.to_consensus_u32().into())
                .push_opcode(opcodes::all::OP_CSV),
            Terminal::Sha256(ref h) => builder
                .push_opcode(opcodes::all::OP_SIZE)
                .push_int(32)
                .push_opcode(opcodes::all::OP_EQUALVERIFY)
                .push_opcode(opcodes::all::OP_SHA256)
                .push_slice(Pk::to_sha256(h).to_byte_array())
                .push_opcode(opcodes::all::OP_EQUAL),
            Terminal::Hash256(ref h) => builder
                .push_opcode(opcodes::all::OP_SIZE)
                .push_int(32)
                .push_opcode(opcodes::all::OP_EQUALVERIFY)
                .push_opcode(opcodes::all::OP_HASH256)
                .push_slice(Pk::to_hash256(h).to_byte_array())
                .push_opcode(opcodes::all::OP_EQUAL),
            Terminal::Ripemd160(ref h) => builder
                .push_opcode(opcodes::all::OP_SIZE)
                .push_int(32)
                .push_opcode(opcodes::all::OP_EQUALVERIFY)
                .push_opcode(opcodes::all::OP_RIPEMD160)
                .push_slice(Pk::to_ripemd160(h).to_byte_array())
                .push_opcode(opcodes::all::OP_EQUAL),
            Terminal::Hash160(ref h) => builder
                .push_opcode(opcodes::all::OP_SIZE)
                .push_int(32)
                .push_opcode(opcodes::all::OP_EQUALVERIFY)
                .push_opcode(opcodes::all::OP_HASH160)
                .push_slice(Pk::to_hash160(h).to_byte_array())
                .push_opcode(opcodes::all::OP_EQUAL),
            Terminal::True => builder.push_opcode(opcodes::OP_TRUE),
            Terminal::False => builder.push_opcode(opcodes::OP_FALSE),
            Terminal::Alt(ref sub) => builder
                .push_opcode(opcodes::all::OP_TOALTSTACK)
                .push_astelem(sub)
                .push_opcode(opcodes::all::OP_FROMALTSTACK),
            Terminal::Swap(ref sub) => builder.push_opcode(opcodes::all::OP_SWAP).push_astelem(sub),
            Terminal::Check(ref sub) => builder
                .push_astelem(sub)
                .push_opcode(opcodes::all::OP_CHECKSIG),
            Terminal::DupIf(ref sub) => builder
                .push_opcode(opcodes::all::OP_DUP)
                .push_opcode(opcodes::all::OP_IF)
                .push_astelem(sub)
                .push_opcode(opcodes::all::OP_ENDIF),
            Terminal::Verify(ref sub) => builder.push_astelem(sub).push_verify(),
            Terminal::NonZero(ref sub) => builder
                .push_opcode(opcodes::all::OP_SIZE)
                .push_opcode(opcodes::all::OP_0NOTEQUAL)
                .push_opcode(opcodes::all::OP_IF)
                .push_astelem(sub)
                .push_opcode(opcodes::all::OP_ENDIF),
            Terminal::ZeroNotEqual(ref sub) => builder
                .push_astelem(sub)
                .push_opcode(opcodes::all::OP_0NOTEQUAL),
            Terminal::AndV(ref left, ref right) => builder.push_astelem(left).push_astelem(right),
            Terminal::AndB(ref left, ref right) => builder
                .push_astelem(left)
                .push_astelem(right)
                .push_opcode(opcodes::all::OP_BOOLAND),
            Terminal::AndOr(ref a, ref b, ref c) => builder
                .push_astelem(a)
                .push_opcode(opcodes::all::OP_NOTIF)
                .push_astelem(c)
                .push_opcode(opcodes::all::OP_ELSE)
                .push_astelem(b)
                .push_opcode(opcodes::all::OP_ENDIF),
            Terminal::OrB(ref left, ref right) => builder
                .push_astelem(left)
                .push_astelem(right)
                .push_opcode(opcodes::all::OP_BOOLOR),
            Terminal::OrD(ref left, ref right) => builder
                .push_astelem(left)
                .push_opcode(opcodes::all::OP_IFDUP)
                .push_opcode(opcodes::all::OP_NOTIF)
                .push_astelem(right)
                .push_opcode(opcodes::all::OP_ENDIF),
            Terminal::OrC(ref left, ref right) => builder
                .push_astelem(left)
                .push_opcode(opcodes::all::OP_NOTIF)
                .push_astelem(right)
                .push_opcode(opcodes::all::OP_ENDIF),
            Terminal::OrI(ref left, ref right) => builder
                .push_opcode(opcodes::all::OP_IF)
                .push_astelem(left)
                .push_opcode(opcodes::all::OP_ELSE)
                .push_astelem(right)
                .push_opcode(opcodes::all::OP_ENDIF),
            Terminal::Thresh(k, ref subs) => {
                builder = builder.push_astelem(&subs[0]);
                for sub in &subs[1..] {
                    builder = builder.push_astelem(sub).push_opcode(opcodes::all::OP_ADD);
                }
                builder
                    .push_int(k as i64)
                    .push_opcode(opcodes::all::OP_EQUAL)
            }
            Terminal::Multi(k, ref keys) => {
                debug_assert!(Ctx::sig_type() == SigType::Ecdsa);
                builder = builder.push_int(k as i64);
                for pk in keys {
                    builder = builder.push_key(&pk.to_public_key());
                }
                builder
                    .push_int(keys.len() as i64)
                    .push_opcode(opcodes::all::OP_CHECKMULTISIG)
            }
            Terminal::MultiA(k, ref keys) => {
                debug_assert!(Ctx::sig_type() == SigType::Schnorr);
                // keys must be atleast len 1 here, guaranteed by typing rules
                builder = builder.push_ms_key::<_, Ctx>(&keys[0]);
                builder = builder.push_opcode(opcodes::all::OP_CHECKSIG);
                for pk in keys.iter().skip(1) {
                    builder = builder.push_ms_key::<_, Ctx>(pk);
                    builder = builder.push_opcode(opcodes::all::OP_CHECKSIGADD);
                }
                builder
                    .push_int(k as i64)
                    .push_opcode(opcodes::all::OP_NUMEQUAL)
            }
        }
    }
}

impl<Ctx: ScriptContext> Terminal<DescriptorPublicKey, Ctx> {
    /// Count total possible assets
    pub fn count_assets(&self) -> u32 {
        match self {
            Terminal::True => 0,
            Terminal::False => 0,
            Terminal::PkK(_) => 1,
            Terminal::PkH(_) => 1,
            Terminal::RawPkH(_) => 1,
            Terminal::After(_) => 0,
            Terminal::Older(_) => 0,
            Terminal::Sha256(_) => 1,
            Terminal::Hash256(_) => 1,
            Terminal::Ripemd160(_) => 1,
            Terminal::Hash160(_) => 1,
            Terminal::Alt(k) => k.count_assets(),
            Terminal::Swap(k) => k.count_assets(),
            Terminal::Check(k) => k.count_assets(),
            Terminal::DupIf(k) => k.count_assets(),
            Terminal::Verify(k) => k.count_assets(),
            Terminal::NonZero(k) => k.count_assets(),
            Terminal::ZeroNotEqual(k) => k.count_assets(),
            Terminal::AndV(left, right) | Terminal::AndB(left, right) => {
                let left_count = left.count_assets();
                let right_count = right.count_assets();
                left_count * right_count
            }
            Terminal::AndOr(a, b, c) => {
                let a = a.count_assets();
                let b = b.count_assets();
                let c = c.count_assets();
                (a * b) + c
            }
            Terminal::OrB(left, right)
            | Terminal::OrC(left, right)
            | Terminal::OrD(left, right)
            | Terminal::OrI(left, right) => {
                let left_count = left.count_assets();
                let right_count = right.count_assets();
                left_count + right_count
            }
            Terminal::Thresh(k, ms_v) => {
                let mut count_array = Vec::new();
                for ms in ms_v {
                    count_array.push(ms.count_assets());
                }
                let products = get_combinations_product(&count_array, *k as u32);
                let mut total_count: u32 = 0;
                for product in products {
                    total_count += product;
                }
                total_count
            }
            Terminal::Multi(k, dpk) | Terminal::MultiA(k, dpk) => {
                let k: u32 = *k as u32;
                let n: u32 = dpk.len() as u32;
                k_of_n(k, n).unwrap()
            }
        }
    }

    /// Retrieve the assets associated with the type of miniscript element.
    pub fn all_assets(&self) -> Vec<Assets> {
        match self {
            Terminal::True => vec![Assets::new()],
            Terminal::False => Vec::new(),
            Terminal::PkK(k) => {
                let mut asset = Assets::new();
                asset = asset.add(k.clone());
                vec![asset]
            }
            Terminal::PkH(k) => {
                let mut asset = Assets::new();
                asset = asset.add(k.clone());
                vec![asset]
            }
            Terminal::RawPkH(k) => {
                let mut asset = Assets::new();
                asset = asset.add(k.clone());
                vec![asset]
            }
            Terminal::After(k) => {
                let mut asset = Assets::new();
                asset.absolute_timelock = Some(k.clone().into());
                vec![asset]
            }
            Terminal::Older(k) => {
                let mut asset = Assets::new();
                asset.relative_timelock = Some(k.clone());
                vec![asset]
            }
            Terminal::Sha256(k) => {
                let mut asset = Assets::new();
                asset = asset.add(k.clone());
                vec![asset]
            }
            Terminal::Hash256(k) => {
                let mut asset = Assets::new();
                asset = asset.add(k.clone());
                vec![asset]
            }
            Terminal::Ripemd160(k) => {
                let mut asset = Assets::new();
                asset = asset.add(k.clone());
                vec![asset]
            }
            Terminal::Hash160(k) => {
                let mut asset = Assets::new();
                asset = asset.add(k.clone());
                vec![asset]
            }
            Terminal::Alt(k) => k.all_assets(),
            Terminal::Swap(k) => k.all_assets(),
            Terminal::Check(k) => k.all_assets(),
            Terminal::DupIf(k) => k.all_assets(),
            Terminal::Verify(k) => k.all_assets(),
            Terminal::NonZero(k) => k.all_assets(),
            Terminal::ZeroNotEqual(k) => k.all_assets(),
            Terminal::AndB(left, right) | Terminal::AndV(left, right) => {
                let a = left.all_assets();
                let b = right.all_assets();
                let result: Vec<Assets> = a
                    .into_iter()
                    .flat_map(|x| {
                        b.clone().into_iter().map(move |y| {
                            let mut new_asset = Assets::new();
                            new_asset = new_asset.add(x.clone());
                            new_asset = new_asset.add(y.clone());
                            new_asset
                        })
                    })
                    .collect();
                result
            }
            Terminal::AndOr(a, b, c) => {
                let a = a.all_assets();
                let b = b.all_assets();
                let mut c = c.all_assets();
                let and: Vec<Assets> = a
                    .into_iter()
                    .flat_map(|x| {
                        b.clone().into_iter().map(move |y| {
                            let mut new_asset = Assets::new();
                            new_asset = new_asset.add(x.clone());
                            new_asset = new_asset.add(y.clone());
                            new_asset
                        })
                    })
                    .collect();
                c.extend(and);
                c
            }
            Terminal::OrB(left, right)
            | Terminal::OrC(left, right)
            | Terminal::OrD(left, right)
            | Terminal::OrI(left, right) => {
                let mut a = left.all_assets();
                let b = right.all_assets();
                a.extend(b);
                a
            }
            Terminal::Thresh(k, ms) => {
                // In order to understand working of below code consider k of n as 2 of 3 thresh policy
                // Eg : thresh(2,ms(A),ms(B),ms(C)) Here ms(A),ms(B) and ms(C) are miniscript policies
                // k = 2
                // ms = [ms(A),ms(B),ms(C)];
                // We would consider the possible combinations of k policies into the ms_v
                // here k=2 so all possible combinations of 2.
                // ms_v = [[ms(A),ms(B)],[ms(A),ms(C)],[ms(B),ms(C)]]
                // Between each set of combination we would need to do an OR
                // (i.e ms_v[0] OR ms_v[1] OR ms_v[3])
                // Now inside of each policy combination we need to have AND
                // Eg : ms_v[0] = [ms(A),ms(B)] so here -> ms(A) AND ms(B)

                let ms_v = Self::get_ms_combination_thresh(*k, ms);
                let mut result = Vec::new();
                for ms in ms_v {
                    // AND between each miniscript policy
                    let mut and: Vec<Assets> = Vec::new();
                    if let Some(first_assets) = ms.first() {
                        and = first_assets.all_assets().clone();
                    }
                    for i in ms.iter().skip(1) {
                        let i_assets = i.all_assets();
                        and = and
                            .iter()
                            .flat_map(|x| {
                                i_assets.iter().map(move |y| {
                                    let mut new_asset = x.clone();
                                    new_asset = new_asset.add(y.clone());
                                    new_asset
                                })
                            })
                            .collect();
                    }
                    // OR of possible combinations of k miniscript policies.
                    result.extend(and.clone());
                }
                result
            }
            Terminal::Multi(k, dpk_v) | Terminal::MultiA(k, dpk_v) => asset_combination(*k, dpk_v),
        }
    }

    // Helper to get all combinations of K policies of N for thresh
    fn get_ms_combination_thresh(
        k: usize,
        ms: &Vec<Arc<Miniscript<DescriptorPublicKey, Ctx>>>,
    ) -> Vec<Vec<Arc<Miniscript<DescriptorPublicKey, Ctx>>>> {
        let mut result = Vec::new();
        let mut current_combination = Vec::new();
        Self::combine_ms(0, &mut current_combination, &mut result, ms, k);
        result
    }

    // combine K policies of N for thresh
    fn combine_ms(
        start: usize,
        current_combination: &mut Vec<Arc<Miniscript<DescriptorPublicKey, Ctx>>>,
        result: &mut Vec<Vec<Arc<Miniscript<DescriptorPublicKey, Ctx>>>>,
        ms: &Vec<Arc<Miniscript<DescriptorPublicKey, Ctx>>>,
        k: usize,
    ) {
        if current_combination.len() == k {
            result.push(current_combination.clone());
            return;
        }
        for i in start..ms.len() {
            current_combination.push(ms[i].clone());
            Self::combine_ms(i + 1, current_combination, result, ms, k);
            current_combination.truncate(current_combination.len() - 1);
        }
    }
}
