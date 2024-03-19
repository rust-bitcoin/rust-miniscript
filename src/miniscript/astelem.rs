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
use bitcoin::{absolute, opcodes, script};
use sync::Arc;

use crate::miniscript::context::SigType;
use crate::miniscript::{types, ScriptContext};
use crate::prelude::*;
use crate::util::MsKeyBuilder;
use crate::{
    expression, AbsLockTime, Error, FromStrKey, Miniscript, MiniscriptKey, RelLockTime, Terminal,
    ToPublicKey,
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

    fn conditional_fmt(&self, f: &mut fmt::Formatter, is_debug: bool) -> fmt::Result {
        match *self {
            Terminal::PkK(ref pk) => fmt_1(f, "pk_k(", pk, is_debug),
            Terminal::PkH(ref pk) => fmt_1(f, "pk_h(", pk, is_debug),
            Terminal::RawPkH(ref pkh) => fmt_1(f, "expr_raw_pk_h(", pkh, is_debug),
            Terminal::After(ref t) => fmt_1(f, "after(", t, is_debug),
            Terminal::Older(ref t) => fmt_1(f, "older(", t, is_debug),
            Terminal::Sha256(ref h) => fmt_1(f, "sha256(", h, is_debug),
            Terminal::Hash256(ref h) => fmt_1(f, "hash256(", h, is_debug),
            Terminal::Ripemd160(ref h) => fmt_1(f, "ripemd160(", h, is_debug),
            Terminal::Hash160(ref h) => fmt_1(f, "hash160(", h, is_debug),
            Terminal::True => f.write_str("1"),
            Terminal::False => f.write_str("0"),
            Terminal::AndV(ref l, ref r) if r.node != Terminal::True => {
                fmt_2(f, "and_v(", l, r, is_debug)
            }
            Terminal::AndB(ref l, ref r) => fmt_2(f, "and_b(", l, r, is_debug),
            Terminal::AndOr(ref a, ref b, ref c) => {
                if c.node == Terminal::False {
                    fmt_2(f, "and_b(", a, b, is_debug)
                } else {
                    f.write_str("andor(")?;
                    conditional_fmt(f, a, is_debug)?;
                    f.write_str(",")?;
                    conditional_fmt(f, b, is_debug)?;
                    f.write_str(",")?;
                    conditional_fmt(f, c, is_debug)?;
                    f.write_str(")")
                }
            }
            Terminal::OrB(ref l, ref r) => fmt_2(f, "or_b(", l, r, is_debug),
            Terminal::OrD(ref l, ref r) => fmt_2(f, "or_d(", l, r, is_debug),
            Terminal::OrC(ref l, ref r) => fmt_2(f, "or_c(", l, r, is_debug),
            Terminal::OrI(ref l, ref r)
                if l.node != Terminal::False && r.node != Terminal::False =>
            {
                fmt_2(f, "or_i(", l, r, is_debug)
            }
            Terminal::Thresh(ref thresh) => {
                if is_debug {
                    fmt::Debug::fmt(&thresh.debug("thresh", true), f)
                } else {
                    fmt::Display::fmt(&thresh.display("thresh", true), f)
                }
            }
            Terminal::Multi(ref thresh) => {
                if is_debug {
                    fmt::Debug::fmt(&thresh.debug("multi", true), f)
                } else {
                    fmt::Display::fmt(&thresh.display("multi", true), f)
                }
            }
            Terminal::MultiA(ref thresh) => {
                if is_debug {
                    fmt::Debug::fmt(&thresh.debug("multi_a", true), f)
                } else {
                    fmt::Display::fmt(&thresh.display("multi_a", true), f)
                }
            }
            // wrappers
            _ => {
                if let Some((ch, sub)) = self.wrap_char() {
                    if ch == 'c' {
                        if let Terminal::PkK(ref pk) = sub.node {
                            // alias: pk(K) = c:pk_k(K)
                            return fmt_1(f, "pk(", pk, is_debug);
                        } else if let Terminal::RawPkH(ref pkh) = sub.node {
                            // `RawPkH` is currently unsupported in the descriptor spec
                            // alias: pkh(K) = c:pk_h(K)
                            // We temporarily display there using raw_pkh, but these descriptors
                            // are not defined in the spec yet. These are prefixed with `expr`
                            // in the descriptor string.
                            // We do not support parsing these descriptors yet.
                            return fmt_1(f, "expr_raw_pkh(", pkh, is_debug);
                        } else if let Terminal::PkH(ref pk) = sub.node {
                            // alias: pkh(K) = c:pk_h(K)
                            return fmt_1(f, "pkh(", pk, is_debug);
                        }
                    }

                    fmt::Write::write_char(f, ch)?;
                    match sub.node.wrap_char() {
                        None => {
                            f.write_str(":")?;
                        }
                        // Add a ':' wrapper if there are other wrappers apart from c:pk_k()
                        // tvc:pk_k() -> tv:pk()
                        Some(('c', ms)) => match ms.node {
                            Terminal::PkK(_) | Terminal::PkH(_) | Terminal::RawPkH(_) => {
                                f.write_str(":")?;
                            }
                            _ => {}
                        },
                        _ => {}
                    };
                    if is_debug {
                        write!(f, "{:?}", sub)
                    } else {
                        write!(f, "{}", sub)
                    }
                } else {
                    unreachable!();
                }
            }
        }
    }
}

fn fmt_1<D: fmt::Debug + fmt::Display>(
    f: &mut fmt::Formatter,
    name: &str,
    a: &D,
    is_debug: bool,
) -> fmt::Result {
    f.write_str(name)?;
    conditional_fmt(f, a, is_debug)?;
    f.write_str(")")
}
fn fmt_2<D: fmt::Debug + fmt::Display>(
    f: &mut fmt::Formatter,
    name: &str,
    a: &D,
    b: &D,
    is_debug: bool,
) -> fmt::Result {
    f.write_str(name)?;
    conditional_fmt(f, a, is_debug)?;
    f.write_str(",")?;
    conditional_fmt(f, b, is_debug)?;
    f.write_str(")")
}
fn conditional_fmt<D: fmt::Debug + fmt::Display>(
    f: &mut fmt::Formatter,
    data: &D,
    is_debug: bool,
) -> fmt::Result {
    if is_debug {
        fmt::Debug::fmt(data, f)
    } else {
        fmt::Display::fmt(data, f)
    }
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> fmt::Debug for Terminal<Pk, Ctx> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fn fmt_type_map(f: &mut fmt::Formatter<'_>, type_map: types::Type) -> fmt::Result {
            f.write_str(match type_map.corr.base {
                types::Base::B => "B",
                types::Base::K => "K",
                types::Base::V => "V",
                types::Base::W => "W",
            })?;
            f.write_str("/")?;
            f.write_str(match type_map.corr.input {
                types::Input::Zero => "z",
                types::Input::One => "o",
                types::Input::OneNonZero => "on",
                types::Input::Any => "",
                types::Input::AnyNonZero => "n",
            })?;
            if type_map.corr.dissatisfiable {
                f.write_str("d")?;
            }
            if type_map.corr.unit {
                f.write_str("u")?;
            }
            f.write_str(match type_map.mall.dissat {
                types::Dissat::None => "f",
                types::Dissat::Unique => "e",
                types::Dissat::Unknown => "",
            })?;
            if type_map.mall.safe {
                f.write_str("s")?;
            }
            if type_map.mall.non_malleable {
                f.write_str("m")?;
            }
            Ok(())
        }

        f.write_str("[")?;
        if let Ok(type_map) = types::Type::type_check(self) {
            fmt_type_map(f, type_map)?;
        } else {
            f.write_str("TYPECHECK FAILED")?;
        }
        f.write_str("]")?;

        self.conditional_fmt(f, true)
    }
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> fmt::Display for Terminal<Pk, Ctx> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { self.conditional_fmt(f, false) }
}

impl<Pk: FromStrKey, Ctx: ScriptContext> crate::expression::FromTree for Arc<Terminal<Pk, Ctx>> {
    fn from_tree(top: &expression::Tree) -> Result<Arc<Terminal<Pk, Ctx>>, Error> {
        Ok(Arc::new(expression::FromTree::from_tree(top)?))
    }
}

impl<Pk: FromStrKey, Ctx: ScriptContext> crate::expression::FromTree for Terminal<Pk, Ctx> {
    fn from_tree(top: &expression::Tree) -> Result<Terminal<Pk, Ctx>, Error> {
        let (frag_name, frag_wrap) = super::split_expression_name(top.name)?;
        let unwrapped = match (frag_name, top.args.len()) {
            ("expr_raw_pkh", 1) => expression::terminal(&top.args[0], |x| {
                hash160::Hash::from_str(x).map(Terminal::RawPkH)
            }),
            ("pk_k", 1) => {
                expression::terminal(&top.args[0], |x| Pk::from_str(x).map(Terminal::PkK))
            }
            ("pk_h", 1) => {
                expression::terminal(&top.args[0], |x| Pk::from_str(x).map(Terminal::PkH))
            }
            ("after", 1) => expression::terminal(&top.args[0], |x| {
                expression::parse_num(x)
                    .and_then(|x| AbsLockTime::from_consensus(x).map_err(Error::AbsoluteLockTime))
                    .map(Terminal::After)
            }),
            ("older", 1) => expression::terminal(&top.args[0], |x| {
                expression::parse_num(x)
                    .and_then(|x| RelLockTime::from_consensus(x).map_err(Error::RelativeLockTime))
                    .map(Terminal::Older)
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
                Arc::new(Miniscript::FALSE),
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
            ("thresh", _) => top
                .to_null_threshold()
                .map_err(Error::ParseThreshold)?
                .translate_by_index(|i| Miniscript::from_tree(&top.args[1 + i]).map(Arc::new))
                .map(Terminal::Thresh),
            ("multi", _) => top
                .to_null_threshold()
                .map_err(Error::ParseThreshold)?
                .translate_by_index(|i| expression::terminal(&top.args[1 + i], Pk::from_str))
                .map(Terminal::Multi),
            ("multi_a", _) => top
                .to_null_threshold()
                .map_err(Error::ParseThreshold)?
                .translate_by_index(|i| expression::terminal(&top.args[1 + i], Pk::from_str))
                .map(Terminal::MultiA),
            _ => Err(Error::Unexpected(format!(
                "{}({} args) while parsing Miniscript",
                top.name,
                top.args.len(),
            ))),
        }?;
        let ms = super::wrap_into_miniscript(unwrapped, frag_wrap)?;
        Ok(ms.node)
    }
}

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
            Terminal::Thresh(ref thresh) => {
                builder = builder.push_astelem(&thresh.data()[0]);
                for sub in &thresh.data()[1..] {
                    builder = builder.push_astelem(sub).push_opcode(opcodes::all::OP_ADD);
                }
                builder
                    .push_int(thresh.k() as i64)
                    .push_opcode(opcodes::all::OP_EQUAL)
            }
            Terminal::Multi(ref thresh) => {
                debug_assert!(Ctx::sig_type() == SigType::Ecdsa);
                builder = builder.push_int(thresh.k() as i64);
                for pk in thresh.data() {
                    builder = builder.push_key(&pk.to_public_key());
                }
                builder
                    .push_int(thresh.n() as i64)
                    .push_opcode(opcodes::all::OP_CHECKMULTISIG)
            }
            Terminal::MultiA(ref thresh) => {
                debug_assert!(Ctx::sig_type() == SigType::Schnorr);
                // keys must be atleast len 1 here, guaranteed by typing rules
                builder = builder.push_ms_key::<_, Ctx>(&thresh.data()[0]);
                builder = builder.push_opcode(opcodes::all::OP_CHECKSIG);
                for pk in thresh.iter().skip(1) {
                    builder = builder.push_ms_key::<_, Ctx>(pk);
                    builder = builder.push_opcode(opcodes::all::OP_CHECKSIGADD);
                }
                builder
                    .push_int(thresh.k() as i64)
                    .push_opcode(opcodes::all::OP_NUMEQUAL)
            }
        }
    }
}
