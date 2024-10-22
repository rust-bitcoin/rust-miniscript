// SPDX-License-Identifier: CC0-1.0

//! AST Elements
//!
//! Datatype describing a Miniscript "script fragment", which are the
//! building blocks of all Miniscripts. Each fragment has a unique
//! encoding in Bitcoin script, as well as a datatype. Full details
//! are given on the Miniscript website.

use core::str::FromStr;

use bitcoin::address::script_pubkey::BuilderExt;
use bitcoin::hashes::hash160;
use bitcoin::{absolute, opcodes, script};
use sync::Arc;

use crate::miniscript::context::SigType;
use crate::miniscript::ScriptContext;
use crate::prelude::*;
use crate::util::MsKeyBuilder;
use crate::{
    expression, AbsLockTime, Error, FromStrKey, Miniscript, MiniscriptKey, RelLockTime, Terminal,
    ToPublicKey,
};

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
                .push_int_unchecked(absolute::LockTime::from(t).to_consensus_u32() as i64)
                .push_opcode(opcodes::all::OP_CLTV),
            Terminal::Older(t) => builder
                .push_int_unchecked(t.to_consensus_u32() as i64)
                .push_opcode(opcodes::all::OP_CSV),
            Terminal::Sha256(ref h) => builder
                .push_opcode(opcodes::all::OP_SIZE)
                .push_int_unchecked(32)
                .push_opcode(opcodes::all::OP_EQUALVERIFY)
                .push_opcode(opcodes::all::OP_SHA256)
                .push_slice(Pk::to_sha256(h).to_byte_array())
                .push_opcode(opcodes::all::OP_EQUAL),
            Terminal::Hash256(ref h) => builder
                .push_opcode(opcodes::all::OP_SIZE)
                .push_int_unchecked(32)
                .push_opcode(opcodes::all::OP_EQUALVERIFY)
                .push_opcode(opcodes::all::OP_HASH256)
                .push_slice(Pk::to_hash256(h).to_byte_array())
                .push_opcode(opcodes::all::OP_EQUAL),
            Terminal::Ripemd160(ref h) => builder
                .push_opcode(opcodes::all::OP_SIZE)
                .push_int_unchecked(32)
                .push_opcode(opcodes::all::OP_EQUALVERIFY)
                .push_opcode(opcodes::all::OP_RIPEMD160)
                .push_slice(Pk::to_ripemd160(h).to_byte_array())
                .push_opcode(opcodes::all::OP_EQUAL),
            Terminal::Hash160(ref h) => builder
                .push_opcode(opcodes::all::OP_SIZE)
                .push_int_unchecked(32)
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
                    .push_int_unchecked(thresh.k() as i64)
                    .push_opcode(opcodes::all::OP_EQUAL)
            }
            Terminal::Multi(ref thresh) => {
                debug_assert!(Ctx::sig_type() == SigType::Ecdsa);
                builder = builder.push_int_unchecked(thresh.k() as i64);
                for pk in thresh.data() {
                    builder = builder.push_key(pk.to_public_key());
                }
                builder
                    .push_int_unchecked(thresh.n() as i64)
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
                    .push_int_unchecked(thresh.k() as i64)
                    .push_opcode(opcodes::all::OP_NUMEQUAL)
            }
        }
    }
}
