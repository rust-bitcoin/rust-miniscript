// SPDX-License-Identifier: CC0-1.0

use core::convert::TryFrom;

use bitcoin::hashes::Hash;
use bitcoin::script::{self, PushBytes, ScriptBuf};
use bitcoin::PubkeyHash;

use crate::miniscript::context;
use crate::miniscript::satisfy::Placeholder;
use crate::prelude::*;
use crate::{MiniscriptKey, ScriptContext, ToPublicKey};
pub(crate) fn varint_len(n: usize) -> usize { bitcoin::VarInt(n as u64).size() }

pub(crate) trait ItemSize {
    fn size(&self) -> usize;
}

impl<Pk: MiniscriptKey> ItemSize for Placeholder<Pk> {
    fn size(&self) -> usize {
        match self {
            Placeholder::Pubkey(_, size) => *size,
            Placeholder::PubkeyHash(_, size) => *size,
            Placeholder::EcdsaSigPk(_) | Placeholder::EcdsaSigPkHash(_) => 73,
            Placeholder::SchnorrSigPk(_, _, size) | Placeholder::SchnorrSigPkHash(_, _, size) => {
                size + 1
            } // +1 for the OP_PUSH
            Placeholder::HashDissatisfaction
            | Placeholder::Sha256Preimage(_)
            | Placeholder::Hash256Preimage(_)
            | Placeholder::Ripemd160Preimage(_)
            | Placeholder::Hash160Preimage(_) => 33,
            Placeholder::PushOne => 2, // On legacy this should be 1 ?
            Placeholder::PushZero => 1,
            Placeholder::TapScript(s) => s.len(),
            Placeholder::TapControlBlock(cb) => cb.serialize().len(),
        }
    }
}

impl ItemSize for Vec<u8> {
    fn size(&self) -> usize { self.len() }
}

// Helper function to calculate witness size
pub(crate) fn witness_size<T: ItemSize>(wit: &[T]) -> usize {
    wit.iter().map(T::size).sum::<usize>() + varint_len(wit.len())
}

pub(crate) fn witness_to_scriptsig(witness: &[Vec<u8>]) -> ScriptBuf {
    let mut b = script::Builder::new();
    for wit in witness {
        if let Ok(n) = script::read_scriptint(wit) {
            b = b.push_int(n);
        } else {
            let push = <&PushBytes>::try_from(wit.as_slice())
                .expect("All pushes in miniscript are <73 bytes");
            b = b.push_slice(push)
        }
    }
    b.into_script()
}

// trait for pushing key that depend on context
pub(crate) trait MsKeyBuilder {
    /// Serialize the key as bytes based on script context. Used when encoding miniscript into bitcoin script
    fn push_ms_key<Pk, Ctx>(self, key: &Pk) -> Self
    where
        Pk: ToPublicKey,
        Ctx: ScriptContext;

    /// Serialize the key hash as bytes based on script context. Used when encoding miniscript into bitcoin script
    fn push_ms_key_hash<Pk, Ctx>(self, key: &Pk) -> Self
    where
        Pk: ToPublicKey,
        Ctx: ScriptContext;
}

impl MsKeyBuilder for script::Builder {
    fn push_ms_key<Pk, Ctx>(self, key: &Pk) -> Self
    where
        Pk: ToPublicKey,
        Ctx: ScriptContext,
    {
        match Ctx::sig_type() {
            context::SigType::Ecdsa => self.push_key(&key.to_public_key()),
            context::SigType::Schnorr => self.push_slice(key.to_x_only_pubkey().serialize()),
        }
    }

    fn push_ms_key_hash<Pk, Ctx>(self, key: &Pk) -> Self
    where
        Pk: ToPublicKey,
        Ctx: ScriptContext,
    {
        match Ctx::sig_type() {
            context::SigType::Ecdsa => self.push_slice(key.to_public_key().pubkey_hash()),
            context::SigType::Schnorr => {
                self.push_slice(PubkeyHash::hash(&key.to_x_only_pubkey().serialize()))
            }
        }
    }
}
