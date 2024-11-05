// SPDX-License-Identifier: CC0-1.0

use core::convert::TryFrom;

use bitcoin::address::script_pubkey::BuilderExt as _;
use bitcoin::constants::MAX_REDEEM_SCRIPT_SIZE;
use bitcoin::hashes::hash160;
use bitcoin::script::{self, PushBytes, ScriptBuf};

use crate::miniscript::context;
use crate::miniscript::satisfy::Placeholder;
use crate::prelude::*;
use crate::{MiniscriptKey, ScriptContext, ToPublicKey};

// Copied from `bitcoin_internals::compact_size`.
pub(crate) fn varint_len(n: usize) -> usize {
    match n {
        0..=0xFC => 1,
        0xFD..=0xFFFF => 3,
        0x10000..=0xFFFFFFFF => 5,
        _ => 9,
    }
}

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
    let read_scriptint = |slice: &[u8]| {
        if let Ok(push) = <&PushBytes>::try_from(slice) {
            if let Ok(n) = push.read_scriptint() {
                return Some(n);
            }
        }
        None
    };

    let mut b = script::Builder::new();
    for (i, wit) in witness.iter().enumerate() {
        if let Some(n) = read_scriptint(wit) {
            // FIXME: Use `push_int` and handle errors.
            b = b.push_int_unchecked(n);
        } else {
            if i != witness.len() - 1 {
                assert!(wit.len() < 73, "All pushes in miniscript are < 73 bytes");
            } else {
                assert!(wit.len() <= MAX_REDEEM_SCRIPT_SIZE, "P2SH redeem script is <= 520 bytes");
            }
            let push = <&PushBytes>::try_from(wit.as_slice()).expect("checked above");
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
            context::SigType::Ecdsa => self.push_key(key.to_public_key()),
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
                let hash = hash160::Hash::hash(&key.to_x_only_pubkey().serialize());
                self.push_slice(
                    <&PushBytes>::try_from(hash.as_byte_array()).expect("32 bytes is fine to push"),
                )
            }
        }
    }
}
