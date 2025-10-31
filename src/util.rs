// SPDX-License-Identifier: CC0-1.0

use core::convert::TryFrom;

use bitcoin::blockdata::constants::MAX_REDEEM_SCRIPT_SIZE;
use bitcoin::script::{self, PushBytes, ScriptSigBuf};

use crate::miniscript::context;
use crate::miniscript::satisfy::Placeholder;
use crate::prelude::*;
use crate::{MiniscriptKey, ScriptContext, ToPublicKey};
pub(crate) fn varint_len(n: usize) -> usize { bitcoin::consensus::encode::varint_size(n as u64) }

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
            Placeholder::TapScript(s) => s.len() + varint_len(s.len()),
            Placeholder::TapControlBlock(cb) => {
                let block_len = cb.serialize().len();
                block_len + varint_len(block_len)
            }
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

pub(crate) fn witness_to_scriptsig(witness: &[Vec<u8>]) -> ScriptSigBuf {
    let mut b = script::Builder::new();
    for (i, wit) in witness.iter().enumerate() {
        if let Ok(push_bytes) = <&PushBytes>::try_from(wit.as_slice()) {
            if let Ok(n) = push_bytes.read_scriptint() {
                b = b.push_int(n as i32).expect("valid script int");
            } else {
                if i != witness.len() - 1 {
                    assert!(wit.len() < 73, "All pushes in miniscript are < 73 bytes");
                } else {
                    assert!(wit.len() <= MAX_REDEEM_SCRIPT_SIZE, "P2SH redeem script is <= 520 bytes");
                }
                b = b.push_slice(push_bytes);
            }
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

impl<T> MsKeyBuilder for script::Builder<T> {
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
                // Convert XOnly key to full public key (assuming even parity) to get hash
                let xonly = key.to_x_only_pubkey();
                let full_pk = xonly.public_key(bitcoin::secp256k1::Parity::Even);
                self.push_slice(full_pk.pubkey_hash())
            }
        }
    }
}
