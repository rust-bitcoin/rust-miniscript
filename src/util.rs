// SPDX-License-Identifier: CC0-1.0

use core::convert::TryFrom;

use bitcoin::hashes::Hash;
use bitcoin::PubkeyHash;
use bitcoin::script::{self, ScriptBuf, PushBytesBuf};

use crate::miniscript::context;
use crate::prelude::*;
use crate::{ScriptContext, ToPublicKey};
pub(crate) fn varint_len(n: usize) -> usize {
    bitcoin::VarInt(n as u64).len()
}

// Helper function to calculate witness size
pub(crate) fn witness_size(wit: &[Vec<u8>]) -> usize {
    wit.iter().map(Vec::len).sum::<usize>() + varint_len(wit.len())
}

pub(crate) fn witness_to_scriptsig(witness: &[Vec<u8>]) -> ScriptBuf {
    let mut b = script::Builder::new();
    for wit in witness {
        if let Ok(n) = script::read_scriptint(wit) {
            b = b.push_int(n);
        } else {
            // FIXME: There has to be a better way than this.
            let push = PushBytesBuf::try_from(wit.clone()).expect("FIXME: Handle error");
            b = b.push_slice(&push)
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
            context::SigType::Schnorr => self.push_slice(&key.to_x_only_pubkey().serialize()),
        }
    }

    fn push_ms_key_hash<Pk, Ctx>(self, key: &Pk) -> Self
    where
        Pk: ToPublicKey,
        Ctx: ScriptContext,
    {
        match Ctx::sig_type() {
            context::SigType::Ecdsa => self.push_slice(&key.to_public_key().pubkey_hash()),
            context::SigType::Schnorr => {
                self.push_slice(&PubkeyHash::hash(&key.to_x_only_pubkey().serialize()))
            }
        }
    }
}
