// SPDX-License-Identifier: CC0-1.0

use core::convert::TryFrom;

use bitcoin::hashes::Hash;
use bitcoin::script::{self, PushBytes, ScriptBuf};
use bitcoin::PubkeyHash;

use crate::miniscript::context;
use crate::miniscript::satisfy::Placeholder;
use crate::plan::Assets;
use crate::prelude::*;
use crate::{DescriptorPublicKey, MiniscriptKey, ScriptContext, ToPublicKey};
pub(crate) fn varint_len(n: usize) -> usize { bitcoin::VarInt(n as u64).len() }

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

// Helper to get all possible pairs of K of N assets
pub fn asset_combination(k: usize, dpk_v: &Vec<DescriptorPublicKey>) -> Vec<Assets> {
    let mut all_assets: Vec<Assets> = Vec::new();
    let current_assets = Assets::new();
    combine_assets(k, dpk_v, 0, current_assets, &mut all_assets);
    all_assets
}

// Combine K of N assets
pub fn combine_assets(
    k: usize,
    dpk_v: &[DescriptorPublicKey],
    index: usize,
    current_assets: Assets,
    all_assets: &mut Vec<Assets>,
) {
    if k == 0 {
        all_assets.push(current_assets);
        return;
    }
    if index >= dpk_v.len() {
        return;
    }
    combine_assets(k, dpk_v, index + 1, current_assets.clone(), all_assets);
    let mut new_asset = current_assets;
    new_asset = new_asset.add(dpk_v[index].clone());
    println!("{:#?}", new_asset);
    combine_assets(k - 1, dpk_v, index + 1, new_asset, all_assets)
}

// Do product of K combinations
pub fn get_combinations_product(values: &[u64], k: u64) -> Vec<u64> {
    let mut products = Vec::new();
    let n = values.len();

    if k == 0 {
        return vec![1]; // Empty combination has a product of 1
    }

    // Using bitwise operations to generate combinations
    let max_combinations = 1u32 << n;
    for combination_bits in 1..max_combinations {
        if combination_bits.count_ones() as usize == k as usize {
            let mut product = 1;
            for i in 0..n {
                if combination_bits & (1u32 << i) != 0 {
                    product *= values[i];
                }
            }
            products.push(product);
        }
    }

    products
}

// ways to select k things out of n
pub fn k_of_n(k: u64, n: u64) -> u64 {
    if k == 0 || k == n {
        return 1;
    }
    k_of_n(k - 1, n - 1) + k_of_n(k, n - 1)
}
