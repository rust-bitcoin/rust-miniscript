// SPDX-License-Identifier: CC0-1.0

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{constants, PublicKey, Scalar, Secp256k1, Verification};
use bitcoin::{bip32, NetworkKind};

use super::key::{DefiniteDescriptorKey, DescriptorMusigKey};
use crate::prelude::*;

const SYNTHETIC_XPUB_CHAIN_CODE: [u8; 32] = [
    0x86, 0x80, 0x87, 0xca, 0x02, 0xa6, 0xf9, 0x74, 0xc4, 0x59, 0x89, 0x24, 0xc3, 0x6b, 0x57, 0x76,
    0x2d, 0x32, 0xcb, 0x45, 0x71, 0x71, 0x67, 0xe3, 0x00, 0x62, 0x2c, 0x71, 0x67, 0xe3, 0x89, 0x65,
];

pub(super) fn derive_public_key<C: Verification>(
    secp: &Secp256k1<C>,
    musig: &DescriptorMusigKey,
) -> bitcoin::PublicKey {
    let aggregate = aggregate_public_key(
        secp,
        musig.participants().iter().map(|participant| {
            DefiniteDescriptorKey::new(participant.clone())
                .expect("musig participants are definite")
                .derive_public_key(secp)
                .inner
        }),
    );

    let derivation_path = &musig.derivation_paths().paths()[0];
    if derivation_path.is_empty() {
        bitcoin::PublicKey::new(aggregate)
    } else {
        let network = musig.xkey_network().unwrap_or(NetworkKind::Main);
        let xpub = synthetic_xpub(aggregate, network);
        bitcoin::PublicKey::new(
            xpub.derive_pub(secp, derivation_path)
                .expect("definite musig aggregate derivation path is unhardened")
                .public_key,
        )
    }
}

fn aggregate_public_key<C, I>(secp: &Secp256k1<C>, keys: I) -> PublicKey
where
    C: Verification,
    I: IntoIterator<Item = PublicKey>,
{
    let mut keys = keys.into_iter().collect::<Vec<_>>();
    keys.sort_by_key(|key| key.serialize());
    key_agg_public_key(secp, keys)
}

fn key_agg_public_key<C, I>(secp: &Secp256k1<C>, keys: I) -> PublicKey
where
    C: Verification,
    I: IntoIterator<Item = PublicKey>,
{
    let keys = keys.into_iter().collect::<Vec<_>>();
    let key_bytes = keys.iter().map(PublicKey::serialize).collect::<Vec<_>>();
    let second_key = second_distinct_key(&key_bytes);
    let key_hash = hash_keys(&key_bytes);

    let mut weighted_keys = Vec::with_capacity(keys.len());
    for (key, key_bytes) in keys.into_iter().zip(key_bytes.iter()) {
        let coeff = if Some(key_bytes) == second_key {
            Scalar::ONE
        } else {
            key_agg_coeff(&key_hash, key_bytes)
        };
        // A zero coefficient is cryptographically unreachable for honest inputs. `mul_tweak`
        // rejects zero, while adding the identity point would not change the aggregate.
        if coeff != Scalar::ZERO {
            weighted_keys.push(
                key.mul_tweak(secp, &coeff)
                    .expect("musig key coefficient produces a valid public key"),
            );
        }
    }

    let refs = weighted_keys.iter().collect::<Vec<_>>();
    let aggregate = PublicKey::combine_keys(&refs);
    debug_assert!(aggregate.is_ok(), "BIP327 KeyAgg output is not infinity");
    // BIP327 specifies infinity as a KeyAgg failure. Descriptor public key derivation is
    // currently infallible, matching the surrounding BIP32 derivation APIs after
    // DefiniteDescriptorKey has ruled out malformed paths, so we treat this cryptographic edge as
    // unreachable here.
    aggregate.expect("BIP327 KeyAgg output is not infinity")
}

fn synthetic_xpub(public_key: PublicKey, network: NetworkKind) -> bip32::Xpub {
    bip32::Xpub {
        network,
        depth: 0,
        parent_fingerprint: Default::default(),
        child_number: bip32::ChildNumber::from_normal_idx(0).expect("0 is a valid child number"),
        public_key,
        chain_code: SYNTHETIC_XPUB_CHAIN_CODE.into(),
    }
}

fn second_distinct_key(key_bytes: &[[u8; 33]]) -> Option<&[u8; 33]> {
    key_bytes.iter().find(|key| *key != &key_bytes[0])
}

fn hash_keys(key_bytes: &[[u8; 33]]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(key_bytes.len() * 33);
    for key in key_bytes {
        bytes.extend_from_slice(key);
    }
    tagged_hash("KeyAgg list", &bytes)
}

fn key_agg_coeff(key_hash: &[u8; 32], key_bytes: &[u8; 33]) -> Scalar {
    let mut bytes = Vec::with_capacity(65);
    bytes.extend_from_slice(key_hash);
    bytes.extend_from_slice(key_bytes);
    scalar_from_hash_mod_n(tagged_hash("KeyAgg coefficient", &bytes))
}

fn tagged_hash(tag: &str, bytes: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag.as_bytes());
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_ref());
    engine.input(tag_hash.as_ref());
    engine.input(bytes);
    sha256::Hash::from_engine(engine).to_byte_array()
}

fn scalar_from_hash_mod_n(mut bytes: [u8; 32]) -> Scalar {
    // A SHA256 digest is below 2^256, which is below twice the secp256k1 group order.
    // One conditional subtraction is therefore enough to reduce this 32-byte value.
    if bytes >= constants::CURVE_ORDER {
        sub_assign_32(&mut bytes, &constants::CURVE_ORDER);
    }
    debug_assert!(bytes < constants::CURVE_ORDER);
    Scalar::from_be_bytes(bytes).expect("hash reduced modulo curve order")
}

fn sub_assign_32(lhs: &mut [u8; 32], rhs: &[u8; 32]) {
    let mut borrow = 0u16;
    for (a, b) in lhs.iter_mut().zip(rhs.iter()).rev() {
        let subtrahend = *b as u16 + borrow;
        let minuend = *a as u16;
        if minuend >= subtrahend {
            *a = (minuend - subtrahend) as u8;
            borrow = 0;
        } else {
            *a = (minuend + 256 - subtrahend) as u8;
            borrow = 1;
        }
    }
    debug_assert_eq!(borrow, 0);
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use bitcoin::bip32;
    use bitcoin::secp256k1::Secp256k1;

    use super::*;

    #[test]
    fn bip328_aggregate_key_vectors() {
        for (keys, expected_aggregate, xpub) in [
            (
                &[
                    "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
                    "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
                ][..],
                "0354240c76b8f2999143301a99c7f721ee57eee0bce401df3afeaa9ae218c70f23",
                "xpub661MyMwAqRbcFt6tk3uaczE1y6EvM1TqXvawXcYmFEWijEM4PDBnuCXwwXEKGEouzXE6QLLRxjatMcLLzJ5LV5Nib1BN7vJg6yp45yHHRbm",
            ),
            (
                &[
                    "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
                    "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                    "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66",
                ][..],
                "0290539eede565f5d054f32cc0c220126889ed1e5d193baf15aef344fe59d4610c",
                "xpub661MyMwAqRbcFt6tk3uaczE1y6EvM1TqXvawXcYmFEWijEM4PDBnuCXwwVk5TFJk8Tw5WAdV3DhrGfbFA216sE9BsQQiSFTdudkETnKdg8k",
            ),
            (
                &[
                    "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                    "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66",
                    "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
                    "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
                ][..],
                "022479f134cdb266141dab1a023cbba30a870f8995b95a91fc8464e56a7d41f8ea",
                "xpub661MyMwAqRbcFt6tk3uaczE1y6EvM1TqXvawXcYmFEWijEM4PDBnuCXwwUvaZYpysLX4wN59tjwU5pBuDjNrPEJbfxjLwn7ruzbXTcUTHkZ",
            ),
        ] {
            let secp = Secp256k1::verification_only();
            let keys = keys
                .iter()
                .map(|key| PublicKey::from_str(key).unwrap())
                .collect::<Vec<_>>();
            let aggregate = key_agg_public_key(&secp, keys);
            assert_eq!(aggregate.to_string(), expected_aggregate);
            let synthetic = synthetic_xpub(aggregate, NetworkKind::Main);
            assert_eq!(synthetic, bip32::Xpub::from_str(xpub).unwrap());
            assert_eq!(synthetic.depth, 0);
            assert_eq!(synthetic.parent_fingerprint, bip32::Fingerprint::default());
            assert_eq!(
                synthetic.child_number,
                bip32::ChildNumber::from_normal_idx(0).unwrap()
            );
            assert_eq!(synthetic.chain_code, SYNTHETIC_XPUB_CHAIN_CODE.into());
        }
    }
}
