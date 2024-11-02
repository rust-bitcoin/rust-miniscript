use std::str::FromStr;

use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::hashes::{ripemd160, sha256, Hash};
use miniscript::descriptor::DescriptorSecretKey;
use miniscript::ToPublicKey;
use secp256k1::Secp256k1;

use crate::KEYS_PER_PERSONA;

pub fn produce_grim_hash(secret: &str) -> (sha256::Hash, ripemd160::Hash) {
    let mut hash_holder = sha256::Hash::hash(secret.as_bytes());
    for _i in 0..5 {
        hash_holder = sha256::Hash::hash(hash_holder.as_byte_array());
        //println!("{} hash: {}", i, hash_holder);
    }

    let ripemd_160_final = ripemd160::Hash::hash(hash_holder.as_byte_array());
    (hash_holder, ripemd_160_final)
}

pub fn produce_kelly_hash(secret: &str) -> (sha256::Hash, sha256::Hash) {
    let prepreimage = secret.as_bytes();
    let preimage_256_hash = sha256::Hash::hash(prepreimage);
    let result256_final = sha256::Hash::hash(&preimage_256_hash.to_byte_array());
    (preimage_256_hash, result256_final)
}

pub fn produce_key_pairs(
    desc: DescriptorSecretKey,
    secp: &Secp256k1<secp256k1::All>,
    derivation_without_index: &str,
    _alias: &str,
) -> (Vec<bitcoin::PublicKey>, Vec<Xpriv>) {
    let mut pks = Vec::new();
    let mut prvs = Vec::new();

    let xprv = match &desc {
        DescriptorSecretKey::XPrv(xpriv) => xpriv,
        _ => panic!("not an xpriv"),
    };

    for i in 0..KEYS_PER_PERSONA {
        let pk = desc
            .to_public(secp)
            .unwrap()
            .at_derivation_index(i.try_into().unwrap())
            .unwrap()
            .to_public_key();

        let derivation_with_index = format!("{}/{}", derivation_without_index, i);
        let derivation_path = DerivationPath::from_str(&derivation_with_index).unwrap();
        let derived_xpriv: Xpriv = xprv.xkey.derive_priv(secp, &derivation_path).unwrap();

        pks.push(pk);
        prvs.push(derived_xpriv);
    }
    (pks, prvs)
}
