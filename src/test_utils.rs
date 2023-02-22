// SPDX-License-Identifier: CC0-1.0

//! Generally useful utilities for test scripts

use std::collections::HashMap;
use std::str::FromStr;

use bitcoin::hashes::{hash160, ripemd160, sha256};
use bitcoin::key::XOnlyPublicKey;
use bitcoin::secp256k1;

use crate::miniscript::context::SigType;
use crate::{hash256, ToPublicKey, Translator};

/// Translate from a String MiniscriptKey type to bitcoin::PublicKey
/// If the hashmap is populated, this will lookup for keys in HashMap
/// Otherwise, this will return a translation to a random key
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct StrKeyTranslator {
    pub pk_map: HashMap<String, bitcoin::PublicKey>,
    pub pkh_map: HashMap<String, hash160::Hash>,
    pub sha256_map: HashMap<String, sha256::Hash>,
    pub ripemd160_map: HashMap<String, ripemd160::Hash>,
    pub hash160_map: HashMap<String, hash160::Hash>,
}

impl Translator<String, bitcoin::PublicKey, ()> for StrKeyTranslator {
    fn pk(&mut self, pk: &String) -> Result<bitcoin::PublicKey, ()> {
        let key = self.pk_map.get(pk).copied().unwrap_or_else(|| {
            bitcoin::PublicKey::from_str(
                "02c2122e30e73f7fe37986e3f81ded00158e94b7ad472369b83bbdd28a9a198a39",
            )
            .unwrap()
        });
        Ok(key)
    }

    fn sha256(&mut self, _sha256: &String) -> Result<sha256::Hash, ()> {
        let hash = sha256::Hash::from_str(
            "4ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260",
        )
        .unwrap();
        Ok(hash)
    }

    fn hash256(&mut self, _hash256: &String) -> Result<hash256::Hash, ()> {
        // hard coded value
        let hash = hash256::Hash::from_str(
            "4ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260",
        )
        .unwrap();
        Ok(hash)
    }

    fn ripemd160(&mut self, _ripemd160: &String) -> Result<ripemd160::Hash, ()> {
        let hash = ripemd160::Hash::from_str("4ae81572f06e1b88fd5ced7a1a00094543a0069").unwrap();
        Ok(hash)
    }

    fn hash160(&mut self, _hash160: &String) -> Result<hash160::Hash, ()> {
        let hash = hash160::Hash::from_str("4ae81572f06e1b88fd5ced7a1a00094543a0069").unwrap();
        Ok(hash)
    }
}

/// Same as [`StrKeyTranslator`], but for [`bitcoin::XOnlyPublicKey`]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct StrXOnlyKeyTranslator {
    pub pk_map: HashMap<String, XOnlyPublicKey>,
    pub pkh_map: HashMap<String, hash160::Hash>,
    pub sha256_map: HashMap<String, sha256::Hash>,
    pub ripemd160_map: HashMap<String, ripemd160::Hash>,
    pub hash160_map: HashMap<String, hash160::Hash>,
}

impl Translator<String, XOnlyPublicKey, ()> for StrXOnlyKeyTranslator {
    fn pk(&mut self, pk: &String) -> Result<XOnlyPublicKey, ()> {
        let key = self.pk_map.get(pk).copied().unwrap_or_else(|| {
            XOnlyPublicKey::from_str(
                "c2122e30e73f7fe37986e3f81ded00158e94b7ad472369b83bbdd28a9a198a39",
            )
            .unwrap()
        });
        Ok(key)
    }

    fn sha256(&mut self, _sha256: &String) -> Result<sha256::Hash, ()> {
        let hash = sha256::Hash::from_str(
            "4ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260",
        )
        .unwrap();
        Ok(hash)
    }

    fn hash256(&mut self, _hash256: &String) -> Result<hash256::Hash, ()> {
        let hash = hash256::Hash::from_str(
            "4ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260",
        )
        .unwrap();
        Ok(hash)
    }

    fn ripemd160(&mut self, _ripemd160: &String) -> Result<ripemd160::Hash, ()> {
        let hash = ripemd160::Hash::from_str("4ae81572f06e1b88fd5ced7a1a00094543a0069").unwrap();
        Ok(hash)
    }

    fn hash160(&mut self, _hash160: &String) -> Result<hash160::Hash, ()> {
        let hash = hash160::Hash::from_str("4ae81572f06e1b88fd5ced7a1a00094543a0069").unwrap();
        Ok(hash)
    }
}

// Deterministically sample keys to allow reproducible tests
fn random_sks(n: usize) -> Vec<secp256k1::SecretKey> {
    let mut sk = [0; 32];
    let mut sks = vec![];
    for i in 1..n + 1 {
        sk[0] = i as u8;
        sk[1] = (i >> 8) as u8;
        sk[2] = (i >> 16) as u8;
        sk[3] = (i >> 24) as u8;

        let sk = secp256k1::SecretKey::from_slice(&sk[..]).expect("secret key");
        sks.push(sk)
    }
    sks
}

impl StrKeyTranslator {
    pub fn new() -> Self {
        let secp = secp256k1::Secp256k1::new();
        let sks = random_sks(26);
        let pks: Vec<_> = sks
            .iter()
            .map(|sk| bitcoin::PublicKey::new(secp256k1::PublicKey::from_secret_key(&secp, sk)))
            .collect();
        let mut pk_map = HashMap::new();
        let mut pkh_map = HashMap::new();
        for (i, c) in (b'A'..=b'Z').enumerate() {
            let key = String::from_utf8(vec![c]).unwrap();
            pk_map.insert(key.clone(), pks[i]);
            pkh_map.insert(key, pks[i].to_pubkeyhash(SigType::Ecdsa));
        }
        // We don't bother filling in sha256_map preimages in default implementation as it not unnecessary
        // for sane miniscripts
        Self {
            pk_map,
            pkh_map,
            sha256_map: HashMap::new(),
            ripemd160_map: HashMap::new(),
            hash160_map: HashMap::new(),
        }
    }
}

impl StrXOnlyKeyTranslator {
    pub fn new() -> Self {
        let secp = secp256k1::Secp256k1::new();
        let sks = random_sks(26);
        let pks: Vec<_> = sks
            .iter()
            .map(|sk| {
                let keypair = secp256k1::KeyPair::from_secret_key(&secp, sk);
                let (pk, _parity) = XOnlyPublicKey::from_keypair(&keypair);
                pk
            })
            .collect();
        let mut pk_map = HashMap::new();
        let mut pkh_map = HashMap::new();
        for (i, c) in (b'A'..b'Z').enumerate() {
            let key = String::from_utf8(vec![c]).unwrap();
            pk_map.insert(key.clone(), pks[i]);
            pkh_map.insert(key, pks[i].to_pubkeyhash(SigType::Schnorr));
        }
        // We don't bother filling in sha256_map preimages in default implementation as it not unnecessary
        // for sane miniscripts
        Self {
            pk_map,
            pkh_map,
            sha256_map: HashMap::new(),
            ripemd160_map: HashMap::new(),
            hash160_map: HashMap::new(),
        }
    }
}
