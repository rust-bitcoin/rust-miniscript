//! # Miniscript integration test file format
//!
//! This file has custom parsing for miniscripts that enables satisfier to spend transaction
//!
//! K : Compressed key available
//! K!: Compressed key with corresponding secret key unknown
//! X: X-only key available
//! X!: X-only key with corresponding secret key unknown
//!
//! Example:
//! pk(K1)/pkh(X1)/multi(n,...K3,...) represents a compressed key 'K1'/(X-only key 'X1') whose private key in known by the wallet
//! pk(K2!)/pkh(K3!)/multi(n,...K5!,...) represents a key 'K' whose private key is NOT known to the test wallet
//! sha256(H)/hash256(H)/ripemd160(H)/hash160(H) is hash node whose preimage is known to wallet
//! sha256(H!)/hash256(H!)/ripemd160(H!)/hash160(H!) is hash node whose preimage is *NOT* known to wallet
//! timelocks are taken from the transaction value.
//!
//! The keys/hashes are automatically translated so that the tests knows how to satisfy things that don't end with !
//!

use std::str::FromStr;

use actual_rand as rand;
use bitcoin::hashes::hex::ToHex;
use bitcoin::hashes::{hash160, ripemd160, sha256, Hash};
use miniscript::descriptor::{SinglePub, SinglePubKey};
use miniscript::{
    hash256, Descriptor, DescriptorPublicKey, Error, Miniscript, ScriptContext, TranslatePk,
    Translator,
};
use rand::RngCore;
#[derive(Clone, Debug)]
pub struct PubData {
    pub pks: Vec<bitcoin::PublicKey>,
    pub x_only_pks: Vec<bitcoin::XOnlyPublicKey>,
    pub sha256: sha256::Hash,
    pub hash256: hash256::Hash,
    pub ripemd160: ripemd160::Hash,
    pub hash160: hash160::Hash,
}

#[derive(Debug, Clone)]
pub struct SecretData {
    pub sks: Vec<bitcoin::secp256k1::SecretKey>,
    pub x_only_keypairs: Vec<bitcoin::KeyPair>,
    pub sha256_pre: [u8; 32],
    pub hash256_pre: [u8; 32],
    pub ripemd160_pre: [u8; 32],
    pub hash160_pre: [u8; 32],
}
#[derive(Debug, Clone)]
pub struct TestData {
    pub pubdata: PubData,
    pub secretdata: SecretData,
}

/// Obtain an insecure random public key with unknown secret key for testing
pub fn random_pk(mut seed: u8) -> bitcoin::PublicKey {
    loop {
        let mut data = [0; 33];
        for byte in &mut data[..] {
            *byte = seed;
            // totally a rng
            seed = seed.wrapping_mul(41).wrapping_add(53);
        }
        data[0] = 2 + (data[0] >> 7);
        if let Ok(key) = bitcoin::PublicKey::from_slice(&data[..33]) {
            return key;
        }
    }
}

#[allow(dead_code)]
// https://github.com/rust-lang/rust/issues/46379. The code is pub fn and integration test, but still shows warnings
/// Parse an insane miniscript into a miniscript with the format described above at file header
pub fn parse_insane_ms<Ctx: ScriptContext>(
    ms: &str,
    pubdata: &PubData,
) -> Miniscript<DescriptorPublicKey, Ctx> {
    let ms = subs_hash_frag(ms, pubdata);
    let ms =
        Miniscript::<String, Ctx>::from_str_insane(&ms).expect("only parsing valid minsicripts");
    let mut translator = StrTranslatorLoose(0, pubdata);
    let ms = ms.translate_pk(&mut translator).unwrap();
    ms
}

// Translate Str to DescriptorPublicKey
#[derive(Debug, Clone)]
struct StrDescPubKeyTranslator<'a>(usize, &'a PubData);

impl<'a> Translator<String, DescriptorPublicKey, ()> for StrDescPubKeyTranslator<'a> {
    fn pk(&mut self, pk_str: &String) -> Result<DescriptorPublicKey, ()> {
        let avail = !pk_str.ends_with("!");
        if avail {
            self.0 = self.0 + 1;
            if pk_str.starts_with("K") {
                Ok(DescriptorPublicKey::Single(SinglePub {
                    origin: None,
                    key: SinglePubKey::FullKey(self.1.pks[self.0]),
                }))
            } else if pk_str.starts_with("X") {
                Ok(DescriptorPublicKey::Single(SinglePub {
                    origin: None,
                    key: SinglePubKey::XOnly(self.1.x_only_pks[self.0]),
                }))
            } else {
                panic!("Key must start with either K or X")
            }
        } else {
            Ok(DescriptorPublicKey::Single(SinglePub {
                origin: None,
                key: SinglePubKey::FullKey(random_pk(59)),
            }))
        }
    }

    fn sha256(&mut self, sha256: &String) -> Result<sha256::Hash, ()> {
        let sha = sha256::Hash::from_str(sha256).unwrap();
        Ok(sha)
    }

    fn hash256(&mut self, hash256: &String) -> Result<hash256::Hash, ()> {
        let hash256 = hash256::Hash::from_str(hash256).unwrap();
        Ok(hash256)
    }

    fn ripemd160(&mut self, ripemd160: &String) -> Result<ripemd160::Hash, ()> {
        let ripemd160 = ripemd160::Hash::from_str(ripemd160).unwrap();
        Ok(ripemd160)
    }

    fn hash160(&mut self, hash160: &String) -> Result<hash160::Hash, ()> {
        let hash160 = hash160::Hash::from_str(hash160).unwrap();
        Ok(hash160)
    }
}

// Translate Str to DescriptorPublicKey
// Same as StrDescPubKeyTranslator, but does not panic when Key is not starting with
// K or X. This is used when testing vectors from C++ to rust
#[derive(Debug, Clone)]
struct StrTranslatorLoose<'a>(usize, &'a PubData);

impl<'a> Translator<String, DescriptorPublicKey, ()> for StrTranslatorLoose<'a> {
    fn pk(&mut self, pk_str: &String) -> Result<DescriptorPublicKey, ()> {
        let avail = !pk_str.ends_with("!");
        if avail {
            self.0 = self.0 + 1;
            if pk_str.starts_with("K") {
                Ok(DescriptorPublicKey::Single(SinglePub {
                    origin: None,
                    key: SinglePubKey::FullKey(self.1.pks[self.0]),
                }))
            } else if pk_str.starts_with("X") {
                Ok(DescriptorPublicKey::Single(SinglePub {
                    origin: None,
                    key: SinglePubKey::XOnly(self.1.x_only_pks[self.0]),
                }))
            } else {
                // Parse any other keys as known to allow compatibility with existing tests
                Ok(DescriptorPublicKey::Single(SinglePub {
                    origin: None,
                    key: SinglePubKey::FullKey(self.1.pks[self.0]),
                }))
            }
        } else {
            Ok(DescriptorPublicKey::Single(SinglePub {
                origin: None,
                key: SinglePubKey::FullKey(random_pk(59)),
            }))
        }
    }

    fn sha256(&mut self, sha256: &String) -> Result<sha256::Hash, ()> {
        let sha = sha256::Hash::from_str(sha256).unwrap();
        Ok(sha)
    }

    fn hash256(&mut self, hash256: &String) -> Result<hash256::Hash, ()> {
        let hash256 = hash256::Hash::from_str(hash256).unwrap();
        Ok(hash256)
    }

    fn ripemd160(&mut self, ripemd160: &String) -> Result<ripemd160::Hash, ()> {
        let ripemd160 = ripemd160::Hash::from_str(ripemd160).unwrap();
        Ok(ripemd160)
    }

    fn hash160(&mut self, hash160: &String) -> Result<hash160::Hash, ()> {
        let hash160 = hash160::Hash::from_str(hash160).unwrap();
        Ok(hash160)
    }
}

#[allow(dead_code)]
// https://github.com/rust-lang/rust/issues/46379. The code is pub fn and integration test, but still shows warnings
pub fn parse_test_desc(
    desc: &str,
    pubdata: &PubData,
) -> Result<Descriptor<DescriptorPublicKey>, Error> {
    let desc = subs_hash_frag(desc, pubdata);
    let desc = Descriptor::<String>::from_str(&desc)?;
    let mut translator = StrDescPubKeyTranslator(0, pubdata);
    let desc: Result<_, ()> = desc.translate_pk(&mut translator);
    Ok(desc.expect("Translate must succeed"))
}

// substitute hash fragments in the string as the per rules
fn subs_hash_frag(ms: &str, pubdata: &PubData) -> String {
    let ms = ms.replace(
        "sha256(H)",
        &format!("sha256({})", &pubdata.sha256.to_hex()),
    );
    let ms = ms.replace(
        "hash256(H)",
        &format!("hash256({})", &pubdata.hash256.into_inner().to_hex()),
    );
    let ms = ms.replace(
        "ripemd160(H)",
        &format!("ripemd160({})", &pubdata.ripemd160.to_hex()),
    );
    let ms = ms.replace(
        "hash160(H)",
        &format!("hash160({})", &pubdata.hash160.to_hex()),
    );

    let mut rand_hash32 = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut rand_hash32);

    let mut rand_hash20 = [0u8; 20];
    rand::thread_rng().fill_bytes(&mut rand_hash20);
    let ms = ms.replace("sha256(H!)", &format!("sha256({})", rand_hash32.to_hex()));
    let ms = ms.replace("hash256(H!)", &format!("hash256({})", rand_hash32.to_hex()));
    let ms = ms.replace(
        "ripemd160(H!)",
        &format!("ripemd160({})", rand_hash20.to_hex()),
    );
    let ms = ms.replace("hash160(H!)", &format!("hash160({})", rand_hash20.to_hex()));
    ms
}
