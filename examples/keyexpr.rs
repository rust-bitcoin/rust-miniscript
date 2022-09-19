use core::str::FromStr;
use std::collections::HashMap;

use actual_rand;
use actual_rand::RngCore;
use bitcoin::hashes::{hash160, ripemd160, sha256};
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::{self, secp256k1, Network};
use miniscript::{hash256, Descriptor, TranslatePk, Translator};
use secp256k1::{KeyPair, Secp256k1, SecretKey};
#[cfg(feature = "std")]
use secp256k1_zkp::{Message, MusigAggNonce, MusigKeyAggCache, MusigSession};

// xonly_keys generates a pair of vector containing public keys and secret keys
fn xonly_keys(n: usize) -> (Vec<bitcoin::XOnlyPublicKey>, Vec<SecretKey>) {
    let mut pubkeys = Vec::with_capacity(n);
    let mut seckeys = Vec::with_capacity(n);
    let secp = secp256k1::Secp256k1::new();
    for _ in 0..n {
        let key_pair = KeyPair::new(&secp, &mut secp256k1::rand::thread_rng());
        let pk = XOnlyPublicKey::from_keypair(&key_pair);
        let sk = SecretKey::from_keypair(&key_pair);
        pubkeys.push(pk);
        seckeys.push(sk);
    }
    (pubkeys, seckeys)
}

// StrPkTranslator helps replacing string with actual keys in descriptor/miniscript
struct StrPkTranslator {
    pk_map: HashMap<String, bitcoin::XOnlyPublicKey>,
}

impl Translator<String, bitcoin::XOnlyPublicKey, ()> for StrPkTranslator {
    fn pk(&mut self, pk: &String) -> Result<bitcoin::XOnlyPublicKey, ()> {
        self.pk_map.get(pk).copied().ok_or(())
    }

    fn pkh(&mut self, _pkh: &String) -> Result<hash160::Hash, ()> {
        unreachable!("Policy doesn't contain any pkh fragment");
    }

    fn sha256(&mut self, _sha256: &String) -> Result<sha256::Hash, ()> {
        unreachable!("Policy does not contain any sha256 fragment");
    }

    fn hash256(&mut self, _sha256: &String) -> Result<hash256::Hash, ()> {
        unreachable!("Policy does not contain any hash256 fragment");
    }

    fn ripemd160(&mut self, _ripemd160: &String) -> Result<ripemd160::Hash, ()> {
        unreachable!("Policy does not contain any ripemd160 fragment");
    }

    fn hash160(&mut self, _hash160: &String) -> Result<hash160::Hash, ()> {
        unreachable!("Policy does not contain any hash160 fragment");
    }
}

#[cfg(not(feature = "std"))]
fn main() {}

#[cfg(feature = "std")]
fn main() {
    let desc =
        Descriptor::<String>::from_str("tr(musig(E,F),{pk(A),multi_a(1,B,musig(C,D))})").unwrap();

    // generate the public and secret keys
    let (pubkeys, seckeys) = xonly_keys(6);

    // create the hashMap (from String to XonlyPublicKey)
    let mut pk_map = HashMap::new();
    pk_map.insert("A".to_string(), pubkeys[0]);
    pk_map.insert("B".to_string(), pubkeys[1]);
    pk_map.insert("C".to_string(), pubkeys[2]);
    pk_map.insert("D".to_string(), pubkeys[3]);
    pk_map.insert("E".to_string(), pubkeys[4]);
    pk_map.insert("F".to_string(), pubkeys[5]);

    let mut t = StrPkTranslator { pk_map };
    // replace with actual keys
    let real_desc = desc.translate_pk(&mut t).unwrap();

    // bitcoin script for the descriptor
    let script = real_desc.script_pubkey();
    println!("The script is {}", script);

    // address for the descriptor (bc1...)
    let address = real_desc.address(Network::Bitcoin).unwrap();
    println!("The address is {}", address);

    let secp = Secp256k1::new();
    // we are spending with the internal key (musig(E,F))
    let key_agg_cache = MusigKeyAggCache::new(&secp, &[pubkeys[4], pubkeys[5]]);
    // aggregated publickey
    let agg_pk = key_agg_cache.agg_pk();

    let mut session_id = [0; 32];
    actual_rand::thread_rng().fill_bytes(&mut session_id);

    // msg should actually be the hash of the transaction, but we use some random
    // 32 byte array.
    let msg = Message::from_slice(&[3; 32]).unwrap();
    let mut pub_nonces = Vec::with_capacity(2);
    let mut sec_nonces = Vec::with_capacity(2);
    match &real_desc {
        Descriptor::Tr(tr) => {
            let mut ind = 4;
            for _ in tr.internal_key().iter() {
                // generate public and secret nonces
                let (sec_nonce, pub_nonce) = key_agg_cache
                    .nonce_gen(&secp, session_id, seckeys[ind], msg, None)
                    .expect("Non zero session id");
                pub_nonces.push(pub_nonce);
                sec_nonces.push(sec_nonce);
                ind += 1;
            }
        }
        _ => (),
    }

    // aggregate nonces
    let aggnonce = MusigAggNonce::new(&secp, pub_nonces.as_slice());
    let session = MusigSession::new(&secp, &key_agg_cache, aggnonce, msg, None);
    let mut partial_sigs = Vec::with_capacity(2);
    match &real_desc {
        Descriptor::Tr(tr) => {
            let mut ind = 0;
            for _ in tr.internal_key().iter() {
                // generate the partial signature for this key
                let partial_sig = session
                    .partial_sign(
                        &secp,
                        &mut sec_nonces[ind],
                        &KeyPair::from_secret_key(&secp, seckeys[4 + ind]),
                        &key_agg_cache,
                    )
                    .unwrap();
                partial_sigs.push(partial_sig);
                ind += 1;
            }
        }
        _ => (),
    }

    // aggregate the signature
    let signature = session.partial_sig_agg(partial_sigs.as_slice());
    // now verify the signature
    assert!(secp.verify_schnorr(&signature, &msg, &agg_pk).is_ok())
}
