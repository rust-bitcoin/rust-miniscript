extern crate miniscript;
extern crate rand;

use miniscript::miniscript::satisfy::bitcoinsig_from_rawsig;
use miniscript::Segwitv0;
use miniscript::{
    bitcoin, BitcoinSig, DummyKey, DummyKeyHash, Miniscript, NullCtx, Satisfier, ToPublicKey,
};
use rand::prelude::random;

use bitcoin::hashes::{hash160, ripemd160, sha256, sha256d};

use rand::Rng;
use std::str::FromStr;
use std::thread;

type DummyScript = Miniscript<DummyKey, Segwitv0>;

struct DummySatisfier {}

fn rand_bool() -> bool {
    random()
}

fn rand_preimage() -> Option<[u8; 32]> {
    if rand_bool() {
        Some([0u8; 32])
    } else {
        None
    }
}

impl Satisfier<NullCtx, DummyKey> for DummySatisfier {
    fn lookup_sig(&self, pk: &DummyKey, _to_pk_ctx: NullCtx) -> Option<BitcoinSig> {
        if rand_bool() {
            let v : Vec<u8> = bitcoin::hashes::hex::FromHex::from_hex("30440220510316cbecd5c8057783d1bf15d050e34298fe44547ad3267a1d6dbdf912064c022066ac4137a1a8dc6d5ae1c37329ea022d45a7ac5c4500c325b570e4542d5e19f801").unwrap();
            Some(bitcoinsig_from_rawsig(&v).unwrap())
        } else {
            None
        }
    }

    fn lookup_pkh_pk(&self, _: &DummyKeyHash) -> Option<DummyKey> {
        if rand_bool() {
            Some(DummyKey)
        } else {
            None
        }
    }

    fn lookup_pkh_sig(
        &self,
        _: &DummyKeyHash,
        _to_pk_ctx: NullCtx,
    ) -> Option<(bitcoin::PublicKey, BitcoinSig)> {
        if rand_bool() {
            let dummy = DummyKey;
            let v : Vec<u8> = bitcoin::hashes::hex::FromHex::from_hex("30440220510316cbecd5c8057783d1bf15d050e34298fe44547ad3267a1d6dbdf912064c022066ac4137a1a8dc6d5ae1c37329ea022d45a7ac5c4500c325b570e4542d5e19f801").unwrap();
            Some((
                dummy.to_public_key(NullCtx),
                (bitcoinsig_from_rawsig(&v).unwrap()),
            ))
        } else {
            None
        }
    }

    fn lookup_sha256(&self, _: sha256::Hash) -> Option<[u8; 32]> {
        rand_preimage()
    }

    fn lookup_hash256(&self, _: sha256d::Hash) -> Option<[u8; 32]> {
        rand_preimage()
    }

    fn lookup_ripemd160(&self, _: ripemd160::Hash) -> Option<[u8; 32]> {
        rand_preimage()
    }

    fn lookup_hash160(&self, _: hash160::Hash) -> Option<[u8; 32]> {
        rand_preimage()
    }

    fn check_older(&self, _: u32) -> bool {
        rand_bool()
    }

    fn check_after(&self, _: u32) -> bool {
        rand_bool()
    }
}

fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data);
    if let Ok(ms) = Miniscript::<DummyKey, Segwitv0>::from_str(&data_str) {
        if let Err(e) = ms.satisfy(DummySatisfier {}, NullCtx) {
            //ignore Err
        }
    }
}

#[cfg(feature = "afl")]
extern crate afl;
#[cfg(feature = "afl")]
fn main() {
    afl::read_stdio_bytes(|data| {
        do_test(&data);
    });
}

#[cfg(feature = "honggfuzz")]
#[macro_use]
extern crate honggfuzz;
#[cfg(feature = "honggfuzz")]
fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}
