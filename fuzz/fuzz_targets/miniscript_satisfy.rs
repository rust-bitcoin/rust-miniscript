#![allow(unexpected_cfgs)]

use std::fmt;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};

use honggfuzz::fuzz;
use miniscript::bitcoin::hashes::{hash160, ripemd160, sha256, Hash};
use miniscript::bitcoin::locktime::{absolute, relative};
use miniscript::bitcoin::taproot::Signature;
use miniscript::bitcoin::{secp256k1, PublicKey, TapLeafHash, TapSighashType, XOnlyPublicKey};
use miniscript::{hash256, Miniscript, MiniscriptKey, Satisfier, Segwitv0, Tap, ToPublicKey};

// FIXME pull this out into a library used by all the fuzztests
#[derive(Clone, PartialOrd, Ord, PartialEq, Eq, Debug, Hash)]
struct FuzzPk {
    compressed: bool,
}

impl FuzzPk {
    pub fn new_from_control_byte(control: u8) -> Self { Self { compressed: control & 1 == 1 } }
}

impl FromStr for FuzzPk {
    type Err = std::num::ParseIntError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let byte = u8::from_str_radix(s, 16)?;
        Ok(Self::new_from_control_byte(byte))
    }
}

impl fmt::Display for FuzzPk {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { "[fuzz pubkey]".fmt(f) }
}

impl MiniscriptKey for FuzzPk {
    type Sha256 = u8;
    type Ripemd160 = u8;
    type Hash160 = u8;
    type Hash256 = u8;
}

impl ToPublicKey for FuzzPk {
    fn to_public_key(&self) -> PublicKey {
        let secp_pk = secp256k1::PublicKey::from_slice(&[
            0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3b, 0x78,
            0xce, 0x56, 0x3f, 0x89, 0xa0, 0xed, 0x94, 0x14, 0xf5, 0xaa, 0x28, 0xad, 0x0d, 0x96,
            0xd6, 0x79, 0x5f, 0x9c, 0x63, 0x3f, 0x39, 0x79, 0xbf, 0x72, 0xae, 0x82, 0x02, 0x98,
            0x3d, 0xc9, 0x89, 0xae, 0xc7, 0xf2, 0xff, 0x2e, 0xd9, 0x1b, 0xdd, 0x69, 0xce, 0x02,
            0xfc, 0x07, 0x00, 0xca, 0x10, 0x0e, 0x59, 0xdd, 0xf3,
        ])
        .unwrap();
        PublicKey { inner: secp_pk, compressed: self.compressed }
    }

    fn to_sha256(hash: &Self::Sha256) -> sha256::Hash { sha256::Hash::from_byte_array([*hash; 32]) }

    fn to_hash256(hash: &Self::Hash256) -> hash256::Hash {
        hash256::Hash::from_byte_array([*hash; 32])
    }

    fn to_ripemd160(hash: &Self::Ripemd160) -> ripemd160::Hash {
        ripemd160::Hash::from_byte_array([*hash; 20])
    }

    fn to_hash160(hash: &Self::Ripemd160) -> hash160::Hash {
        hash160::Hash::from_byte_array([*hash; 20])
    }
}

struct FuzzSatisfier<'b> {
    idx: AtomicUsize,
    buf: &'b [u8],
}

impl FuzzSatisfier<'_> {
    fn read_byte(&self) -> Option<u8> {
        let idx = self.idx.fetch_add(1, Ordering::SeqCst);
        self.buf.get(idx).copied()
    }
}

impl Satisfier<FuzzPk> for FuzzSatisfier<'_> {
    fn lookup_tap_key_spend_sig(&self) -> Option<Signature> {
        let b = self.read_byte()?;
        if b & 1 == 1 {
            // FIXME in later version of rust-secp we can use from_byte_array
            let secp_sig = secp256k1::schnorr::Signature::from_slice(&[0xab; 64]).unwrap();
            Some(Signature { signature: secp_sig, sighash_type: TapSighashType::Default })
        } else {
            None
        }
    }

    fn lookup_tap_leaf_script_sig(&self, _: &FuzzPk, _: &TapLeafHash) -> Option<Signature> {
        self.lookup_tap_key_spend_sig()
    }

    // todo
    //fn lookup_tap_control_block_map(
    //   &self,
    //) -> Option<&BTreeMap<ControlBlock, (ScriptBuf, LeafVersion)>>;

    #[rustfmt::skip]
    fn lookup_raw_pkh_pk(&self, _: &hash160::Hash) -> Option<PublicKey> {
        let b = self.read_byte()?;
        if b & 1 == 1 {
            // Decoding an uncompresssed key is extremely fast, while decoding
            // a compressed one is pretty slow.
            let secp_pk = secp256k1::PublicKey::from_slice(&[
                0x04,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x3b, 0x78, 0xce, 0x56, 0x3f,
                0x89, 0xa0, 0xed, 0x94, 0x14, 0xf5, 0xaa, 0x28,
                0xad, 0x0d, 0x96, 0xd6, 0x79, 0x5f, 0x9c, 0x63,

                0x3f, 0x39, 0x79, 0xbf, 0x72, 0xae, 0x82, 0x02,
                0x98, 0x3d, 0xc9, 0x89, 0xae, 0xc7, 0xf2, 0xff,
                0x2e, 0xd9, 0x1b, 0xdd, 0x69, 0xce, 0x02, 0xfc,
                0x07, 0x00, 0xca, 0x10, 0x0e, 0x59, 0xdd, 0xf3,
            ]).unwrap();

            if b & 2 == 2 {
                Some(PublicKey::new(secp_pk))
            } else{
                Some(PublicKey::new_uncompressed(secp_pk))
            }
        } else {
            None
        }
    }

    fn lookup_raw_pkh_x_only_pk(&self, h: &hash160::Hash) -> Option<XOnlyPublicKey> {
        self.lookup_raw_pkh_pk(h)
            .map(|pk| pk.inner.x_only_public_key().0)
    }

    // todo
    //fn lookup_raw_pkh_ecdsa_sig(&self, h: &hash160::Hash) -> Option<(PublicKey, ecdsa::Signature)>;

    fn lookup_raw_pkh_tap_leaf_script_sig(
        &self,
        (h, _): &(hash160::Hash, TapLeafHash),
    ) -> Option<(XOnlyPublicKey, Signature)> {
        self.lookup_raw_pkh_x_only_pk(h)
            .zip(self.lookup_tap_key_spend_sig())
    }

    fn lookup_sha256(&self, b: &u8) -> Option<[u8; 32]> {
        if *b & 1 == 1 {
            Some([*b; 32])
        } else {
            None
        }
    }

    fn lookup_hash256(&self, b: &u8) -> Option<[u8; 32]> {
        if *b & 1 == 1 {
            Some([*b; 32])
        } else {
            None
        }
    }

    fn lookup_ripemd160(&self, b: &u8) -> Option<[u8; 32]> {
        if *b & 1 == 1 {
            Some([*b; 32])
        } else {
            None
        }
    }

    fn lookup_hash160(&self, b: &u8) -> Option<[u8; 32]> {
        if *b & 1 == 1 {
            Some([*b; 32])
        } else {
            None
        }
    }

    fn check_older(&self, t: relative::LockTime) -> bool { t.to_consensus_u32() & 1 == 1 }

    fn check_after(&self, t: absolute::LockTime) -> bool { t.to_consensus_u32() & 1 == 1 }
}

fn do_test(data: &[u8]) {
    if data.len() < 3 {
        return;
    }
    let control = data[0];
    let len = (usize::from(data[1]) << 8) + usize::from(data[2]);
    if data.len() < 3 + len {
        return;
    }

    let s = &data[3..3 + len];
    let fuzz_sat = FuzzSatisfier { idx: AtomicUsize::new(0), buf: &data[3 + len..] };

    let s = String::from_utf8_lossy(s);
    if control & 1 == 1 {
        let ms = match Miniscript::<FuzzPk, Segwitv0>::from_str(&s) {
            Ok(d) => d,
            Err(_) => return,
        };

        let _ = ms.build_template(&fuzz_sat);
    } else {
        let ms = match Miniscript::<FuzzPk, Tap>::from_str(&s) {
            Ok(d) => d,
            Err(_) => return,
        };

        let _ = ms.build_template(&fuzz_sat);
    };
}

fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}

#[cfg(test)]
mod tests {
    fn extend_vec_from_hex(hex: &str, out: &mut Vec<u8>) {
        let mut b = 0;
        for (idx, c) in hex.as_bytes().iter().enumerate() {
            b <<= 4;
            match *c {
                b'A'..=b'F' => b |= c - b'A' + 10,
                b'a'..=b'f' => b |= c - b'a' + 10,
                b'0'..=b'9' => b |= c - b'0',
                _ => panic!("Bad hex"),
            }
            if (idx & 1) == 1 {
                out.push(b);
                b = 0;
            }
        }
    }

    #[test]
    fn duplicate_crash() {
        let mut a = Vec::new();
        extend_vec_from_hex("", &mut a);
        super::do_test(&a);
    }
}
