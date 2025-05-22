#![allow(unexpected_cfgs)]

use std::sync::atomic::{AtomicUsize, Ordering};

use descriptor_fuzz::FuzzPk;
use honggfuzz::fuzz;
use miniscript::bitcoin::hashes::hash160;
use miniscript::bitcoin::locktime::{absolute, relative};
use miniscript::bitcoin::taproot::Signature;
use miniscript::bitcoin::{secp256k1, PublicKey, TapLeafHash, TapSighashType, XOnlyPublicKey};
use miniscript::{Miniscript, Satisfier, Segwitv0, Tap};

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
        let ms = match s.parse::<Miniscript<FuzzPk, Segwitv0>>() {
            Ok(d) => d,
            Err(_) => return,
        };

        let _ = ms.build_template(&fuzz_sat);
    } else {
        let ms = match s.parse::<Miniscript<FuzzPk, Tap>>() {
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
    use miniscript::hex;

    #[test]
    fn duplicate_crash() {
        let v = hex::decode_to_vec("abcd").unwrap();
        super::do_test(&v);
    }
}
