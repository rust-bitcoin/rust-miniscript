// SPDX-License-Identifier: CC0-1.0

//! Example: Signing a 2-of-3 multisignature.

use std::collections::HashMap;
use std::str::FromStr;

use bitcoin::blockdata::witness::Witness;
use bitcoin::{absolute, ecdsa, transaction, Amount, OutPoint, Sequence};

fn main() {
    let mut tx = spending_transaction();
    let pks = list_of_three_arbitrary_public_keys();
    let sig = random_signature_from_the_blockchain();

    // Descriptor for the output being spent.
    let s = format!("wsh(multi(2,{},{},{}))", pks[0], pks[1], pks[2],);
    let descriptor = miniscript::Descriptor::<bitcoin::PublicKey>::from_str(&s).unwrap();

    // Check weight for witness satisfaction cost ahead of time.
    // 106 (serialized witnessScript)
    // + 73*2 (signature length + signatures + sighash bytes) + 1 (dummy byte) = 253
    assert_eq!(descriptor.max_weight_to_satisfy().unwrap().to_wu(), 253);

    // Sometimes it is necessary to have additional information to get the
    // `bitcoin::PublicKey` from the `MiniscriptKey` which can be supplied by
    // the `to_pk_ctx` parameter. For example, when calculating the script
    // pubkey of a descriptor with xpubs, the secp context and child information
    // maybe required.

    // Observe the script properties, just for fun.
    assert_eq!(
        format!("{:x}", descriptor.script_pubkey()),
        "00200ed49b334a12c37f3df8a2974ad91ff95029215a2b53f78155be737907f06163"
    );

    assert_eq!(
        format!(
            "{:x}",
            descriptor
                .explicit_script()
                .expect("wsh descriptors have unique inner script")
        ),
        "52\
         21020202020202020202020202020202020202020202020202020202020202020202\
         21020102030405060708010203040506070801020304050607080000000000000000\
         21030102030405060708010203040506070801020304050607080000000000000000\
         53ae"
    );

    // Attempt to satisfy at age 0, height 0.
    let original_txin = tx.input[0].clone();

    let mut sigs = HashMap::<bitcoin::PublicKey, ecdsa::Signature>::new();

    // Doesn't work with no signatures.
    assert!(descriptor.satisfy(&mut tx.input[0], &sigs).is_err());
    assert_eq!(tx.input[0], original_txin);

    // ...or one signature...
    sigs.insert(pks[1], sig);
    assert!(descriptor.satisfy(&mut tx.input[0], &sigs).is_err());
    assert_eq!(tx.input[0], original_txin);

    // ...but two signatures is ok.
    sigs.insert(pks[2], sig);
    assert!(descriptor.satisfy(&mut tx.input[0], &sigs).is_ok());
    assert_ne!(tx.input[0], original_txin);
    assert_eq!(tx.input[0].witness.len(), 4); // 0, sig, sig, witness script

    // ...and even if we give it a third signature, only two are used.
    sigs.insert(pks[0], sig);
    assert!(descriptor.satisfy(&mut tx.input[0], &sigs).is_ok());
    assert_ne!(tx.input[0], original_txin);
    assert_eq!(tx.input[0].witness.len(), 4); // 0, sig, sig, witness script
}

// Transaction which spends some output.
fn spending_transaction() -> bitcoin::Transaction {
    bitcoin::Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: OutPoint::COINBASE_PREVOUT,
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: vec![bitcoin::TxOut {
            script_pubkey: bitcoin::ScriptBuf::new(),
            value: Amount::from_sat(100_000_000),
        }],
    }
}

#[rustfmt::skip]
fn list_of_three_arbitrary_public_keys() -> Vec<bitcoin::PublicKey> {
    vec![
        bitcoin::PublicKey::from_slice(&[2; 33]).expect("key 1"),
        bitcoin::PublicKey::from_slice(&[
            0x02,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]).expect("key 2"),
        bitcoin::PublicKey::from_slice(&[
            0x03,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]).expect("key 3"),
    ]
}

// Returns a signature copied at random off the blockchain; this is not actually
// a valid signature for this transaction; Miniscript does not verify the validity.
fn random_signature_from_the_blockchain() -> ecdsa::Signature {
    ecdsa::Signature {
        signature: secp256k1::ecdsa::Signature::from_str(
            "3045\
             0221\
             00f7c3648c390d87578cd79c8016940aa8e3511c4104cb78daa8fb8e429375efc1\
             0220\
             531d75c136272f127a5dc14acc0722301cbddc222262934151f140da345af177",
        )
        .unwrap(),
        sighash_type: bitcoin::sighash::EcdsaSighashType::All,
    }
}
