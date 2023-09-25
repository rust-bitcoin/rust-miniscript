use std::collections::BTreeMap;
use std::str::FromStr;

use bitcoin::absolute::Height;
use bitcoin::blockdata::locktime::absolute;
use bitcoin::key::TapTweak;
use bitcoin::psbt::{self, Psbt};
use bitcoin::sighash::SighashCache;
use bitcoin::{taproot, PrivateKey, ScriptBuf};
use miniscript::bitcoin::consensus::encode::deserialize;
use miniscript::bitcoin::hashes::hex::FromHex;
use miniscript::bitcoin::{
    self, base64, secp256k1, Address, Network, OutPoint, Sequence, Transaction, TxIn, TxOut,
};
use miniscript::psbt::{PsbtExt, PsbtInputExt};
use miniscript::{Descriptor, DescriptorPublicKey};
use secp256k1::Secp256k1;

fn main() {
    // Defining the descriptor keys required.
    let secp256k1 = secp256k1::Secp256k1::new();
    let keys = vec![
        "036a7ae441409bd40af1b8efba7dbd34b822b9a72566eff10b889b8de13659e343",
        "03b6c8a1a901edf3c5f1cb0e3ffe1f20393435a5d467f435e2858c9ab43d3ca78c",
        "03500a2b48b0f66c8183cc0d6645ab21cc19c7fad8a33ff04d41c3ece54b0bc1c5",
        "033ad2d191da4f39512adbaac320cae1f12f298386a4e9d43fd98dec7cf5db2ac9",
        "023fc33527afab09fa97135f2180bcd22ce637b1d2fbcb2db748b1f2c33f45b2b4",
    ];

    // The taproot descriptor combines different spending paths and conditions, allowing the funds to be spent using
    // different methods depending on the desired conditions.

    // tr({A},{{pkh({B}),{{multi_a(1,{C},{D}),and_v(v:pk({E}),after(10))}}}}) represents a taproot spending policy.
    // Let's break it down:
    //
    // * Key Spend Path
    // {A} represents the public key for the taproot key spending path.
    //
    // * Script Spend Paths
    // {B} represents the public key for the pay-to-pubkey-hash (P2PKH) spending path.
    // The multi_a(1,{C},{D}) construct represents a 1-of-2 multi-signature script condition.
    // It requires at least one signature from {C} and {D} to spend funds using the script spend path.
    // The and_v(v:pk({E}),after(10)) construct represents a combination of a P2PK script condition and a time lock.
    // It requires a valid signature from {E} and enforces a time lock of 10 blocks on spending funds.

    // By constructing transactions using this taproot descriptor and signing them appropriately,
    // you can create flexible spending policies that enable different spending paths and conditions depending on the
    // transaction's inputs and outputs.
    let s = format!(
        "tr({},{{pkh({}),{{multi_a(1,{},{}),and_v(v:pk({}),after(10))}}}})",
        keys[0], // Key A
        keys[1], // Key B
        keys[2], // Key C
        keys[3], // Key D
        keys[4], // Key E
    );

    let descriptor = Descriptor::from_str(&s).expect("parse descriptor string");
    assert!(descriptor.sanity_check().is_ok());

    println!("Descriptor pubkey script: {}", descriptor.script_pubkey());
    println!("Descriptor address: {}", descriptor.address(Network::Regtest).unwrap());

    let master_private_key_str = "KxQqtbUnMugSEbKHG3saknvVYux1cgFjFqWzMfwnFhLm8QrGq26v";
    let master_private_key =
        PrivateKey::from_str(master_private_key_str).expect("Can't create private key");
    println!("Master public key: {}", master_private_key.public_key(&secp256k1));

    let backup1_private_key_str = "Kwb9oFfPNt6D3Fa9DCF5emRvLyJ3UUvCHnVxp4xf7bWDxWmeVdeH";
    let backup1_private =
        PrivateKey::from_str(backup1_private_key_str).expect("Can't create private key");

    println!("Backup1 public key: {}", backup1_private.public_key(&secp256k1));

    let backup2_private_key_str = "cPJFWUKk8sdL7pcDKrmNiWUyqgovimmhaaZ8WwsByDaJ45qLREkh";
    let backup2_private =
        PrivateKey::from_str(backup2_private_key_str).expect("Can't create private key");

    println!("Backup2 public key: {}", backup2_private.public_key(&secp256k1));

    let backup3_private_key_str = "cT5cH9UVm81W5QAf5KABXb23RKNSMbMzMx85y6R2mF42L94YwKX6";
    let _backup3_private =
        PrivateKey::from_str(backup3_private_key_str).expect("Can't create private key");

    println!("Backup3 public key: {}", _backup3_private.public_key(&secp256k1));

    // Create a spending transaction
    let spend_tx = Transaction {
        version: 2,
        lock_time: absolute::LockTime::Blocks(Height::ZERO),
        input: vec![],
        output: vec![],
    };

    let hex_tx = "020000000001018ff27041f3d738f5f84fd5ee62f1c5b36afebfb15f6da0c9d1382ddd0eaaa23c0000000000feffffff02b3884703010000001600142ca3b4e53f17991582d47b15a053b3201891df5200e1f5050000000022512061763f4288d086c0347c4e3c387ce22ab9372cecada6c326e77efd57e9a5ea460247304402207b820860a9d425833f729775880b0ed59dd12b64b9a3d1ab677e27e4d6b370700220576003163f8420fe0b9dc8df726cff22cbc191104a2d4ae4f9dfedb087fcec72012103817e1da42a7701df4db94db8576f0e3605f3ab3701608b7e56f92321e4d8999100000000";
    let depo_tx: Transaction = deserialize(&Vec::<u8>::from_hex(hex_tx).unwrap()).unwrap();

    let receiver = Address::from_str("bcrt1qsdks5za4t6sevaph6tz9ddfjzvhkdkxe9tfrcy").unwrap();

    let amount = 100000000;

    let (outpoint, witness_utxo) = get_vout(&depo_tx, descriptor.script_pubkey());

    let all_assets = Descriptor::<DescriptorPublicKey>::from_str(&s)
        .unwrap()
        .all_assets()
        .unwrap();

    for asset in all_assets {
        // Creating a PSBT Object
        let mut psbt = Psbt {
            unsigned_tx: spend_tx.clone(),
            unknown: BTreeMap::new(),
            proprietary: BTreeMap::new(),
            xpub: BTreeMap::new(),
            version: 0,
            inputs: vec![],
            outputs: vec![],
        };

        // Defining the Transaction Input
        let mut txin = TxIn::default();
        txin.previous_output = outpoint;
        txin.sequence = Sequence::from_height(26); //Sequence::MAX; //
        psbt.unsigned_tx.input.push(txin);

        // Defining the Transaction Output
        psbt.unsigned_tx.output.push(TxOut {
            script_pubkey: receiver.payload.script_pubkey(),
            value: amount / 5 - 500,
        });

        psbt.unsigned_tx
            .output
            .push(TxOut { script_pubkey: descriptor.script_pubkey(), value: amount * 4 / 5 });

        // Consider that out of all the keys required to sign the descriptor spend path we only have some handful of assets.
        // We can plan the PSBT with only few assets(keys or hashes) if that are enough for satisfying any policy.
        //
        // Here for example assume that we only have two keys available.
        // Key A and Key B (as seen from the descriptor above)
        // We have to add the keys to `Asset` and then obtain plan with only available signatures if  the descriptor can be satisfied.

        // Obtain the Plan based on available Assets
        let plan = descriptor.clone().plan(&asset).unwrap();

        // Creating PSBT Input
        let mut input = psbt::Input::default();
        plan.update_psbt_input(&mut input);

        // Update the PSBT input from the result which we have obtained from the Plan.
        input.update_with_descriptor_unchecked(&descriptor).unwrap();
        input.witness_utxo = Some(witness_utxo.clone());

        // Push the PSBT Input and declare an PSBT Output Structure
        psbt.inputs.push(input);
        psbt.outputs.push(psbt::Output::default());

        // Use private keys to sign
        let key_a = master_private_key.inner;
        let key_b = backup1_private.inner;

        // Taproot script can be signed when we have either Key spend or Script spend or both.
        // Here you can try to verify by commenting one of the spend path or try signing with both.
        sign_taproot_psbt(&key_a, &mut psbt, &secp256k1); // Key Spend - With Key A
        sign_taproot_psbt(&key_b, &mut psbt, &secp256k1); // Script Spend - With Key B

        // Serializing and finalizing the PSBT Transaction
        let serialized = psbt.serialize();
        println!("{}", base64::encode(&serialized));
        psbt.finalize_mut(&secp256k1).unwrap();

        let tx = psbt.extract_tx();
        println!("{}", bitcoin::consensus::encode::serialize_hex(&tx));
    }
}

// Siging the Taproot PSBT Transaction
fn sign_taproot_psbt(
    secret_key: &secp256k1::SecretKey,
    psbt: &mut psbt::Psbt,
    secp256k1: &Secp256k1<secp256k1::All>,
) {
    // Creating signing entitites required
    let hash_ty = bitcoin::sighash::TapSighashType::Default;
    let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);

    // Defining Keypair for given private key
    let keypair = secp256k1::KeyPair::from_seckey_slice(&secp256k1, secret_key.as_ref()).unwrap();

    // Checking if leaf hash exist or not.
    // For Key Spend -> Leaf Hash is None
    // For Script Spend -> Leaf Hash is Some(_)
    // Convert this leaf_hash tree to a full map.
    let (leaf_hashes, (_, _)) = &psbt.inputs[0].tap_key_origins[&keypair.x_only_public_key().0];
    let leaf_hash = if !leaf_hashes.is_empty() {
        Some(leaf_hashes[0])
    } else {
        None
    };

    let keypair = match leaf_hash {
        None => keypair
            .tap_tweak(&secp256k1, psbt.inputs[0].tap_merkle_root)
            .to_inner(), // tweak for key spend
        Some(_) => keypair, // no tweak for script spend
    };

    // Construct the message to input for schnorr signature
    let msg = psbt
        .sighash_msg(0, &mut sighash_cache, leaf_hash)
        .unwrap()
        .to_secp_msg();
    let sig = secp256k1.sign_schnorr(&msg, &keypair);
    let (pk, _parity) = keypair.x_only_public_key();
    assert!(secp256k1.verify_schnorr(&sig, &msg, &pk).is_ok());

    // Create final signature with corresponding hash type
    let final_signature1 = taproot::Signature { hash_ty, sig };

    if let Some(lh) = leaf_hash {
        // Script Spend
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk, lh), final_signature1);
    } else {
        // Key Spend
        psbt.inputs[0].tap_key_sig = Some(final_signature1);
        println!("{:#?}", psbt);
    }
}

// Find the Outpoint by spk
fn get_vout(tx: &Transaction, spk: ScriptBuf) -> (OutPoint, TxOut) {
    for (i, txout) in tx.clone().output.into_iter().enumerate() {
        if spk == txout.script_pubkey {
            return (OutPoint::new(tx.txid(), i as u32), txout);
        }
    }
    panic!("Only call get vout on functions which have the expected outpoint");
}
