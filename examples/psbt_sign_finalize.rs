use std::collections::BTreeMap;
use std::str::FromStr;

use bitcoin::sighash::SighashCache;
use bitcoin::PrivateKey;
use miniscript::bitcoin::consensus::encode::deserialize;
use miniscript::bitcoin::hashes::hex::FromHex;
use miniscript::bitcoin::psbt::PartiallySignedTransaction as Psbt;
use miniscript::bitcoin::{
    self, base64, psbt, secp256k1, Address, Network, OutPoint, Script, Sequence, Transaction, TxIn,
    TxOut,
};
use miniscript::psbt::{PsbtExt, PsbtInputExt};
use miniscript::{Descriptor, DescriptorPublicKey};

fn main() {
    // Defining the descriptor keys
    let secp256k1 = secp256k1::Secp256k1::new();
    let keys = vec![
        "027a3565454fe1b749bccaef22aff72843a9c3efefd7b16ac54537a0c23f0ec0de",
        "032d672a1a91cc39d154d366cd231983661b0785c7f27bc338447565844f4a6813",
        "03417129311ed34c242c012cd0a3e0b9bca0065f742d0dfb63c78083ea6a02d4d9",
        "025a687659658baeabdfc415164528065be7bcaade19342241941e556557f01e28",
    ];
    // The wsh descriptor indicates a Witness Script Hash, meaning the descriptor is for a SegWit script.
    // wsh(or(pk(A),thresh(1,pkh(B),pkh(C),pkh(D))))

    // Let's break it down:
    // t:or_c specifies an "or" construct, which means the script can be satisfied by one of the given conditions:
    // pk(A) OR thresh(1,pkh(B),pkh(C),pkh(D))
    // Inside threshold condition atleast 1 out of all given conditions should satisfy.

    // By constructing transactions using this wsh descriptor and signing them appropriately,
    // you can create flexible spending policies that enable different spending paths and conditions depending on the
    // transaction's inputs and outputs.
    let s = format!(
        "wsh(t:or_c(pk({}),v:thresh(1,pkh({}),a:pkh({}),a:pkh({}))))",
        keys[0], // key A
        keys[1], // key B
        keys[2], // key C
        keys[3], // key D
    );
    let descriptor = Descriptor::from_str(&s).expect("parse descriptor string");

    assert!(descriptor.sanity_check().is_ok());
    println!("descriptor pubkey script: {}", descriptor.script_pubkey());
    println!("descriptor address: {}", descriptor.address(Network::Regtest).unwrap());
    println!(
        "Weight for witness satisfaction cost {}",
        descriptor.max_weight_to_satisfy().unwrap()
    );

    let master_private_key_str = "cQhdvB3McbBJdx78VSSumqoHQiSXs75qwLptqwxSQBNBMDxafvaw";
    let _master_private_key =
        PrivateKey::from_str(master_private_key_str).expect("Can't create private key");
    println!("Master public key: {}", _master_private_key.public_key(&secp256k1));

    let backup1_private_key_str = "cWA34TkfWyHa3d4Vb2jNQvsWJGAHdCTNH73Rht7kAz6vQJcassky";
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
        lock_time: bitcoin::absolute::LockTime::from_consensus(5000),
        input: vec![],
        output: vec![],
    };

    let hex_tx = "020000000001018ff27041f3d738f5f84fd5ee62f1c5b36afebfb15f6da0c9d1382ddd0eaaa23c0000000000feffffff02b3884703010000001600142ca3b4e53f17991582d47b15a053b3201891df5200e1f50500000000220020c0ebf552acd2a6f5dee4e067daaef17b3521e283aeaa44a475278617e3d2238a0247304402207b820860a9d425833f729775880b0ed59dd12b64b9a3d1ab677e27e4d6b370700220576003163f8420fe0b9dc8df726cff22cbc191104a2d4ae4f9dfedb087fcec72012103817e1da42a7701df4db94db8576f0e3605f3ab3701608b7e56f92321e4d8999100000000";
    let depo_tx: Transaction = deserialize(&Vec::<u8>::from_hex(hex_tx).unwrap()).unwrap();

    let receiver = Address::from_str("bcrt1qsdks5za4t6sevaph6tz9ddfjzvhkdkxe9tfrcy")
        .unwrap()
        .assume_checked();

    let amount = 100000000;

    let (outpoint, witness_utxo) = get_vout(&depo_tx, &descriptor.script_pubkey());

    let all_assets = Descriptor::<DescriptorPublicKey>::from_str(&s)
        .unwrap()
        .all_assets()
        .unwrap();

    for asset in all_assets {
        // Spend one input and spend one output for simplicity.
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
        psbt.unsigned_tx
            .output
            .push(TxOut { script_pubkey: receiver.script_pubkey(), value: amount / 5 - 500 });

        psbt.unsigned_tx
            .output
            .push(TxOut { script_pubkey: descriptor.script_pubkey(), value: amount * 4 / 5 });

        // Consider that out of all the keys required to sign the descriptor, we only have some handful of assets.
        // We can plan the PSBT with only few assets(keys or hashes) if that are enough for satisfying any policy.
        //
        // Here for example assume that we only have one key available i.e Key A(as seen from the descriptor above)
        // Key A is enough to satisfy the given descriptor because it is OR.
        // We have to add the key to `Asset` and then obtain plan with only available signature if  the descriptor can be satisfied.

        // Check the possible asset which we can use
        println!("{:#?}", asset);

        // Obtain the Plan based on available Assets
        let plan = descriptor.clone().plan(&asset).unwrap();

        // Creating a PSBT Input
        let mut input = psbt::Input::default();

        // Update the PSBT input from the result which we have obtained from the Plan.
        plan.update_psbt_input(&mut input);
        input.update_with_descriptor_unchecked(&descriptor).unwrap();
        input.witness_utxo = Some(witness_utxo.clone());

        // Push the PSBT Input and declare an PSBT Output Structure
        psbt.inputs.push(input);
        psbt.outputs.push(psbt::Output::default());

        let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);

        let msg = psbt
            .sighash_msg(0, &mut sighash_cache, None)
            .unwrap()
            .to_secp_msg();

        // Fixme: Take a parameter
        let hash_ty = bitcoin::sighash::EcdsaSighashType::All;

        let sk = backup1_private.inner;

        // Finally construct the signature and add to psbt
        let sig = secp256k1.sign_ecdsa(&msg, &sk);
        let key_a = backup1_private.public_key(&secp256k1);
        assert!(secp256k1.verify_ecdsa(&msg, &sig, &key_a.inner).is_ok());

        psbt.inputs[0]
            .partial_sigs
            .insert(key_a, bitcoin::ecdsa::Signature { sig, hash_ty });

        println!("{:#?}", psbt);

        let serialized = psbt.serialize();
        println!("{}", base64::encode(&serialized));

        psbt.finalize_mut(&secp256k1).unwrap();
        println!("{:#?}", psbt);

        let tx = psbt.extract_tx();
        println!("{}", bitcoin::consensus::encode::serialize_hex(&tx));
    }
}

// Find the Outpoint by spk
fn get_vout(tx: &Transaction, spk: &Script) -> (OutPoint, TxOut) {
    for (i, txout) in tx.clone().output.into_iter().enumerate() {
        if spk == &txout.script_pubkey {
            return (OutPoint::new(tx.txid(), i as u32), txout);
        }
    }
    panic!("Only call get vout on functions which have the expected outpoint");
}
