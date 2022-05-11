//! # rust-miniscript integration test
//!
//! Read Miniscripts from file and translate into miniscripts
//! which we know how to satisfy
//!

use bitcoin::blockdata::witness::Witness;
use bitcoin::secp256k1;
use bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
use bitcoin::util::sighash::SighashCache;
use bitcoin::util::taproot::{LeafVersion, TapLeafHash};
use bitcoin::util::{psbt, sighash};
use bitcoin::{self, Amount, OutPoint, SchnorrSig, Script, Transaction, TxIn, TxOut, Txid};
use bitcoincore_rpc::{json, Client, RpcApi};
use miniscript::miniscript::iter;
use miniscript::psbt::{PsbtInputExt, PsbtExt};
use miniscript::{Descriptor, DescriptorTrait, Miniscript, ToPublicKey};
use miniscript::{MiniscriptKey, ScriptContext};
use std::collections::BTreeMap;

use crate::test_util::{self, TestData};

/// Quickly create a BTC amount.
fn btc<F: Into<f64>>(btc: F) -> Amount {
    Amount::from_btc(btc.into()).unwrap()
}

// Find the Outpoint by spk
fn get_vout(cl: &Client, txid: Txid, value: u64, spk: Script) -> (OutPoint, TxOut) {
    let tx = cl
        .get_transaction(&txid, None)
        .unwrap()
        .transaction()
        .unwrap();
    for (i, txout) in tx.output.into_iter().enumerate() {
        if txout.value == value && spk == txout.script_pubkey {
            return (OutPoint::new(txid, i as u32), txout);
        }
    }
    unreachable!("Only call get vout on functions which have the expected outpoint");
}

pub fn test_desc_satisfy(cl: &Client, testdata: &TestData, desc: &str) -> Witness {
    let secp = secp256k1::Secp256k1::new();
    let sks = &testdata.secretdata.sks;
    let xonly_keypairs = &testdata.secretdata.x_only_keypairs;
    let pks = &testdata.pubdata.pks;
    let x_only_pks = &testdata.pubdata.x_only_pks;
    // Generate some blocks
    let blocks = cl
        .generate_to_address(1, &cl.get_new_address(None, None).unwrap())
        .unwrap();
    assert_eq!(blocks.len(), 1);

    let desc = test_util::parse_test_desc(&desc, &testdata.pubdata);
    let derived_desc = desc.derived_descriptor(&secp, 0).unwrap();
    // Next send some btc to each address corresponding to the miniscript
    let txid = cl
        .send_to_address(
            &derived_desc.address(bitcoin::Network::Regtest).unwrap(),
            btc(1),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
    // Wait for the funds to mature.
    let blocks = cl
        .generate_to_address(2, &cl.get_new_address(None, None).unwrap())
        .unwrap();
    assert_eq!(blocks.len(), 2);
    // Create a PSBT for each transaction.
    // Spend one input and spend one output for simplicity.
    let mut psbt = Psbt {
        unsigned_tx: Transaction {
            version: 2,
            lock_time: 1_603_866_330, // time at 10/28/2020 @ 6:25am (UTC)
            input: vec![],
            output: vec![],
        },
        unknown: BTreeMap::new(),
        proprietary: BTreeMap::new(),
        xpub: BTreeMap::new(),
        version: 0,
        inputs: vec![],
        outputs: vec![],
    };
    // figure out the outpoint from the txid
    let (outpoint, witness_utxo) =
        get_vout(&cl, txid, btc(1.0).as_sat(), derived_desc.script_pubkey());
    let mut txin = TxIn::default();
    txin.previous_output = outpoint;
    // set the sequence to a non-final number for the locktime transactions to be
    // processed correctly.
    // We waited 2 blocks, keep 1 for safety
    txin.sequence = 1;
    psbt.unsigned_tx.input.push(txin);
    // Get a new script pubkey from the node so that
    // the node wallet tracks the receiving transaction
    // and we can check it by gettransaction RPC.
    let addr = cl
        .get_new_address(None, Some(json::AddressType::Bech32))
        .unwrap();
    psbt.unsigned_tx.output.push(TxOut {
        value: 99_999_000,
        script_pubkey: addr.script_pubkey(),
    });
    let mut input = psbt::Input::default();
    input.update_with_descriptor_unchecked(&desc).unwrap();
    input.witness_utxo = Some(witness_utxo.clone());
    psbt.inputs.push(input);
    psbt.outputs.push(psbt::Output::default());

    // --------------------------------------------
    // Sign the transactions with all keys
    // AKA the signer role of psbt
    // Get all the pubkeys and the corresponding secret keys

    let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);
    match derived_desc {
        Descriptor::Tr(tr) => {
            // Fixme: take a parameter
            let hash_ty = sighash::SchnorrSighashType::Default;

            let internal_key_present = x_only_pks
                .iter()
                .position(|&x| x.to_public_key() == *tr.internal_key());
            let internal_keypair = internal_key_present.map(|idx| xonly_keypairs[idx].clone());
            let prevouts = [witness_utxo];
            let prevouts = sighash::Prevouts::All(&prevouts);

            if let Some(mut internal_keypair) = internal_keypair {
                // ---------------------- Tr key spend --------------------
                internal_keypair
                    .tweak_add_assign(&secp, tr.spend_info().tap_tweak().as_ref())
                    .expect("Tweaking failed");
                let sighash_msg = sighash_cache
                    .taproot_key_spend_signature_hash(0, &prevouts, hash_ty)
                    .unwrap();
                let msg = secp256k1::Message::from_slice(&sighash_msg[..]).unwrap();
                let schnorr_sig = secp.sign_schnorr(&msg, &internal_keypair);
                psbt.inputs[0].tap_key_sig = Some(SchnorrSig {
                    sig: schnorr_sig,
                    hash_ty: hash_ty,
                });
            } else {
                // No internal key
            }
            // ------------------ script spend -------------
            let x_only_keypairs_reqd: Vec<(secp256k1::KeyPair, TapLeafHash)> = tr
                .iter_scripts()
                .flat_map(|(_depth, ms)| {
                    let leaf_hash = TapLeafHash::from_script(&ms.encode(), LeafVersion::TapScript);
                    ms.iter_pk_pkh().filter_map(move |pk_pkh| match pk_pkh {
                        iter::PkPkh::PlainPubkey(pk) => {
                            let i = x_only_pks.iter().position(|&x| x.to_public_key() == pk);
                            i.map(|idx| (xonly_keypairs[idx].clone(), leaf_hash))
                        }
                        iter::PkPkh::HashedPubkey(hash) => {
                            let i = x_only_pks
                                .iter()
                                .position(|&x| x.to_public_key().to_pubkeyhash() == hash);
                            i.map(|idx| (xonly_keypairs[idx].clone(), leaf_hash))
                        }
                    })
                })
                .collect();
            for (keypair, leaf_hash) in x_only_keypairs_reqd {
                let sighash_msg = sighash_cache
                    .taproot_script_spend_signature_hash(0, &prevouts, leaf_hash, hash_ty)
                    .unwrap();
                let msg = secp256k1::Message::from_slice(&sighash_msg[..]).unwrap();
                let sig = secp.sign_schnorr(&msg, &keypair);
                // FIXME: uncomment when == is supported for secp256k1::KeyPair. (next major release)
                // let x_only_pk = pks[xonly_keypairs.iter().position(|&x| x == keypair).unwrap()];
                // Just recalc public key
                let x_only_pk = secp256k1::XOnlyPublicKey::from_keypair(&keypair);
                psbt.inputs[0].tap_script_sigs.insert(
                    (x_only_pk, leaf_hash),
                    bitcoin::SchnorrSig {
                        sig,
                        hash_ty: hash_ty,
                    },
                );
            }
        }
        _ => {
            // Non-tr descriptors
            // Ecdsa sigs
            let sks_reqd = match derived_desc {
                Descriptor::Bare(bare) => find_sks_ms(&bare.as_inner(), testdata),
                Descriptor::Pkh(pk) => find_sk_single_key(*pk.as_inner(), testdata),
                Descriptor::Wpkh(pk) => find_sk_single_key(*pk.as_inner(), testdata),
                Descriptor::Sh(sh) => match sh.as_inner() {
                    miniscript::descriptor::ShInner::Wsh(wsh) => match wsh.as_inner() {
                        miniscript::descriptor::WshInner::SortedMulti(smv) => {
                            let ms = Miniscript::from_ast(smv.sorted_node()).unwrap();
                            find_sks_ms(&ms, testdata)
                        }
                        miniscript::descriptor::WshInner::Ms(ms) => find_sks_ms(&ms, testdata),
                    },
                    miniscript::descriptor::ShInner::Wpkh(pk) => {
                        find_sk_single_key(*pk.as_inner(), testdata)
                    }
                    miniscript::descriptor::ShInner::SortedMulti(smv) => {
                        let ms = Miniscript::from_ast(smv.sorted_node()).unwrap();
                        find_sks_ms(&ms, testdata)
                    }
                    miniscript::descriptor::ShInner::Ms(ms) => find_sks_ms(&ms, testdata),
                },
                Descriptor::Wsh(wsh) => match wsh.as_inner() {
                    miniscript::descriptor::WshInner::SortedMulti(smv) => {
                        let ms = Miniscript::from_ast(smv.sorted_node()).unwrap();
                        find_sks_ms(&ms, testdata)
                    }
                    miniscript::descriptor::WshInner::Ms(ms) => find_sks_ms(&ms, testdata),
                },
                Descriptor::Tr(_tr) => unreachable!("Tr checked earlier"),
            };
            let msg = psbt
                .sighash_msg(0, &mut sighash_cache, None)
                .unwrap()
                .to_secp_msg();

            // Fixme: Take a parameter
            let hash_ty = bitcoin::EcdsaSighashType::All;

            // Finally construct the signature and add to psbt
            for sk in sks_reqd {
                let sig = secp.sign_ecdsa(&msg, &sk);
                let pk = pks[sks.iter().position(|&x| x == sk).unwrap()];
                assert!(secp.verify_ecdsa(&msg, &sig, &pk.inner).is_ok());
                psbt.inputs[0].partial_sigs.insert(
                    pk,
                    bitcoin::EcdsaSig {
                        sig,
                        hash_ty: hash_ty,
                    },
                );
            }
        }
    }
    // Add the hash preimages to the psbt
    psbt.inputs[0].sha256_preimages.insert(
        testdata.pubdata.sha256,
        testdata.secretdata.sha256_pre.to_vec(),
    );
    psbt.inputs[0].hash256_preimages.insert(
        testdata.pubdata.hash256,
        testdata.secretdata.hash256_pre.to_vec(),
    );
    psbt.inputs[0].hash160_preimages.insert(
        testdata.pubdata.hash160,
        testdata.secretdata.hash160_pre.to_vec(),
    );
    psbt.inputs[0].ripemd160_preimages.insert(
        testdata.pubdata.ripemd160,
        testdata.secretdata.ripemd160_pre.to_vec(),
    );
    println!("Testing descriptor: {}", desc);
    // Finalize the transaction using psbt
    // Let miniscript do it's magic!
    if let Err(e) = psbt.finalize_mut(&secp) {
        // All miniscripts should satisfy
        panic!(
            "Could not satisfy non-malleably: error{} desc:{} ",
            e[0], desc
        );
    }
    let tx = psbt.extract(&secp).expect("Extraction error");

    // Send the transactions to bitcoin node for mining.
    // Regtest mode has standardness checks
    // Check whether the node accepts the transactions
    let txid = cl
        .send_raw_transaction(&tx)
        .expect(&format!("send tx failed for desc {}", desc));

    // Finally mine the blocks and await confirmations
    let _blocks = cl
        .generate_to_address(1, &cl.get_new_address(None, None).unwrap())
        .unwrap();
    // Get the required transactions from the node mined in the blocks.
    // Check whether the transaction is mined in blocks
    // Assert that the confirmations are > 0.
    let num_conf = cl.get_transaction(&txid, None).unwrap().info.confirmations;
    assert!(num_conf > 0);
    tx.input[0].witness.clone()
}

// Find all secret corresponding to the known public keys in ms
fn find_sks_ms<Ctx: ScriptContext>(
    ms: &Miniscript<bitcoin::PublicKey, Ctx>,
    testdata: &TestData,
) -> Vec<secp256k1::SecretKey> {
    let sks = &testdata.secretdata.sks;
    let pks = &testdata.pubdata.pks;
    let sks = ms
        .iter_pk_pkh()
        .filter_map(|pk_pkh| match pk_pkh {
            iter::PkPkh::PlainPubkey(pk) => {
                let i = pks.iter().position(|&x| x.to_public_key() == pk);
                i.map(|idx| (sks[idx]))
            }
            iter::PkPkh::HashedPubkey(hash) => {
                let i = pks
                    .iter()
                    .position(|&x| x.to_public_key().to_pubkeyhash() == hash);
                i.map(|idx| (sks[idx]))
            }
        })
        .collect();
    sks
}

fn find_sk_single_key(pk: bitcoin::PublicKey, testdata: &TestData) -> Vec<secp256k1::SecretKey> {
    let sks = &testdata.secretdata.sks;
    let pks = &testdata.pubdata.pks;
    let i = pks.iter().position(|&x| x.to_public_key() == pk);
    i.map(|idx| vec![sks[idx]]).unwrap_or(Vec::new())
}
