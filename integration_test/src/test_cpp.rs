//! # rust-miniscript integration test
//!
//! Read Miniscripts from file and translate into miniscripts
//! which we know how to satisfy
//!

use bitcoin::secp256k1::{self, Secp256k1};
use bitcoin::util::psbt;
use bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
use bitcoin::{self, Amount, OutPoint, Transaction, TxIn, TxOut, Txid};
use bitcoincore_rpc::{json, Client, RpcApi};
use miniscript::miniscript::iter;
use miniscript::psbt::PsbtExt;
use miniscript::MiniscriptKey;
use miniscript::Segwitv0;
use miniscript::{Descriptor, DescriptorTrait, Miniscript};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

use super::test_util::PubData;
use crate::test_util::{self, TestData};

// parse ~30 miniscripts from file
pub(crate) fn parse_miniscripts(
    secp: &Secp256k1<secp256k1::All>,
    pubdata: &PubData,
) -> Vec<Descriptor<bitcoin::PublicKey>> {
    // File must exist in current path before this produces output
    let mut desc_vec = vec![];
    if let Ok(lines) = read_lines("./random_ms.txt") {
        // Consumes the iterator, returns an (Optional) String
        for line in lines {
            let ms = test_util::parse_insane_ms(&line.unwrap(), pubdata);
            let wsh = Descriptor::new_wsh(ms).unwrap();
            desc_vec.push(wsh.derived_descriptor(secp, 0).unwrap());
        }
    }
    desc_vec
}

// The output is wrapped in a Result to allow matching on errors
// Returns an Iterator to the Reader of the lines of the file.
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

/// Quickly create a BTC amount.
fn btc<F: Into<f64>>(btc: F) -> Amount {
    Amount::from_btc(btc.into()).unwrap()
}

// Find the Outpoint by value.
// Ideally, we should find by scriptPubkey, but this
// works for temp test case
fn get_vout(cl: &Client, txid: Txid, value: u64) -> (OutPoint, TxOut) {
    let tx = cl
        .get_transaction(&txid, None)
        .unwrap()
        .transaction()
        .unwrap();
    for (i, txout) in tx.output.into_iter().enumerate() {
        if txout.value == value {
            return (OutPoint::new(txid, i as u32), txout);
        }
    }
    unreachable!("Only call get vout on functions which have the expected outpoint");
}

pub fn test_from_cpp_ms(cl: &Client, testdata: &TestData) {
    let secp = secp256k1::Secp256k1::new();
    let desc_vec = parse_miniscripts(&secp, &testdata.pubdata);
    let sks = &testdata.secretdata.sks;
    let pks = &testdata.pubdata.pks;
    // Generate some blocks
    let blocks = cl
        .generate_to_address(500, &cl.get_new_address(None, None).unwrap())
        .unwrap();
    assert_eq!(blocks.len(), 500);

    // Next send some btc to each address corresponding to the miniscript
    let mut txids = vec![];
    for wsh in desc_vec.iter() {
        let txid = cl
            .send_to_address(
                &wsh.address(bitcoin::Network::Regtest).unwrap(),
                btc(1),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        txids.push(txid);
    }
    // Wait for the funds to mature.
    let blocks = cl
        .generate_to_address(50, &cl.get_new_address(None, None).unwrap())
        .unwrap();
    assert_eq!(blocks.len(), 50);
    // Create a PSBT for each transaction.
    // Spend one input and spend one output for simplicity.
    let mut psbts = vec![];
    for (desc, txid) in desc_vec.iter().zip(txids) {
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
        let (outpoint, witness_utxo) = get_vout(&cl, txid, btc(1.0).as_sat());
        let mut txin = TxIn::default();
        txin.previous_output = outpoint;
        // set the sequence to a non-final number for the locktime transactions to be
        // processed correctly.
        // We waited 50 blocks, keep 49 for safety
        txin.sequence = 49;
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
        input.witness_utxo = Some(witness_utxo);
        input.witness_script = Some(desc.explicit_script().unwrap());
        psbt.inputs.push(input);
        psbt.outputs.push(psbt::Output::default());
        psbts.push(psbt);
    }

    let mut spend_txids = vec![];
    // Sign the transactions with all keys
    // AKA the signer role of psbt
    for i in 0..psbts.len() {
        // Get all the pubkeys and the corresponding secret keys
        let ms: Miniscript<miniscript::bitcoin::PublicKey, Segwitv0> =
            Miniscript::parse_insane(psbts[i].inputs[0].witness_script.as_ref().unwrap()).unwrap();

        let sks_reqd: Vec<_> = ms
            .iter_pk_pkh()
            .map(|pk_pkh| match pk_pkh {
                iter::PkPkh::PlainPubkey(pk) => sks[pks.iter().position(|&x| x == pk).unwrap()],
                iter::PkPkh::HashedPubkey(hash) => {
                    sks[pks
                        .iter()
                        .position(|&pk| pk.to_pubkeyhash() == hash)
                        .unwrap()]
                }
            })
            .collect();
        // Get the required sighash message
        let amt = btc(1).as_sat();
        let mut sighash_cache = bitcoin::util::sighash::SighashCache::new(&psbts[i].unsigned_tx);
        let sighash_ty = bitcoin::EcdsaSighashType::All;
        let sighash = sighash_cache
            .segwit_signature_hash(0, &ms.encode(), amt, sighash_ty)
            .unwrap();

        // requires both signing and verification because we check the tx
        // after we psbt extract it
        let msg = secp256k1::Message::from_slice(&sighash[..]).unwrap();

        // Finally construct the signature and add to psbt
        for sk in sks_reqd {
            let sig = secp.sign_ecdsa(&msg, &sk);
            let pk = pks[sks.iter().position(|&x| x == sk).unwrap()];
            psbts[i].inputs[0].partial_sigs.insert(
                pk,
                bitcoin::EcdsaSig {
                    sig,
                    hash_ty: sighash_ty,
                },
            );
        }
        // Add the hash preimages to the psbt
        psbts[i].inputs[0].sha256_preimages.insert(
            testdata.pubdata.sha256,
            testdata.secretdata.sha256_pre.to_vec(),
        );
        psbts[i].inputs[0].hash256_preimages.insert(
            testdata.pubdata.hash256,
            testdata.secretdata.hash256_pre.to_vec(),
        );
        println!("{}", ms);
        psbts[i].inputs[0].hash160_preimages.insert(
            testdata.pubdata.hash160,
            testdata.secretdata.hash160_pre.to_vec(),
        );
        psbts[i].inputs[0].ripemd160_preimages.insert(
            testdata.pubdata.ripemd160,
            testdata.secretdata.ripemd160_pre.to_vec(),
        );
        // Finalize the transaction using psbt
        // Let miniscript do it's magic!
        if let Err(e) = psbts[i].finalize_mall_mut(&secp) {
            // All miniscripts should satisfy
            panic!("Could not satisfy: error{} ms:{} at ind:{}", e[0], ms, i);
        } else {
            let tx = psbts[i].extract(&secp).unwrap();

            // Send the transactions to bitcoin node for mining.
            // Regtest mode has standardness checks
            // Check whether the node accepts the transactions
            let txid = cl
                .send_raw_transaction(&tx)
                .expect(&format!("{} send tx failed for ms {}", i, ms));
            spend_txids.push(txid);
        }
    }
    // Finally mine the blocks and await confirmations
    let _blocks = cl
        .generate_to_address(10, &cl.get_new_address(None, None).unwrap())
        .unwrap();
    // Get the required transactions from the node mined in the blocks.
    for txid in spend_txids {
        // Check whether the transaction is mined in blocks
        // Assert that the confirmations are > 0.
        let num_conf = cl.get_transaction(&txid, None).unwrap().info.confirmations;
        assert!(num_conf > 0);
    }
}
