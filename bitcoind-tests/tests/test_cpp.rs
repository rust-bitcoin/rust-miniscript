//! # rust-miniscript integration test
//!
//! Read Miniscripts from file and translate into miniscripts
//! which we know how to satisfy
//!

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

use bitcoin::hashes::sha256d;
use bitcoin::psbt::Psbt;
use bitcoin::transaction::OutPointExt as _;
use bitcoin::{
    psbt, secp256k1, transaction, Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid,
};
use bitcoind::{AddressType, Client};
use miniscript::bitcoin::absolute;
use miniscript::psbt::PsbtExt;
use miniscript::{bitcoin, DefiniteDescriptorKey, Descriptor};

mod setup;
use setup::test_util::{self, PubData, TestData};

// parse ~30 miniscripts from file
pub(crate) fn parse_miniscripts(pubdata: &PubData) -> Vec<Descriptor<DefiniteDescriptorKey>> {
    // File must exist in current path before this produces output
    let mut desc_vec = vec![];
    // Consumes the iterator, returns an (Optional) String
    for line in read_lines("tests/data/random_ms.txt") {
        let ms = test_util::parse_insane_ms(&line.unwrap(), pubdata);
        let wsh = Descriptor::new_wsh(ms).unwrap();
        desc_vec.push(wsh.at_derivation_index(0).unwrap());
    }
    desc_vec
}

// The output is wrapped in a Result to allow matching on errors
// Returns an Iterator to the Reader of the lines of the file.
fn read_lines<P>(filename: P) -> io::Lines<io::BufReader<File>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename).expect("File not found");
    io::BufReader::new(file).lines()
}

/// Quickly create a BTC amount.
fn btc<F: Into<f64>>(btc: F) -> Amount { Amount::from_btc(btc.into()).unwrap() }

// Find the Outpoint by value.
// Ideally, we should find by scriptPubkey, but this
// works for temp test case
fn get_vout(cl: &Client, txid: Txid, value: Amount) -> (OutPoint, TxOut) {
    let model = cl
        .get_transaction(txid)
        .expect("rpc call failed")
        .into_model()
        .expect("conversion to model type failed");
    let tx = model.tx;

    for (i, txout) in tx.output.into_iter().enumerate() {
        if txout.value == value {
            return (OutPoint::new(txid, i as u32), txout);
        }
    }
    unreachable!("Only call get vout on functions which have the expected outpoint");
}

pub fn test_from_cpp_ms(cl: &Client, testdata: &TestData) {
    let secp = secp256k1::Secp256k1::new();
    let desc_vec = parse_miniscripts(&testdata.pubdata);
    let sks = &testdata.secretdata.sks;
    let pks = &testdata.pubdata.pks;
    // Generate some blocks
    let blocks = cl
        .generate_to_address(500, &cl.new_address().unwrap())
        .unwrap();
    assert_eq!(blocks.0.len(), 500);

    // Next send some btc to each address corresponding to the miniscript
    let mut txids = vec![];
    for wsh in desc_vec.iter() {
        let txid = cl
            .send_to_address(&wsh.address(bitcoin::Network::Regtest).unwrap(), btc(1))
            .expect("rpc call failed")
            .txid()
            .expect("conversion to model failed");
        txids.push(txid);
    }
    // Wait for the funds to mature.
    let blocks = cl
        .generate_to_address(50, &cl.new_address().unwrap())
        .unwrap();
    assert_eq!(blocks.0.len(), 50);
    // Create a PSBT for each transaction.
    // Spend one input and spend one output for simplicity.
    let mut psbts = vec![];
    for (desc, txid) in desc_vec.iter().zip(txids) {
        let mut psbt = Psbt {
            unsigned_tx: Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::from_time(1_603_866_330).expect("valid timestamp"), // 10/28/2020 @ 6:25am (UTC)
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
        let (outpoint, witness_utxo) = get_vout(cl, txid, btc(1.0));
        let txin = TxIn {
            previous_output: outpoint,
            // set the sequence to a non-final number for the locktime transactions to be
            // processed correctly.
            // We waited 50 blocks, keep 49 for safety
            sequence: Sequence::from_height(49),
            ..TxIn::EMPTY_COINBASE
        };
        psbt.unsigned_tx.input.push(txin);
        // Get a new script pubkey from the node so that
        // the node wallet tracks the receiving transaction
        // and we can check it by gettransaction RPC.
        let addr = cl.new_address_with_type(AddressType::Bech32).unwrap();
        psbt.unsigned_tx.output.push(TxOut {
            value: Amount::from_sat(99_999_000),
            script_pubkey: addr.script_pubkey(),
        });
        let input = psbt::Input {
            witness_utxo: Some(witness_utxo),
            witness_script: Some(desc.explicit_script().unwrap()),
            ..Default::default()
        };
        psbt.inputs.push(input);
        psbt.update_input_with_descriptor(0, desc).unwrap();
        psbt.outputs.push(psbt::Output::default());
        psbts.push(psbt);
    }

    let mut spend_txids = vec![];
    // Sign the transactions with all keys
    // AKA the signer role of psbt
    for i in 0..psbts.len() {
        let wsh_derived = desc_vec[i].derived_descriptor(&secp).unwrap();
        let ms = if let Descriptor::Wsh(wsh) = &wsh_derived {
            match wsh.as_inner() {
                miniscript::descriptor::WshInner::Ms(ms) => ms,
                _ => unreachable!(),
            }
        } else {
            unreachable!("Only Wsh descriptors are supported");
        };

        let sks_reqd: Vec<_> = ms
            .iter_pk()
            .map(|pk| sks[pks.iter().position(|&x| x == pk).unwrap()])
            .collect();
        // Get the required sighash message
        let amt = btc(1);
        let mut sighash_cache = bitcoin::sighash::SighashCache::new(&psbts[i].unsigned_tx);
        let sighash_type = bitcoin::sighash::EcdsaSighashType::All;
        let sighash = sighash_cache
            .p2wsh_signature_hash(0, &ms.encode(), amt, sighash_type)
            .unwrap();

        // requires both signing and verification because we check the tx
        // after we psbt extract it
        let msg = secp256k1::Message::from_digest(sighash.to_byte_array());

        // Finally construct the signature and add to psbt
        for sk in sks_reqd {
            let signature = secp.sign_ecdsa(&msg, &sk);
            let pk = pks[sks.iter().position(|&x| x == sk).unwrap()];
            psbts[i].inputs[0]
                .partial_sigs
                .insert(pk, bitcoin::ecdsa::Signature { signature, sighash_type });
        }
        // Add the hash preimages to the psbt
        psbts[i].inputs[0]
            .sha256_preimages
            .insert(testdata.pubdata.sha256, testdata.secretdata.sha256_pre.to_vec());
        psbts[i].inputs[0].hash256_preimages.insert(
            sha256d::Hash::from_byte_array(testdata.pubdata.hash256.to_byte_array()),
            testdata.secretdata.hash256_pre.to_vec(),
        );
        println!("{}", ms);
        psbts[i].inputs[0]
            .hash160_preimages
            .insert(testdata.pubdata.hash160, testdata.secretdata.hash160_pre.to_vec());
        psbts[i].inputs[0]
            .ripemd160_preimages
            .insert(testdata.pubdata.ripemd160, testdata.secretdata.ripemd160_pre.to_vec());
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
                .unwrap_or_else(|_| panic!("{} send tx failed for ms {}", i, ms))
                .txid()
                .expect("conversion to model failed");
            spend_txids.push(txid);
        }
    }
    // Finally mine the blocks and await confirmations
    let _blocks = cl
        .generate_to_address(10, &cl.new_address().unwrap())
        .unwrap();
    // Get the required transactions from the node mined in the blocks.
    for txid in spend_txids {
        // Check whether the transaction is mined in blocks
        // Assert that the confirmations are > 0.
        let num_conf = cl.get_transaction(txid).unwrap().confirmations;
        assert!(num_conf > 0);
    }
}

#[test]
fn test_setup() { setup::setup(); }

#[test]
fn tests_from_cpp() {
    let cl = &setup::setup().client;
    let testdata = TestData::new_fixed_data(50);
    test_from_cpp_ms(cl, &testdata);
}
