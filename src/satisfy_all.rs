
extern crate bitcoin;
extern crate script_descriptor;
extern crate secp256k1;

use std::collections::HashMap;
use std::io::BufReader;
use std::io::BufRead;
use std::fs::File;
use std::str::FromStr;

use bitcoin::blockdata::script;
use bitcoin::blockdata::transaction::{SigHashType, Transaction, TxIn, TxOut, OutPoint};
use bitcoin::network::serialize::serialize_hex;
use bitcoin::util::bip143;
use bitcoin::util::hash::Sha256dHash;
use bitcoin::util::hash::Hash160;

use script_descriptor::Policy;
                
fn main() {
    let secp = secp256k1::Secp256k1::signing_only();
    let halfsk = secp256k1::SecretKey::from_slice(&secp, &[
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
        0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0, 
    ]).expect("secret key");
    let halfpk = secp256k1::PublicKey::from_secret_key(&secp, &halfsk);

    let mut pkhmap = HashMap::new();
    pkhmap.insert(Hash160::from_data(&halfpk.serialize()[..]), halfpk.clone());

    let f = File::open("first_1M.input").expect("opening file");
    let file = BufReader::new(&f);
    for (lineno, line) in file.lines().enumerate().skip(0).take(1_000_000) {
        let l = line.unwrap();
        let policy = match Policy::from_str(&l) {
            Ok(pol) => pol,
            Err(e) => {
                panic!("Error parsing {}: {}", l, e);
            }
        };

        let d = policy.compile();
        let s = d.serialize();
        let witprog = s.to_v0_p2wsh();

        // Make tx sending 1000 sat from an output controlled by this descriptor
        // to an identical output
        let mut tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![
                TxIn {
                    previous_output: OutPoint {
                        txid: Sha256dHash::from_data(b"test"),
                        vout: 0,
                    },
                    script_sig: script::Script::new(),
                    sequence: 0,
                    witness: vec![],
                }
            ],
            output: vec![
                // Just send the coins back to themselves
                TxOut {
                    value: 1000,
                    script_pubkey: witprog.clone(),
                }
            ],
        };

        // Sign it
        let sighash_comp = bip143::SighashComponents::new(&tx);
        let sighash = sighash_comp.sighash_all(&tx.input[0], &s, 1000);
        let msg = secp256k1::Message::from_slice(&sighash[..]).expect("sighash to message");

        let sig = secp.sign(&msg, &halfsk);

        tx.input[0].witness = d.satisfy(
            Some(&|_: &secp256k1::PublicKey| Some((sig, Some(SigHashType::All)))),
            Some(&|_: &Sha256dHash| Some([0; 32])),
            0x20000000,
        ).expect("could not satisfy");
        tx.input[0].witness.push(s.to_bytes());

        println!("{}, {:?} {} {}", lineno, d, l, s);
        println!(
            "bitcoin-cli signrawtransaction {} '[{{ \"txid\": \"{}\", \"vout\": 0, \"scriptPubKey\": \"{:x}\", \"redeemScript\": \"{:x}\", \"amount\": 0.00001000 }}]' '[]'",
            serialize_hex(&tx).expect("hex"),
            Sha256dHash::from_data(b"test"),
            witprog,
            s,
        );
    }           
}   

