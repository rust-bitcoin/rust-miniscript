
extern crate bitcoin;
extern crate script_descriptor;
extern crate secp256k1;

use std::io::BufReader;
use std::io::BufRead;
use std::fs::File;
use std::str::FromStr;


use bitcoin::blockdata::script;
use secp256k1::{Secp256k1, PublicKey};
use script_descriptor::Policy;
use script_descriptor::policy::compiler;
use script_descriptor::descript::astelem::AstElem;
                
static DUMMY_PK: &'static [u8] = &[
    0x02,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3b, 0x78, 0xce, 0x56, 0x3f,
    0x89, 0xa0, 0xed, 0x94, 0x14, 0xf5, 0xaa, 0x28, 0xad, 0x0d, 0x96, 0xd6, 0x79, 0x5f, 0x9c, 0x63,
];

#[derive(Copy, Clone, Debug)]
struct DummyKey;
impl FromStr for DummyKey {
    type Err = String;
    fn from_str(_: &str) -> Result<DummyKey, String> {
        Ok(DummyKey)
    }
}

impl script_descriptor::PublicKey for DummyKey {}

fn main() {   
    let f = File::open("first_1M.input").expect("opening file");
    let file = BufReader::new(&f);
    for (lineno, line) in file.lines().enumerate().skip(0).take(100_000_000) {
        let l = line.unwrap();
        let policy = match Policy::<DummyKey>::from_str(&l) {
            Ok(pol) => pol,
            Err(e) => {
                panic!("Error parsing {}: {}", l, e);
            }
        };

        let secp = Secp256k1::without_caps();
        let policy_secp = policy.translate(
            &|_| PublicKey::from_slice(&secp, DUMMY_PK)
        ).expect("dummy is a good key");

        let node = compiler::CompiledNode::from_policy(&policy_secp);
        let cost = node.best_t(1.0, 0.0);
        let s = cost.ast.serialize(script::Builder::new()).into_script();

        println!("{:7} {:17.10} {:5} {:x} {:?} {}", lineno, cost.pk_cost as f64 + cost.sat_cost, cost.pk_cost, s, cost.ast, l);
    }           
}   

