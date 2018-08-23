
extern crate bitcoin;
extern crate script_descriptor;

use std::io::BufReader;
use std::io::BufRead;
use std::fs::File;
use std::str::FromStr;

use bitcoin::blockdata::script;
use script_descriptor::ast::compiler::Compileable;
use script_descriptor::ast::astelem::{AstElem, T};
                
fn main() {   
    let f = File::open("first_1M.input").expect("opening file");
    let file = BufReader::new(&f);
    for (lineno, line) in file.lines().enumerate().skip(0).take(1_000_000) {
        let l = line.unwrap();
        let desc = match script_descriptor::Descriptor::from_str(&l) {
            Ok(desc) => desc,
            Err(e) => {
                panic!("Error parsing {}: {}", l, e);
            }
        };

        let cost = T::from_descriptor(&desc, 1.0, 0.0);
        let s = cost.ast.serialize(script::Builder::new()).into_script();

        println!("{:7} {:17.10} {:5} {:x} {:?} {}", lineno, cost.pk_cost as f64 + cost.sat_cost, cost.pk_cost, s, cost.ast, l);
    }           
}   

