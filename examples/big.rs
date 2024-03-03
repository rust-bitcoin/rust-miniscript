// SPDX-License-Identifier: CC0-1.0
//! This is not an example and will surely panic if executed, the purpose of this is using the 
//! compiled binary with tools like `cargo bloat` that cannot work with libraries.
//!
//! Ideal properties:
//!
//! * Call all the library API surface.
//! * Depend on user input so that functions are not stripped out on the base of static input.
//! * Use results so that calls are not stripped out.
//!

use std::{collections::HashMap, str::FromStr};
use bitcoin::ecdsa;
use miniscript::{descriptor::Wsh, policy::{Concrete, Liftable}, psbt::PsbtExt, DefiniteDescriptorKey, Descriptor, DescriptorPublicKey, MiniscriptKey};
use secp256k1::Secp256k1;
fn main() {
    let empty = "".to_string();
    let mut args = std::env::args().collect::<Vec<_>>();
    let i = args.pop().unwrap_or(empty);

    let d = Descriptor::<DescriptorPublicKey>::from_str(&i).unwrap();
    use_descriptor(d.clone());
    use_descriptor(Descriptor::<DefiniteDescriptorKey>::from_str(&i).unwrap());
    use_descriptor(Descriptor::<bitcoin::PublicKey>::from_str(&i).unwrap());
    use_descriptor(Descriptor::<String>::from_str(&i).unwrap());

    let a = d.at_derivation_index(0).unwrap().address(bitcoin::Network::Bitcoin).unwrap();
    println!("{}", a);

    let secp = Secp256k1::new();
    let (d, m) = Descriptor::parse_descriptor(&secp, &i).unwrap();
    use_descriptor(d);
    println!("{:?}", m);

    let p = Concrete::<bitcoin::PublicKey>::from_str(&i).unwrap();
    let h = Wsh::new(p.compile().unwrap()).unwrap();
    println!("{}", h);
    println!("{:?}", h.lift());
    println!("{:?}", h.script_pubkey());
    println!("{:?}", h.address(bitcoin::Network::Bitcoin));

    let psbt: bitcoin::Psbt = i.parse().unwrap();
    let psbt = psbt.finalize(&secp).unwrap();
    let mut tx = psbt.extract_tx().unwrap();
    println!("{:?}", tx);

    let d = miniscript::Descriptor::<bitcoin::PublicKey>::from_str(&i).unwrap();
    let sigs = HashMap::<bitcoin::PublicKey, ecdsa::Signature>::new();
    d.satisfy(&mut tx.input[0], &sigs).unwrap();
}

fn use_descriptor<K: MiniscriptKey>(d: Descriptor<K>) {
    println!("{}", d);
    println!("{:?}", d);
    println!("{:?}", d.desc_type());
    println!("{:?}", d.sanity_check());
}