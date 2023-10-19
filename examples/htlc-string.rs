// Written by Thomas Eizinger <thomas@coblox.tech>
// SPDX-License-Identifier: CC0-1.0

//! Example: Create an HTLC with miniscript using the policy compiler

use std::str::FromStr;

use miniscript::descriptor::Wsh;
use miniscript::policy::{Concrete, Liftable};

fn main() {
    // HTLC policy with 10:1 odds for happy (co-operative) case compared to uncooperative case.
    // let policy = Concrete::<String>::from_str(&format!("or(10@and(sha256(secret_hash),pk(redeem)),1@and(older(expiry),pk(refund)))")).unwrap();

    let policy = Concrete::<String>::from_str(&format!(
        "or(10@and(sha256(secret_hash),pk(redeem)),1@and(older(4444),pk(refund)))"
    ))
    .unwrap();

    let descriptor = Wsh::new(
        policy
            .compile()
            .expect("policy compilation only fails on resource limits or mixed timelocks"),
    )
    .expect("resource limits");

    println!("descriptor: {}", descriptor);
    println!("lifted    : {}", descriptor.lift().unwrap());
    // println!("{}", descriptor.script_pubkey());
    // println!("{}", descriptor.inner_script());
    // println!("{}", descriptor.address(Network::Bitcoin));
}
