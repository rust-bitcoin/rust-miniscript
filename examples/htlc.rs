// Miniscript
// Written in 2019 by
//    Thomas Eizinger <thomas@coblox.tech>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Example: Create an HTLC with miniscript using the policy compiler

extern crate bitcoin;
extern crate miniscript;

use bitcoin::Network;
use miniscript::descriptor::Wsh;
use miniscript::policy::{Concrete, Liftable};
use miniscript::DescriptorTrait;
use std::str::FromStr;

fn main() {
    //HTLC policy with 10:1 odds for happy(co-operative) case compared to uncooperative case
    let htlc_policy = Concrete::<bitcoin::PublicKey>::from_str(&format!("or(10@and(sha256({secret_hash}),pk({redeem_identity})),1@and(older({expiry}),pk({refund_identity})))",
                                                  secret_hash = "1111111111111111111111111111111111111111111111111111111111111111",
                                                  redeem_identity = "022222222222222222222222222222222222222222222222222222222222222222",
                                                  refund_identity = "020202020202020202020202020202020202020202020202020202020202020202",
                                                  expiry = "4444"
    )).unwrap();

    let htlc_descriptor = Wsh::new(
        htlc_policy
            .compile()
            .expect("Policy compilation only fails on resource limits or mixed timelocks"),
    )
    .expect("Resource limits");

    // Check whether the descriptor is safe
    // This checks whether all spend paths are accessible in bitcoin network.
    // It maybe possible that some of the spend require more than 100 elements in Wsh scripts
    // Or they contain a combination of timelock and heightlock.
    assert!(htlc_descriptor.sanity_check().is_ok());
    assert_eq!(
        format!("{}", htlc_descriptor),
        "wsh(andor(pk(022222222222222222222222222222222222222222222222222222222222222222),sha256(1111111111111111111111111111111111111111111111111111111111111111),and_v(v:pkh(51814f108670aced2d77c1805ddd6634bc9d4731),older(4444))))#s0qq76ng"
    );

    assert_eq!(
        format!("{}", htlc_descriptor.lift().unwrap()),
        "or(and(pkh(4377a5acd66dc5cb67148a24818d1e51fa183bd2),sha256(1111111111111111111111111111111111111111111111111111111111111111)),and(pkh(51814f108670aced2d77c1805ddd6634bc9d4731),older(4444)))"
    );

    assert_eq!(
        format!("{:x}", htlc_descriptor.spk()),
        "0020d853877af928a8d2a569c9c0ed14bd16f6a80ce9cccaf8a6150fd8f7f8867ae2"
    );

    assert_eq!(
        format!("{:x}", htlc_descriptor.inner_script()),
        "21022222222222222222222222222222222222222222222222222222222222222222ac6476a91451814f108670aced2d77c1805ddd6634bc9d473188ad025c11b26782012088a82011111111111111111111111111111111111111111111111111111111111111118768"
    );

    assert_eq!(
        format!("{}", htlc_descriptor.address(Network::Bitcoin).unwrap()),
        "bc1qmpfcw7he9z5d9ftfe8qw699azmm2sr8fen903fs4plv007yx0t3qxfmqv5"
    );
}
