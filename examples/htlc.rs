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
use miniscript::policy::{Concrete, Liftable};
use miniscript::Descriptor;
use std::str::FromStr;

fn main() {
    //HTLC policy with 10:1 odds for happy(co-operative) case compared to uncooperative case
    let htlc_policy = Concrete::<bitcoin::PublicKey>::from_str(&format!("or(10@and(sha256({secret_hash}),pk({redeem_identity})),1@and(older({expiry}),pk({refund_identity})))",
                                                  secret_hash = "1111111111111111111111111111111111111111111111111111111111111111",
                                                  redeem_identity = "022222222222222222222222222222222222222222222222222222222222222222",
                                                  refund_identity = "022222222222222222222222222222222222222222222222222222222222222222",
                                                  expiry = "4444"
    )).unwrap();

    let htlc_descriptor = Descriptor::Wsh(htlc_policy.compile().unwrap());

    assert_eq!(
        format!("{}", htlc_descriptor),
        "wsh(andor(c:pk(022222222222222222222222222222222222222222222222222222222222222222),sha256(1111111111111111111111111111111111111111111111111111111111111111),and_v(vc:pk_h(4377a5acd66dc5cb67148a24818d1e51fa183bd2),older(4444))))"
    );

    assert_eq!(
        format!("{}", htlc_descriptor.lift()),
        "or(and(pkh(4377a5acd66dc5cb67148a24818d1e51fa183bd2),and(pkh(4377a5acd66dc5cb67148a24818d1e51fa183bd2),older(4444))),sha256(1111111111111111111111111111111111111111111111111111111111111111))"
    );

    assert_eq!(
        format!("{:x}", htlc_descriptor.script_pubkey()),
        "002066114a2b652583a331705623ab3163511fa5bc50aea8bf5d1295c730a9a6763a"
    );

    assert_eq!(
        format!("{:x}", htlc_descriptor.witness_script()),
        "21022222222222222222222222222222222222222222222222222222222222222222ac6482012088a8201111111111111111111111111111111111111111111111111111111111111111876776a9144377a5acd66dc5cb67148a24818d1e51fa183bd288ad025c11b168"
    );

    assert_eq!(
        format!("{}", htlc_descriptor.address(Network::Bitcoin).unwrap()),
        "bc1qvcg552m9ykp6xvts2c36kvtr2y06t0zs465t7hgjjhrnp2dxwcaq5h00a4"
    );
}
