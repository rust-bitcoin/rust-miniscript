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

//! Example: Create an HTLC with miniscript

extern crate bitcoin;
extern crate miniscript;

use bitcoin::Network;
use std::str::FromStr;

fn main() {
    let descriptor_template = format!(
        "wsh(c:or_i(and_v(v:sha256({secret_hash}),pk_h({redeem_identity})),and_v(v:after({expiry}),pk_h({refund_identity}))))",
        secret_hash = "1111111111111111111111111111111111111111111111111111111111111111",
        redeem_identity = "2222222222222222222222222222222222222222",
        refund_identity = "3333333333333333333333333333333333333333",
        expiry = "4444"
    );

    let htlc_descriptor =
        miniscript::Descriptor::<bitcoin::PublicKey>::from_str(&descriptor_template).unwrap();

    assert_eq!(
        format!("{:x}", htlc_descriptor.script_pubkey()),
        "0020b822548461760c6a7c3c51c7fdaa0ccbdc69ae39a66b752ec8a4772bfdd41e64"
    );

    assert_eq!(
        format!("{:x}", htlc_descriptor.witness_script()),
        "6382012088a82011111111111111111111111111111111111111111111111111111111111111118876a91422222222222222222222222222222222222222228867025c11b26976a91433333333333333333333333333333333333333338868ac"
    );

    assert_eq!(
        format!("{}", htlc_descriptor.address(Network::Bitcoin).unwrap()),
        "bc1qhq39fprpwcxx5lpu28rlm2sve0wxnt3e5e4h2tkg53mjhlw5rejq7e8n2t"
    );
}
