// Miniscript
// Written in 2019 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
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

//! Example: Parsing a descriptor from a string

extern crate bitcoin;
extern crate miniscript;

use std::str::FromStr;

fn main() {
    let my_descriptor = miniscript::Descriptor::<bitcoin::PublicKey>::from_str(
        "wsh(pk(020202020202020202020202020202020202020202020202020202020202020202))",
    )
    .unwrap();

    assert_eq!(
        format!("{:x}", my_descriptor.script_pubkey()),
        "0020a0a1a044f8d1e318caeba296ec10fe7c0939a59bc562dc013d39acbc724ded47"
    );

    assert_eq!(
        format!("{:x}", my_descriptor.witness_script()),
        "21020202020202020202020202020202020202020202020202020202020202020202"
    );
}
