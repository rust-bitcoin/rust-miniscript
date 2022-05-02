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

use bitcoin;
use miniscript;

use miniscript::{descriptor::DescriptorType, Descriptor, DescriptorTrait};
use std::str::FromStr;

fn main() {
    let my_descriptor = miniscript::Descriptor::<bitcoin::PublicKey>::from_str(
        "wsh(c:pk_k(020202020202020202020202020202020202020202020202020202020202020202))",
    )
    .unwrap();

    // Check whether the descriptor is safe
    // This checks whether all spend paths are accessible in bitcoin network.
    // It maybe possible that some of the spend require more than 100 elements in Wsh scripts
    // Or they contain a combination of timelock and heightlock.
    assert!(my_descriptor.sanity_check().is_ok());

    // Compute the script pubkey. As mentioned in the documentation, script_pubkey only fails
    // for Tr descriptors that don't have some pre-computed data
    assert_eq!(
        format!("{:x}", my_descriptor.script_pubkey()),
        "0020daef16dd7c946a3e735a6e43310cb2ce33dfd14a04f76bf8241a16654cb2f0f9"
    );

    // Another way to compute script pubkey
    // We can also compute the type of descriptor
    let desc_type = my_descriptor.desc_type();
    assert_eq!(desc_type, DescriptorType::Wsh);
    // Since we know the type of descriptor, we can get the Wsh struct from Descriptor
    // This allows us to call infallible methods for getting script pubkey
    if let Descriptor::Wsh(wsh) = &my_descriptor {
        assert_eq!(
            format!("{:x}", wsh.spk()),
            "0020daef16dd7c946a3e735a6e43310cb2ce33dfd14a04f76bf8241a16654cb2f0f9"
        );
    } else {
        // We checked for the descriptor type earlier
    }

    // Get the inner script inside the descriptor
    assert_eq!(
        format!(
            "{:x}",
            my_descriptor
                .explicit_script()
                .expect("Wsh descriptors have inner scripts")
        ),
        "21020202020202020202020202020202020202020202020202020202020202020202ac"
    );

    let desc = miniscript::Descriptor::<bitcoin::PublicKey>::from_str(
        "sh(wsh(c:pk_k(020202020202020202020202020202020202020202020202020202020202020202)))",
    )
    .unwrap();

    assert!(desc.desc_type() == DescriptorType::ShWsh);
}
