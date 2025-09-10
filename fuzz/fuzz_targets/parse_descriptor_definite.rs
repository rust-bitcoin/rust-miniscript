// SPDX-License-Identifier: CC0-1.0

#![cfg_attr(fuzzing, no_main)]

use miniscript::{DefiniteDescriptorKey, Descriptor};

fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data);

    if let Ok(desc) = data_str.parse::<Descriptor<DefiniteDescriptorKey>>() {
        let _ = desc.to_string();
        let _ = desc.address(miniscript::bitcoin::Network::Bitcoin);
    }
}

#[cfg(fuzzing)]
libfuzzer_sys::fuzz_target!(|data| { do_test(data); });

#[cfg(not(fuzzing))]
fn main() { do_test(&[]); }

#[cfg(test)]
mod tests {
    use miniscript::hex;

    #[test]
    fn duplicate_crash() {
        let v = hex::decode_to_vec("abcd").unwrap();
        super::do_test(&v);
    }
}
