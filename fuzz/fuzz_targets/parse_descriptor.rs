use std::str::FromStr;

use honggfuzz::fuzz;
use miniscript::DescriptorPublicKey;

fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data);
    if let Ok(dpk) = DescriptorPublicKey::from_str(&data_str) {
        let _output = dpk.to_string();
        // assert_eq!(data_str.to_lowercase(), _output.to_lowercase());
    }
}

fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}
