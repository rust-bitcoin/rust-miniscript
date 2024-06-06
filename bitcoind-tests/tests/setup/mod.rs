extern crate miniscript;

use core::convert::TryInto;

use bitcoind::client::json::model;
use bitcoind::client::bitcoin;

pub mod test_util;

// Launch an instance of bitcoind with
pub fn setup() -> bitcoind::BitcoinD {
    // Create env var BITCOIND_EXE_PATH to point to the ../bitcoind/bin/bitcoind binary
    let key = "BITCOIND_EXE";
    if std::env::var(key).is_err() {
        let mut root_path = std::env::current_dir().unwrap();
        while std::fs::metadata(root_path.join("LICENSE")).is_err() {
            if !root_path.pop() {
                panic!("Could not find LICENSE file; do not know where repo root is.");
            }
        }

        let bitcoind_path = root_path
            .join("bitcoind-tests")
            .join("bin")
            .join("bitcoind");
        std::env::set_var(key, bitcoind_path);
    }

    let exe_path = bitcoind::exe_path().unwrap();
    let bitcoind = bitcoind::BitcoinD::new(exe_path).unwrap();
    let cl = &bitcoind.client;
    // generate to an address by the wallet. And wait for funds to mature
    let addr = cl.new_address().unwrap();
    let blks = cl.generate_to_address(101, &addr).unwrap();
    assert_eq!(blks.0.len(), 101);

    let json = cl.get_balance().expect("failed to get balance");
    let concrete: model::GetBalance = json.try_into().unwrap();
    assert_eq!(
        concrete.0,
        bitcoin::Amount::from_sat(100_000_000 * 50),
    );
    bitcoind
}
