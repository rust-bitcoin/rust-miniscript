extern crate miniscript;

use bitcoind::bitcoincore_rpc::RpcApi;
use bitcoind::BitcoinD;
use miniscript::bitcoin;

pub mod test_util;

// Launch an instance of bitcoind with
pub fn setup() -> BitcoinD {
    let exe_path = bitcoind::exe_path().unwrap();
    let bitcoind = bitcoind::BitcoinD::new(exe_path).unwrap();
    let cl = &bitcoind.client;
    // generate to an address by the wallet. And wait for funds to mature
    let addr = cl.get_new_address(None, None).unwrap();
    let blks = cl.generate_to_address(101, &addr).unwrap();
    assert_eq!(blks.len(), 101);

    assert_eq!(
        cl.get_balance(Some(1) /*min conf*/, None).unwrap(),
        bitcoin::Amount::from_sat(100_000_000 * 50)
    );
    bitcoind
}
