//! # rust-miniscript integration test
//!
//! This is how some external user would use rust-miniscript

extern crate bitcoincore_rpc;
extern crate log;

extern crate bitcoin;
extern crate miniscript;

use bitcoincore_rpc::{Auth, Client, RpcApi};

mod test_desc;
mod test_cpp;
mod test_util;
use test_util::TestData;

struct StdLogger;

impl log::Log for StdLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.target().contains("jsonrpc") || metadata.target().contains("bitcoincore_rpc")
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            println!(
                "[{}][{}]: {}",
                record.level(),
                record.metadata().target(),
                record.args()
            );
        }
    }

    fn flush(&self) {}
}

static LOGGER: StdLogger = StdLogger;

fn get_rpc_url() -> String {
    return std::env::var("RPC_URL").expect("RPC_URL must be set");
}

fn get_auth() -> bitcoincore_rpc::Auth {
    if let Ok(cookie) = std::env::var("RPC_COOKIE") {
        return Auth::CookieFile(cookie.into());
    } else if let Ok(user) = std::env::var("RPC_USER") {
        return Auth::UserPass(user, std::env::var("RPC_PASS").unwrap_or_default());
    } else {
        panic!("Either RPC_COOKIE or RPC_USER + RPC_PASS must be set.");
    };
}

fn main() {
    log::set_logger(&LOGGER)
        .map(|()| log::set_max_level(log::LevelFilter::max()))
        .unwrap();

    let rpc_url = format!("{}/wallet/testwallet", get_rpc_url());
    let auth = get_auth();

    let cl = Client::new(&rpc_url, auth).unwrap();

    // 0.21 does not create default wallet..
    cl.create_wallet("testwallet", None, None, None, None)
        .unwrap();

    let testdata = TestData::new_fixed_data(50);
    test_cpp::test_from_cpp_ms(&cl, &testdata);
}
