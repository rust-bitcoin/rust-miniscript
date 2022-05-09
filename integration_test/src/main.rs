//! # rust-miniscript integration test
//!
//! This is how some external user would use rust-miniscript

use bitcoincore_rpc::{Auth, Client, RpcApi};

mod test_cpp;
mod test_desc;
mod test_util;
use crate::test_util::TestData;

struct StdLogger;

impl log::Log for StdLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.target().contains("jsonrpc") || metadata.target().contains("bitcoincore_rpc")
    }

    fn log(&self, record: &log::Record<'_>) {
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

    test_descs(&cl, &testdata);
}

fn test_descs(cl: &Client, testdata: &TestData) {
    // K : Compressed key available
    // K!: Compressed key with corresponding secret key unknown
    // X: X-only key available
    // X!: X-only key with corresponding secret key unknown

    // Test 1: Simple spend with internal key
    let wit = test_desc::test_desc_satisfy(cl, testdata, "tr(X)");
    assert!(wit.len() == 1);

    // Test 2: Same as above, but with leaves
    let wit = test_desc::test_desc_satisfy(cl, testdata, "tr(X,{pk(X1!),pk(X2!)})");
    assert!(wit.len() == 1);

    // Test 3: Force to spend with script spend. Unknown internal key and only one known script path
    // X! -> Internal key unknown
    // Leaf 1 -> pk(X1) with X1 known
    // Leaf 2-> and_v(v:pk(X2),pk(X3!)) with partial witness only to X2 known
    let wit = test_desc::test_desc_satisfy(cl, testdata, "tr(X!,{pk(X1),and_v(v:pk(X2),pk(X3!))})");
    assert!(wit.len() == 3); // control block, script and signature

    // Test 4: Force to spend with script spend. Unknown internal key and multiple script paths
    // Should select the one with minimum weight
    // X! -> Internal key unknown
    // Leaf 1 -> pk(X1!) with X1 unknown
    // Leaf 2-> and_v(v:pk(X2),pk(X3)) X2 and X3 known
    let wit = test_desc::test_desc_satisfy(cl, testdata, "tr(X!,{pk(X1),and_v(v:pk(X2),pk(X3))})");
    assert!(wit.len() == 3); // control block, script and one signatures

    // Test 5: When everything is available, we should select the key spend path
    let wit = test_desc::test_desc_satisfy(cl, testdata, "tr(X,{pk(X1),and_v(v:pk(X2),pk(X3!))})");
    assert!(wit.len() == 1); // control block, script and signature

    // Test 6: Test the new multi_a opcodes
    test_desc::test_desc_satisfy(cl, testdata, "tr(X!,{pk(X1!),multi_a(1,X2,X3!,X4!,X5!)})");
    test_desc::test_desc_satisfy(cl, testdata, "tr(X!,{pk(X1!),multi_a(2,X2,X3,X4!,X5!)})");
    test_desc::test_desc_satisfy(cl, testdata, "tr(X!,{pk(X1!),multi_a(3,X2,X3,X4,X5!)})");
    test_desc::test_desc_satisfy(cl, testdata, "tr(X!,{pk(X1!),multi_a(4,X2,X3,X4,X5)})");

    // Misc tests for other descriptors that we support
    // Keys
    test_desc::test_desc_satisfy(cl, testdata, "wpkh(K)");
    test_desc::test_desc_satisfy(cl, testdata, "pkh(K)");
    test_desc::test_desc_satisfy(cl, testdata, "sh(wpkh(K))");

    // sorted multi
    test_desc::test_desc_satisfy(cl, testdata, "sh(sortedmulti(2,K1,K2,K3))");
    test_desc::test_desc_satisfy(cl, testdata, "wsh(sortedmulti(2,K1,K2,K3))");
    test_desc::test_desc_satisfy(cl, testdata, "sh(wsh(sortedmulti(2,K1,K2,K3)))");

    // Miniscripts
    test_desc::test_desc_satisfy(cl, testdata, "sh(and_v(v:pk(K1),pk(K2)))");
    test_desc::test_desc_satisfy(cl, testdata, "wsh(and_v(v:pk(K1),pk(K2)))");
    test_desc::test_desc_satisfy(cl, testdata, "sh(wsh(and_v(v:pk(K1),pk(K2))))");
}
