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

    // Test 7: Test script tree of depth 127 is valid, only X128 is known
    test_desc::test_desc_satisfy(cl, testdata, "tr(X!,{pk(X1!),{pk(X2!),{pk(X3!),{pk(X4!),{pk(X5!),{pk(X6!),{pk(X7!),{pk(X8!),{pk(X9!),{pk(X10!),{pk(X11!),{pk(X12!),{pk(X13!),{pk(X14!),{pk(X15!),{pk(X16!),{pk(X17!),{pk(X18!),{pk(X19!),{pk(X20!),{pk(X21!),{pk(X22!),{pk(X23!),{pk(X24!),{pk(X25!),{pk(X26!),{pk(X27!),{pk(X28!),{pk(X29!),{pk(X30!),{pk(X31!),{pk(X32!),{pk(X33!),{pk(X34!),{pk(X35!),{pk(X36!),{pk(X37!),{pk(X38!),{pk(X39!),{pk(X40!),{pk(X41!),{pk(X42!),{pk(X43!),{pk(X44!),{pk(X45!),{pk(X46!),{pk(X47!),{pk(X48!),{pk(X49!),{pk(X50!),{pk(X51!),{pk(X52!),{pk(X53!),{pk(X54!),{pk(X55!),{pk(X56!),{pk(X57!),{pk(X58!),{pk(X59!),{pk(X60!),{pk(X61!),{pk(X62!),{pk(X63!),{pk(X64!),{pk(X65!),{pk(X66!),{pk(X67!),{pk(X68!),{pk(X69!),{pk(X70!),{pk(X71!),{pk(X72!),{pk(X73!),{pk(X74!),{pk(X75!),{pk(X76!),{pk(X77!),{pk(X78!),{pk(X79!),{pk(X80!),{pk(X81!),{pk(X82!),{pk(X83!),{pk(X84!),{pk(X85!),{pk(X86!),{pk(X87!),{pk(X88!),{pk(X89!),{pk(X90!),{pk(X91!),{pk(X92!),{pk(X93!),{pk(X94!),{pk(X95!),{pk(X96!),{pk(X97!),{pk(X98!),{pk(X99!),{pk(X100!),{pk(X101!),{pk(X102!),{pk(X103!),{pk(X104!),{pk(X105!),{pk(X106!),{pk(X107!),{pk(X108!),{pk(X109!),{pk(X110!),{pk(X111!),{pk(X112!),{pk(X113!),{pk(X114!),{pk(X115!),{pk(X116!),{pk(X117!),{pk(X118!),{pk(X119!),{pk(X120!),{pk(X121!),{pk(X122!),{pk(X123!),{pk(X124!),{pk(X125!),{pk(X126!),{pk(X127!),pk(X128)}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}})");

    // Test 8: Test script tree of depth 128 is valid, only X129 is known
    test_desc::test_desc_satisfy(cl, testdata, "tr(X!,{pk(X1!),{pk(X2!),{pk(X3!),{pk(X4!),{pk(X5!),{pk(X6!),{pk(X7!),{pk(X8!),{pk(X9!),{pk(X10!),{pk(X11!),{pk(X12!),{pk(X13!),{pk(X14!),{pk(X15!),{pk(X16!),{pk(X17!),{pk(X18!),{pk(X19!),{pk(X20!),{pk(X21!),{pk(X22!),{pk(X23!),{pk(X24!),{pk(X25!),{pk(X26!),{pk(X27!),{pk(X28!),{pk(X29!),{pk(X30!),{pk(X31!),{pk(X32!),{pk(X33!),{pk(X34!),{pk(X35!),{pk(X36!),{pk(X37!),{pk(X38!),{pk(X39!),{pk(X40!),{pk(X41!),{pk(X42!),{pk(X43!),{pk(X44!),{pk(X45!),{pk(X46!),{pk(X47!),{pk(X48!),{pk(X49!),{pk(X50!),{pk(X51!),{pk(X52!),{pk(X53!),{pk(X54!),{pk(X55!),{pk(X56!),{pk(X57!),{pk(X58!),{pk(X59!),{pk(X60!),{pk(X61!),{pk(X62!),{pk(X63!),{pk(X64!),{pk(X65!),{pk(X66!),{pk(X67!),{pk(X68!),{pk(X69!),{pk(X70!),{pk(X71!),{pk(X72!),{pk(X73!),{pk(X74!),{pk(X75!),{pk(X76!),{pk(X77!),{pk(X78!),{pk(X79!),{pk(X80!),{pk(X81!),{pk(X82!),{pk(X83!),{pk(X84!),{pk(X85!),{pk(X86!),{pk(X87!),{pk(X88!),{pk(X89!),{pk(X90!),{pk(X91!),{pk(X92!),{pk(X93!),{pk(X94!),{pk(X95!),{pk(X96!),{pk(X97!),{pk(X98!),{pk(X99!),{pk(X100!),{pk(X101!),{pk(X102!),{pk(X103!),{pk(X104!),{pk(X105!),{pk(X106!),{pk(X107!),{pk(X108!),{pk(X109!),{pk(X110!),{pk(X111!),{pk(X112!),{pk(X113!),{pk(X114!),{pk(X115!),{pk(X116!),{pk(X117!),{pk(X118!),{pk(X119!),{pk(X120!),{pk(X121!),{pk(X122!),{pk(X123!),{pk(X124!),{pk(X125!),{pk(X126!),{pk(X127!),{pk(X128!),pk(X129)}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}})");
    
    // Test 9: Test script complete tree having 128 leaves with depth log(128), only X1 is known
    test_desc::test_desc_satisfy(cl, testdata, "tr(X!,{{{{{{{pk(X1),pk(X2!)},{pk(X3!),pk(X4!)}},{{pk(X5!),pk(X6!)},{pk(X7!),pk(X8!)}}},{{{pk(X9!),pk(X10!)},{pk(X11!),pk(X12!)}},{{pk(X13!),pk(X14!)},{pk(X15!),pk(X16!)}}}},{{{{pk(X17!),pk(X18!)},{pk(X19!),pk(X20!)}},{{pk(X21!),pk(X22!)},{pk(X23!),pk(X24!)}}},{{{pk(X25!),pk(X26!)},{pk(X27!),pk(X28!)}},{{pk(X29!),pk(X30!)},{pk(X31!),pk(X32!)}}}}},{{{{{pk(X33!),pk(X34!)},{pk(X35!),pk(X36!)}},{{pk(X37!),pk(X38!)},{pk(X39!),pk(X40!)}}},{{{pk(X41!),pk(X42!)},{pk(X43!),pk(X44!)}},{{pk(X45!),pk(X46!)},{pk(X47!),pk(X48!)}}}},{{{{pk(X49!),pk(X50!)},{pk(X51!),pk(X52!)}},{{pk(X53!),pk(X54!)},{pk(X55!),pk(X56!)}}},{{{pk(X57!),pk(X58!)},{pk(X59!),pk(X60!)}},{{pk(X61!),pk(X62!)},{pk(X63!),pk(X64!)}}}}}},{{{{{{pk(X65!),pk(X66!)},{pk(X67!),pk(X68!)}},{{pk(X69!),pk(X70!)},{pk(X71!),pk(X72!)}}},{{{pk(X73!),pk(X74!)},{pk(X75!),pk(X76!)}},{{pk(X77!),pk(X78!)},{pk(X79!),pk(X80!)}}}},{{{{pk(X81!),pk(X82!)},{pk(X83!),pk(X84!)}},{{pk(X85!),pk(X86!)},{pk(X87!),pk(X88!)}}},{{{pk(X89!),pk(X90!)},{pk(X91!),pk(X92!)}},{{pk(X93!),pk(X94!)},{pk(X95!),pk(X96!)}}}}},{{{{{pk(X97!),pk(X98!)},{pk(X99!),pk(X100!)}},{{pk(X101!),pk(X102!)},{pk(X103!),pk(X104!)}}},{{{pk(X105!),pk(X106!)},{pk(X107!),pk(X108!)}},{{pk(X109!),pk(X110!)},{pk(X111!),pk(X112!)}}}},{{{{pk(X113!),pk(X114!)},{pk(X115!),pk(X116!)}},{{pk(X117!),pk(X118!)},{pk(X119!),pk(X120!)}}},{{{pk(X121!),pk(X122!)},{pk(X123!),pk(X124!)}},{{pk(X125!),pk(X126!)},{pk(X127!),pk(X128!)}}}}}}})");

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
