
extern crate miniscript;

use miniscript::Miniscript;
use miniscript::bitcoin::blockdata::script;

fn do_test(data: &[u8]) {
    // Try round-tripping as a script
    let script = script::Script::from(data.to_owned());

    if let Ok(pt) = Miniscript::parse(&script) {
        let output = pt.encode();
        assert_eq!(pt.script_size(), output.len());
        assert_eq!(output, script);
    }
}

#[cfg(feature = "afl")]
extern crate afl;
#[cfg(feature = "afl")]
fn main() {
    afl::read_stdio_bytes(|data| {
        do_test(&data);
    });
}

#[cfg(feature = "honggfuzz")]
#[macro_use] extern crate honggfuzz;
#[cfg(feature = "honggfuzz")]
fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}
