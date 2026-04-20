use std::collections::{HashMap, HashSet};

use descriptor_fuzz::FuzzPk;
use honggfuzz::fuzz;
use miniscript::descriptor::Tr;
use old_miniscript::descriptor::Tr as OldTr;

fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data);
    match (data_str.parse::<Tr<FuzzPk>>(), data_str.parse::<OldTr<FuzzPk>>()) {
        (Err(_), Err(_)) => {}
        (Ok(_), Err(_)) => {} // 12.x logic rejects some parses for sanity reasons
        (Err(e), Ok(x)) => panic!("old logic parses {} as {:?}, new fails with {}", data_str, x, e),
        (Ok(new), Ok(old)) => {
            let new_si = new.spend_info();
            let old_si = old.spend_info();
            // The old and new crates each carry their own copy of `bitcoin` types, so we can't
            // compare the typed values directly. Compare their serialized byte representations
            // instead.
            // `internal_key()` yields an `UntweakedPublicKey` in both crates, but since new
            // bitcoin's `XOnlyPublicKey::serialize()` returns `([u8; 32], Parity)` while the old
            // one returns `[u8; 32]`, discard the parity on the new side to compare x-coords.
            assert_eq!(
                old_si.internal_key().serialize(),
                new_si.internal_key().serialize().0,
                "internal key mismatch (left is old, new is right)",
            );
            assert_eq!(
                old_si.merkle_root().as_ref().map(|h| {
                    use old_miniscript::bitcoin::hashes::Hash as _;
                    h.to_byte_array()
                }),
                new_si.merkle_root().as_ref().map(|h| h.to_byte_array()),
                "merkle root mismatch (left is old, new is right)",
            );
            assert_eq!(
                old_si.output_key().serialize(),
                new_si.output_key().serialize(),
                "output key mismatch (left is old, new is right)",
            );

            // Map every leaf script to a set of all the control blocks (keyed by script bytes).
            let mut new_cbs: HashMap<Vec<u8>, HashSet<Vec<u8>>> = HashMap::new();
            for leaf in new_si.leaves() {
                new_cbs
                    .entry(leaf.script().to_vec())
                    .or_default()
                    .insert(leaf.control_block().serialize());
            }
            // ...the old code will only ever yield one of them and it's not easy to predict which one
            for leaf in new_si.leaves() {
                let old_cb_bytes = {
                    use old_miniscript::bitcoin::taproot::LeafVersion;
                    let leaf_bytes: Vec<u8> = leaf.script().to_vec();
                    let script_buf =
                        old_miniscript::bitcoin::ScriptBuf::from_bytes(leaf_bytes.clone());
                    let leaf_ver = LeafVersion::from_consensus(
                        miniscript::bitcoin::taproot::LeafVersion::to_consensus(
                            leaf.leaf_version(),
                        ),
                    )
                    .expect("valid leaf version");
                    old_si
                        .control_block(&(script_buf, leaf_ver))
                        .unwrap()
                        .serialize()
                };
                assert!(new_cbs[&leaf.script().to_vec()].contains(&old_cb_bytes));
            }
        }
    }
}

fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn duplicate_crash() { crate::do_test(b"tr(0,{0,0})"); }
}
