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
            assert_eq!(
                old_si.internal_key(),
                new_si.internal_key(),
                "merkle root mismatch (left is old, new is right)",
            );
            assert_eq!(
                old_si.merkle_root(),
                new_si.merkle_root(),
                "merkle root mismatch (left is old, new is right)",
            );
            assert_eq!(
                old_si.output_key(),
                new_si.output_key(),
                "merkle root mismatch (left is old, new is right)",
            );
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
