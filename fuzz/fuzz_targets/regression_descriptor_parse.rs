use core::str::FromStr;

use honggfuzz::fuzz;
use miniscript::Descriptor;
use old_miniscript::Descriptor as OldDescriptor;

type Desc = Descriptor<descriptor_fuzz::FuzzPk>;
type OldDesc = OldDescriptor<descriptor_fuzz::FuzzPk>;

fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data);
    match (Desc::from_str(&data_str), OldDesc::from_str(&data_str)) {
        (Err(_), Err(_)) => {}
        (Ok(x), Err(e)) => panic!("new logic parses {} as {:?}, old fails with {}", data_str, x, e),
        (Err(e), Ok(x)) => panic!("old logic parses {} as {:?}, new fails with {}", data_str, x, e),
        (Ok(new), Ok(old)) => {
            use miniscript::policy::Liftable as _;
            use old_miniscript::policy::Liftable as _;

            assert_eq!(
                old.to_string(),
                new.to_string(),
                "input {} (left is old, right is new)",
                data_str
            );

            match (new.lift(), old.lift()) {
                (Err(_), Err(_)) => {}
                (Ok(x), Err(e)) => {
                    panic!("new logic lifts {} as {:?}, old fails with {}", data_str, x, e)
                }
                (Err(e), Ok(x)) => {
                    panic!("old logic lifts {} as {:?}, new fails with {}", data_str, x, e)
                }
                (Ok(new), Ok(old)) => {
                    assert_eq!(
                        old.to_string(),
                        new.to_string(),
                        "lifted input {} (left is old, right is new)",
                        data_str
                    )
                }
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
    fn duplicate_crash() { crate::do_test(b"tr(d,{0,{0,0}})") }
}
