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
            assert_eq!(
                old.to_string(),
                new.to_string(),
                "input {} (left is old, right is new)",
                data_str
            );

            // The current crate's semantic::Policy Display was changed to
            // mathematical notation, which does not match old_miniscript's
            // function-call format. Use to_policy_syntax_string() to
            // serialize in the policy-syntax form so we can still do a full
            // structural comparison across crate versions.
            {
                use miniscript::policy::Liftable as _;
                use old_miniscript::policy::Liftable as _;

                match (new.lift(), old.lift()) {
                    (Err(_), Err(_)) => {}
                    (Ok(x), Err(e)) => {
                        panic!("new logic lifts {} as {:?}, old fails with {}", data_str, x, e)
                    }
                    (Err(e), Ok(x)) => {
                        panic!("old logic lifts {} as {:?}, new fails with {}", data_str, x, e)
                    }
                    (Ok(new_lift), Ok(old_lift)) => {
                        assert_eq!(
                            old_lift.to_string(),
                            new_lift.to_policy_syntax_string(),
                            "lifted semantic policy mismatch for input {} (left is old, right is new as policy-syntax string)",
                            data_str
                        );
                    }
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
