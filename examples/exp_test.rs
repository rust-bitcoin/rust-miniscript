use miniscript::Descriptor;
use std::str::FromStr;

fn test_one_descriptor(descriptor: &str) -> bool {
    let res = Descriptor::<String>::from_str(descriptor);
    match res {
        Ok(_) => true,
        Err(err) => {
            println!("{}", err);
            false
        }
    }
}

fn main() {
    dbg!("inside test");
    assert!(test_one_descriptor("pk(musig(a))"));
    // assert!(test_one_descriptor("pk(musig(a,b))"));
    // assert!(test_one_descriptor("pk(musig(a,musig(b,c,d)))"));
    // assert!(test_one_descriptor("sh(multi(2,musig(a,b),k1,k2))"));
    // assert!(test_one_descriptor("pk(musig(musig(a,b),musig(c,d)))"));
    // assert!(test_one_descriptor(
    //     "pk(musig(a,musig(b,c,musig(d,e,f,musig(g,h,i))),j))"
    // ));
    // assert!(test_one_descriptor(
    //     "sh(sortedmulti(3,k1,musig(a,b),musig(musig(c,d))))"
    // ));
    // Need to test, cases which can give errors
    // assert!(!test_one_descriptor("pk(musig(a,b),musig(c))"));
    // assert!(!test_one_descriptor("pk(k1,k2)"));
}