// Written in 2019 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Benchmarks
//!
//! Benchmarks using the built-in rustc benchmark infrastructure. Requires a
//! nightly compiler to run. See the README for exact instructions.
//!

use core::str::FromStr;

use bitcoin::secp256k1::{Secp256k1, SecretKey};
use test::{black_box, Bencher};

use crate::descriptor::{SinglePub, SinglePubKey};
use crate::expression::Tree;
use crate::{Descriptor, DescriptorPublicKey};

type Desc = Descriptor<DescriptorPublicKey>;

fn keygen(n: u32) -> DescriptorPublicKey {
    let secp = Secp256k1::new();

    let mut sk = [0; 32];
    sk[31] = n as u8;
    sk[30] = (n >> 8) as u8;
    sk[29] = (n >> 16) as u8;
    sk[28] = (n >> 24) as u8;
    let sk = SecretKey::from_slice(&sk).unwrap();
    let pk = bitcoin::PublicKey { inner: sk.public_key(&secp), compressed: true };
    DescriptorPublicKey::Single(SinglePub { origin: None, key: SinglePubKey::FullKey(pk) })
}

/// Generate a balanced binary tree with a given number of nodes.
///
/// This method is extremely slow relative to parsing or even re-serializing
/// and should never be called from inside a benchmark.
fn generate_balanced_tree_str<CombFn>(n_nodes: usize, mut combfn: CombFn) -> String
where
    CombFn: FnMut(&str, &str) -> String,
{
    if n_nodes == 0 {
        return "1".into();
    }
    let mut count = 0;
    let mut leaf = || {
        count += 1;
        format!("pk({})", keygen(count))
    };

    let mut stack = vec![];
    for i in 0..n_nodes {
        stack.push(leaf());

        for _ in 0..(i + 1).trailing_zeros() {
            let right = stack.pop().unwrap();
            let left = stack.pop().unwrap();
            stack.push(combfn(&left, &right));
        }
    }
    assert_ne!(stack.len(), 0, "n_nodes checked above to be nonzero");

    while stack.len() > 1 {
        let right = stack.pop().unwrap();
        let left = stack.pop().unwrap();
        stack.push(combfn(&left, &right));
    }

    stack.pop().unwrap()
}

/// Generate a one-sided binary tree with a given number of nodes.
///
/// This method is extremely slow relative to parsing or even re-serializing
/// and should never be called from inside a benchmark.
fn generate_deep_tree_str<CombFn>(n_nodes: usize, mut combfn: CombFn) -> String
where
    CombFn: FnMut(&str, &str) -> String,
{
    if n_nodes == 0 {
        return "1".into();
    }
    let mut count = 0;
    let mut leaf = || {
        count += 1;
        format!("pk({})", keygen(count))
    };

    let mut stack = vec![];
    for i in 0..n_nodes {
        stack.push(leaf());

        if i > 0 {
            let right = stack.pop().unwrap();
            let left = stack.pop().unwrap();
            stack.push(combfn(&left, &right));
        }
    }
    assert_eq!(stack.len(), 1);
    stack.pop().unwrap()
}

macro_rules! benchmark {
    ($ty:ty, $name:ident, $genfn:expr, $n:expr, $topstr:expr; $comb:expr) => {
        #[bench]
        fn $name(bh: &mut Bencher) {
            let s = format!("{}({})", $topstr, $genfn($n, $comb));
            bh.iter(|| black_box(<$ty>::from_str(&s).unwrap()))
        }
    };
    ($ty:ty, $name:ident, $genfn:expr, $n:expr, $topstr:expr, parens $comb:expr) => {
        benchmark!($ty, $name, $genfn, $n, $topstr; |left, right| format!("{}({left},{right})", $comb));
    };
}

macro_rules! benchmark_tr {
    // Taproot we need to treat specially
    ($ty:ty, $name:ident, $genfn:expr, $n:expr; $comb:expr) => {
        #[bench]
        fn $name(bh: &mut Bencher) {
            let s = format!("tr(02b35c601492528601122c0807fa1f8bf987b9704dff438b2524d979b954e206fb,{})", $genfn($n, $comb));
            println!("{}", s);
            bh.iter(|| black_box(<$ty>::from_str(&s).unwrap()))
        }
    };
    ($ty:ty, $name:ident, $genfn:expr, $n:expr, parens $comb:expr) => {
        benchmark_tr!($ty, $name, $genfn, $n; |left, right| format!("{}({left},{right})", $comb));
    };
    ($ty:ty, $name:ident, $genfn:expr, $n:expr, braces) => {
        benchmark_tr!($ty, $name, $genfn, $n; |left, right| format!("{{{left},{right}}}"));
    };
}

macro_rules! balanced_expression {
    ($name:ident, $n:expr) => {
        benchmark!(Tree, $name, generate_balanced_tree_str, $n, "xyz", parens "xyz");
    }
}

macro_rules! deep_expression {
    ($name:ident, $n:expr) => {
        benchmark!(Tree, $name, generate_deep_tree_str, $n, "xyz", parens "xyz");
    }
}

macro_rules! balanced_segwit {
    ($name:ident, $n:expr) => {
        benchmark!(Desc, $name, generate_balanced_tree_str, $n, "wsh", parens "or_i");
    }
}

macro_rules! deep_segwit {
    ($name:ident, $n:expr) => {
        benchmark!(Desc, $name, generate_deep_tree_str, $n, "wsh", parens "or_i");
    }
}

macro_rules! balanced_segwit_thresh {
    ($name:ident, $n:expr) => {
        benchmark!(Desc, $name, generate_balanced_tree_str, $n, "wsh"; |l, r| format!("thresh(2,{l},a:{r})"));
    }
}

macro_rules! deep_segwit_thresh {
    ($name:ident, $n:expr) => {
        benchmark!(Desc, $name, generate_deep_tree_str, $n, "wsh"; |l, r| format!("thresh(2,{l},a:{r})"));
    }
}

macro_rules! taproot_bigscript {
    ($name:ident, $n:expr) => {
        benchmark_tr!(Desc, $name, generate_balanced_tree_str, $n, parens "or_i");
    }
}

macro_rules! taproot_bigtree {
    ($name:ident, $n:expr) => {
        benchmark_tr!(Desc, $name, generate_balanced_tree_str, $n, braces);
    };
}

macro_rules! deep_taproot_bigscript {
    ($name:ident, $n:expr) => {
        benchmark_tr!(Desc, $name, generate_deep_tree_str, $n, parens "or_i");
    }
}

macro_rules! deep_taproot_bigtree {
    ($name:ident, $n:expr) => {
        benchmark_tr!(Desc, $name, generate_deep_tree_str, $n, braces);
    };
}

// a, b, c, etc to make the output sort in the right order
balanced_expression!(parse_expression_balanced_a_0, 0);
balanced_expression!(parse_expression_balanced_b_1, 1);
balanced_expression!(parse_expression_balanced_c_2, 2);
balanced_expression!(parse_expression_balanced_d_5, 5);
balanced_expression!(parse_expression_balanced_e_10, 10);
balanced_expression!(parse_expression_balanced_f_20, 20);
balanced_expression!(parse_expression_balanced_g_50, 50);
balanced_expression!(parse_expression_balanced_h_100, 100);
balanced_expression!(parse_expression_balanced_i_200, 200);
balanced_expression!(parse_expression_balanced_j_500, 500);
balanced_expression!(parse_expression_balanced_k_1000, 1000);
balanced_expression!(parse_expression_balanced_l_2000, 2000);
balanced_expression!(parse_expression_balanced_m_5000, 5000);
balanced_expression!(parse_expression_balanced_n_10000, 10000);

deep_expression!(parse_expression_deep_a_0, 0);
deep_expression!(parse_expression_deep_b_1, 1);
deep_expression!(parse_expression_deep_c_2, 2);
deep_expression!(parse_expression_deep_d_5, 5);
deep_expression!(parse_expression_deep_e_10, 10);
deep_expression!(parse_expression_deep_f_20, 20);
deep_expression!(parse_expression_deep_g_50, 50);
deep_expression!(parse_expression_deep_h_100, 100);
deep_expression!(parse_expression_deep_i_200, 200);
deep_expression!(parse_expression_deep_j_300, 300);
deep_expression!(parse_expression_deep_j_400, 400);
// For "deep" benchmarks we hit max recursion depth and can't go farther

balanced_segwit!(parse_descriptor_balanced_segwit_a_0, 0);
balanced_segwit!(parse_descriptor_balanced_segwit_b_1, 1);
balanced_segwit!(parse_descriptor_balanced_segwit_c_10, 10);
balanced_segwit!(parse_descriptor_balanced_segwit_d_20, 20);
balanced_segwit!(parse_descriptor_balanced_segwit_e_40, 40);
balanced_segwit!(parse_descriptor_balanced_segwit_f_60, 60);
balanced_segwit!(parse_descriptor_balanced_segwit_g_80, 80);
balanced_segwit!(parse_descriptor_balanced_segwit_h_90, 90);
deep_segwit!(parse_descriptor_deep_segwit_a_0, 0);
deep_segwit!(parse_descriptor_deep_segwit_b_1, 1);
deep_segwit!(parse_descriptor_deep_segwit_c_10, 10);
deep_segwit!(parse_descriptor_deep_segwit_d_20, 20);
deep_segwit!(parse_descriptor_deep_segwit_e_40, 40);
deep_segwit!(parse_descriptor_deep_segwit_f_60, 60);
deep_segwit!(parse_descriptor_deep_segwit_g_80, 80);
deep_segwit!(parse_descriptor_deep_segwit_h_90, 90);
// With or_i construction we cannot segwit more than 94 keys without exceeding the max witness size.

balanced_segwit_thresh!(parse_descriptor_balanced_segwit_thresh_a_1, 1);
balanced_segwit_thresh!(parse_descriptor_balanced_segwit_thresh_b_10, 10);
balanced_segwit_thresh!(parse_descriptor_balanced_segwit_thresh_c_20, 20);
balanced_segwit_thresh!(parse_descriptor_balanced_segwit_thresh_d_40, 40);
balanced_segwit_thresh!(parse_descriptor_balanced_segwit_thresh_e_60, 60);
balanced_segwit_thresh!(parse_descriptor_balanced_segwit_thresh_f_80, 80);
balanced_segwit_thresh!(parse_descriptor_balanced_segwit_thresh_g_90, 90);
deep_segwit_thresh!(parse_descriptor_deep_segwit_thresh_a_1, 1);
deep_segwit_thresh!(parse_descriptor_deep_segwit_thresh_b_10, 10);
deep_segwit_thresh!(parse_descriptor_deep_segwit_thresh_c_20, 20);
deep_segwit_thresh!(parse_descriptor_deep_segwit_thresh_d_40, 40);
deep_segwit_thresh!(parse_descriptor_deep_segwit_thresh_e_60, 60);
deep_segwit_thresh!(parse_descriptor_deep_segwit_thresh_f_80, 80);
deep_segwit_thresh!(parse_descriptor_deep_segwit_thresh_g_90, 90);

//taproot_bigscript!(parse_descriptor_tr_oneleaf_a_0, 0); // See #734
taproot_bigscript!(parse_descriptor_tr_oneleaf_a_1, 1);
taproot_bigscript!(parse_descriptor_tr_oneleaf_b_10, 10);
taproot_bigscript!(parse_descriptor_tr_oneleaf_c_20, 20);
taproot_bigscript!(parse_descriptor_tr_oneleaf_d_50, 50);
taproot_bigscript!(parse_descriptor_tr_oneleaf_e_100, 100);
taproot_bigscript!(parse_descriptor_tr_oneleaf_f_200, 200);
taproot_bigscript!(parse_descriptor_tr_oneleaf_g_500, 500);
taproot_bigscript!(parse_descriptor_tr_oneleaf_h_1000, 1000);
taproot_bigscript!(parse_descriptor_tr_oneleaf_i_2000, 2000);
taproot_bigscript!(parse_descriptor_tr_oneleaf_j_5000, 5000);
taproot_bigscript!(parse_descriptor_tr_oneleaf_k_10000, 10000);

taproot_bigtree!(parse_descriptor_tr_bigtree_a_1, 1);
taproot_bigtree!(parse_descriptor_tr_bigtree_b_2, 2);
taproot_bigtree!(parse_descriptor_tr_bigtree_c_5, 5);
taproot_bigtree!(parse_descriptor_tr_bigtree_d_10, 10);
taproot_bigtree!(parse_descriptor_tr_bigtree_e_20, 20);
taproot_bigtree!(parse_descriptor_tr_bigtree_f_50, 50);
taproot_bigtree!(parse_descriptor_tr_bigtree_g_100, 100);
taproot_bigtree!(parse_descriptor_tr_bigtree_h_200, 200);
taproot_bigtree!(parse_descriptor_tr_bigtree_i_500, 500);
taproot_bigtree!(parse_descriptor_tr_bigtree_j_1000, 1000);
taproot_bigtree!(parse_descriptor_tr_bigtree_k_2000, 2000);
taproot_bigtree!(parse_descriptor_tr_bigtree_l_5000, 5000);
taproot_bigtree!(parse_descriptor_tr_bigtree_m_10000, 10000);

deep_taproot_bigscript!(parse_descriptor_tr_deep_oneleaf_a_1, 1);
deep_taproot_bigscript!(parse_descriptor_tr_deep_oneleaf_b_10, 10);
deep_taproot_bigscript!(parse_descriptor_tr_deep_oneleaf_c_20, 20);
deep_taproot_bigscript!(parse_descriptor_tr_deep_oneleaf_d_50, 50);
deep_taproot_bigscript!(parse_descriptor_tr_deep_oneleaf_e_100, 100);
deep_taproot_bigscript!(parse_descriptor_tr_deep_oneleaf_f_200, 200);

deep_taproot_bigtree!(parse_descriptor_tr_deep_bigtree_a_1, 1);
deep_taproot_bigtree!(parse_descriptor_tr_deep_bigtree_b_2, 2);
deep_taproot_bigtree!(parse_descriptor_tr_deep_bigtree_c_5, 5);
deep_taproot_bigtree!(parse_descriptor_tr_deep_bigtree_d_10, 10);
deep_taproot_bigtree!(parse_descriptor_tr_deep_bigtree_e_20, 20);
deep_taproot_bigtree!(parse_descriptor_tr_deep_bigtree_f_50, 50);
deep_taproot_bigtree!(parse_descriptor_tr_deep_bigtree_g_100, 100);
deep_taproot_bigtree!(parse_descriptor_tr_deep_bigtree_h_128, 128);
// taproot trees are not allowed to be 129 deep

#[cfg(feature = "compiler")]
mod compiler_benches {
    use super::*;
    use crate::descriptor::Descriptor;
    use crate::miniscript::Tap;
    use crate::policy::compiler::CompilerError;
    use crate::policy::Concrete;
    use crate::prelude::*;
    use crate::Error;

    type TapMsRes = Result<Miniscript<String, Tap>, CompilerError>;
    type TapDesc = Result<Descriptor<String>, Error>;

    #[bench]
    pub fn compile_large_tap(bh: &mut Bencher) {
        let pol = Concrete::<String>::from_str(
            "thresh(20,pk(A),pk(B),pk(C),pk(D),pk(E),pk(F),pk(G),pk(H),pk(I),pk(J),pk(K),pk(L),pk(M),pk(N),pk(O),pk(P),pk(Q),pk(R),pk(S),pk(T),pk(U),pk(V),pk(W),pk(X),pk(Y),pk(Z))",
        )
        .expect("parsing");
        bh.iter(|| {
            let pt: TapDesc = pol.compile_tr_private_experimental(Some("UNSPEND".to_string()));
            black_box(pt).unwrap();
        });
    }

    #[bench]
    pub fn compile_basic(bh: &mut Bencher) {
        let h = (0..64).map(|_| "a").collect::<String>();
        let pol = Concrete::<String>::from_str(&format!(
            "and(thresh(2,and(sha256({}),or(sha256({}),pk(A))),pk(B),pk(C),pk(D),sha256({})),pk(E))",
            h, h, h
        ))
        .expect("parsing");
        bh.iter(|| {
            let pt: TapMsRes = pol.compile();
            black_box(pt).unwrap();
        });
    }

    #[bench]
    pub fn compile_large(bh: &mut Bencher) {
        let h = (0..64).map(|_| "a").collect::<String>();
        let pol = Concrete::<String>::from_str(
            &format!("or(pk(L),thresh(9,sha256({}),pk(A),pk(B),and(or(pk(C),pk(D)),pk(E)),after(100),pk(F),pk(G),pk(H),pk(I),and(pk(J),pk(K))))", h)
        ).expect("parsing");
        bh.iter(|| {
            let pt: TapMsRes = pol.compile();
            black_box(pt).unwrap();
        });
    }

    #[bench]
    pub fn compile_xlarge(bh: &mut Bencher) {
        let pol = Concrete::<String>::from_str(
            "or(pk(A),thresh(4,pk(B),older(100),pk(C),and(after(100),or(pk(D),or(pk(E),and(pk(F),thresh(2,pk(G),or(pk(H),and(thresh(5,pk(I),or(pk(J),pk(K)),pk(L),pk(M),pk(N),pk(O),pk(P),pk(Q),pk(R),pk(S),pk(T)),pk(U))),pk(V),or(and(pk(W),pk(X)),pk(Y)),after(100)))))),pk(Z)))"
        ).expect("parsing");
        bh.iter(|| {
            let pt: TapMsRes = pol.compile();
            black_box(pt).unwrap();
        });
    }
}
