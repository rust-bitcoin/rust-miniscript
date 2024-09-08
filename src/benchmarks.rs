// Written in 2019 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Benchmarks
//!
//! Benchmarks using the built-in rustc benchmark infrastructure. Requires a
//! nightly compiler to run. See the README for exact instructions.
//!

use test::{black_box, Bencher};

use crate::expression::Tree;
use crate::miniscript::context;
use crate::{Miniscript, ExtParams};

    #[bench]
    pub fn parse_segwit0(bh: &mut Bencher) {
        bh.iter(|| {
            let tree = Miniscript::<String, context::Segwitv0>::from_str_ext(
                "and_v(v:pk(E),thresh(2,j:and_v(v:sha256(H),t:or_i(v:sha256(H),v:pkh(A))),s:pk(B),s:pk(C),s:pk(D),sjtv:sha256(H)))",
                &ExtParams::sane(),
            ).unwrap();
            black_box(tree);
        });
    }

    #[bench]
    pub fn parse_segwit0_deep(bh: &mut Bencher) {
        bh.iter(|| {
            let tree = Miniscript::<String, context::Segwitv0>::from_str_ext(
                "and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:pk(1),pk(2)),pk(3)),pk(4)),pk(5)),pk(6)),pk(7)),pk(8)),pk(9)),pk(10)),pk(11)),pk(12)),pk(13)),pk(14)),pk(15)),pk(16)),pk(17)),pk(18)),pk(19)),pk(20)),pk(21))",
                &ExtParams::sane(),
            ).unwrap();
            black_box(tree);
        });
    }

    #[bench]
    pub fn parse_tree(bh: &mut Bencher) {
        bh.iter(|| {
            let tree = Tree::from_str(
                "and(thresh(2,and(sha256(H),or(sha256(H),pk(A))),pk(B),pk(C),pk(D),sha256(H)),pk(E))",
            ).unwrap();
            black_box(tree);
        });
    }

    #[bench]
    pub fn parse_tree_deep(bh: &mut Bencher) {
        bh.iter(|| {
            let tree = Tree::from_str(
                "and(and(and(and(and(and(and(and(and(and(and(and(and(and(and(and(and(and(and(and(1,2),3),4),5),6),7),8),9),10),11),12),13),14),15),16),17),18),19),20),21)"
            ).unwrap();
            black_box(tree);
        });
    }

#[cfg(feature = "compiler")]
mod compiler_benches {
    use super::*;

    use core::str::FromStr;

    use crate::Error;
    use crate::policy::Concrete;
    use crate::policy::compiler::CompilerError;
    use crate::descriptor::Descriptor;
    use crate::miniscript::Tap;
    use crate::prelude::*;

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
