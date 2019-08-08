// Miniscript
// Written in 2019 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Policy Compiler
//!
//! Optimizing compiler from concrete policies to Miniscript
//!

use std::collections::{hash_map, HashMap};
use std::{cmp, f64};

use miniscript::types::{self, ErrorKind, Property};
use policy::Concrete;
use std::sync::Arc;
use Terminal;
use {Miniscript, MiniscriptKey};

#[derive(Copy, Clone, PartialEq, PartialOrd, Debug)]
struct OrdF64(f64);

impl Eq for OrdF64 {}
impl Ord for OrdF64 {
    fn cmp(&self, other: &OrdF64) -> cmp::Ordering {
        // will panic if given NaN
        self.0.partial_cmp(&other.0).unwrap()
    }
}
#[derive(Copy, Clone, Debug)]
struct CompilerExtData {
    /// If this node is the direct child of a disjunction, this field must
    /// have the probability of its branch being taken. Otherwise it is ignored.
    /// All functions initialize it to `None`.
    branch_prob: Option<f64>,
    /// The number of bytes needed to satisfy the fragment in segwit format
    /// (total length of all witness pushes, plus their own length prefixes)
    sat_cost: f64,
    /// The number of bytes needed to dissatisfy the fragment in segwit format
    /// (total length of all witness pushes, plus their own length prefixes)
    /// for fragments that can be dissatisfied without failing the script.
    dissat_cost: Option<f64>,
}

impl Property for CompilerExtData {
    fn from_true() -> Self {
        // only used in casts. should never be computed directly
        unreachable!();
    }

    fn from_false() -> Self {
        // only used in casts. should never be computed directly
        unreachable!();
    }

    fn from_pk() -> Self {
        CompilerExtData {
            branch_prob: None,
            sat_cost: 73.0,
            dissat_cost: Some(1.0),
        }
    }

    fn from_pk_h() -> Self {
        CompilerExtData {
            branch_prob: None,
            sat_cost: 73.0 + 34.0,
            dissat_cost: Some(1.0 + 34.0),
        }
    }

    fn from_multi(k: usize, _n: usize) -> Self {
        CompilerExtData {
            branch_prob: None,
            sat_cost: 1.0 + 73.0 * k as f64,
            dissat_cost: Some(1.0 * (k + 1) as f64),
        }
    }

    fn from_hash() -> Self {
        // never called directly
        unreachable!()
    }

    fn from_sha256() -> Self {
        CompilerExtData {
            branch_prob: None,
            sat_cost: 33.0,
            dissat_cost: Some(33.0),
        }
    }

    fn from_hash256() -> Self {
        CompilerExtData {
            branch_prob: None,
            sat_cost: 33.0,
            dissat_cost: Some(33.0),
        }
    }

    fn from_ripemd160() -> Self {
        CompilerExtData {
            branch_prob: None,
            sat_cost: 33.0,
            dissat_cost: Some(33.0),
        }
    }

    fn from_hash160() -> Self {
        CompilerExtData {
            branch_prob: None,
            sat_cost: 33.0,
            dissat_cost: Some(33.0),
        }
    }

    fn from_time(_t: u32) -> Self {
        CompilerExtData {
            branch_prob: None,
            sat_cost: 0.0,
            dissat_cost: None,
        }
    }

    fn cast_alt(self) -> Result<Self, types::ErrorKind> {
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: self.sat_cost,
            dissat_cost: self.dissat_cost,
        })
    }

    fn cast_swap(self) -> Result<Self, types::ErrorKind> {
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: self.sat_cost,
            dissat_cost: self.dissat_cost,
        })
    }

    fn cast_check(self) -> Result<Self, types::ErrorKind> {
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: self.sat_cost,
            dissat_cost: self.dissat_cost,
        })
    }

    fn cast_dupif(self) -> Result<Self, types::ErrorKind> {
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: 2.0 + self.sat_cost,
            dissat_cost: Some(1.0),
        })
    }

    fn cast_verify(self) -> Result<Self, types::ErrorKind> {
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: self.sat_cost,
            dissat_cost: None,
        })
    }

    fn cast_nonzero(self) -> Result<Self, types::ErrorKind> {
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: self.sat_cost,
            dissat_cost: Some(1.0),
        })
    }

    fn cast_zeronotequal(self) -> Result<Self, types::ErrorKind> {
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: self.sat_cost,
            dissat_cost: self.dissat_cost,
        })
    }

    fn cast_true(self) -> Result<Self, types::ErrorKind> {
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: self.sat_cost,
            dissat_cost: None,
        })
    }

    fn cast_or_i_false(self) -> Result<Self, types::ErrorKind> {
        // never called directly
        unreachable!()
    }

    fn cast_unlikely(self) -> Result<Self, types::ErrorKind> {
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: 2.0 + self.sat_cost,
            dissat_cost: Some(1.0),
        })
    }

    fn cast_likely(self) -> Result<Self, types::ErrorKind> {
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: 1.0 + self.sat_cost,
            dissat_cost: Some(2.0),
        })
    }

    fn and_b(left: Self, right: Self) -> Result<Self, types::ErrorKind> {
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: left.sat_cost + right.sat_cost,
            dissat_cost: match (left.dissat_cost, right.dissat_cost) {
                (Some(l), Some(r)) => Some(l + r),
                _ => None,
            },
        })
    }

    fn and_v(left: Self, right: Self) -> Result<Self, types::ErrorKind> {
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: left.sat_cost + right.sat_cost,
            dissat_cost: None,
        })
    }

    fn or_b(l: Self, r: Self) -> Result<Self, types::ErrorKind> {
        let lprob = l
            .branch_prob
            .expect("BUG: left branch prob must be set for disjunctions");
        let rprob = r
            .branch_prob
            .expect("BUG: right branch prob must be set for disjunctions");
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: lprob * (l.sat_cost + r.dissat_cost.unwrap())
                + rprob * (r.sat_cost + l.dissat_cost.unwrap()),
            dissat_cost: Some(l.dissat_cost.unwrap() + r.dissat_cost.unwrap()),
        })
    }

    fn or_d(l: Self, r: Self) -> Result<Self, types::ErrorKind> {
        let lprob = l
            .branch_prob
            .expect("BUG: left branch prob must be set for disjunctions");
        let rprob = r
            .branch_prob
            .expect("BUG: right branch prob must be set for disjunctions");
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: lprob * l.sat_cost + rprob * (r.sat_cost + l.dissat_cost.unwrap()),
            dissat_cost: r.dissat_cost.map(|rd| l.dissat_cost.unwrap() + rd),
        })
    }

    fn or_c(l: Self, r: Self) -> Result<Self, types::ErrorKind> {
        let lprob = l
            .branch_prob
            .expect("BUG: left branch prob must be set for disjunctions");
        let rprob = r
            .branch_prob
            .expect("BUG: right branch prob must be set for disjunctions");
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: lprob * l.sat_cost + rprob * (r.sat_cost + l.dissat_cost.unwrap()),
            dissat_cost: None,
        })
    }

    fn or_i(l: Self, r: Self) -> Result<Self, types::ErrorKind> {
        let lprob = l
            .branch_prob
            .expect("BUG: left branch prob must be set for disjunctions");
        let rprob = r
            .branch_prob
            .expect("BUG: right branch prob must be set for disjunctions");
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: lprob * (2.0 + l.sat_cost) + rprob * (1.0 + r.sat_cost),
            dissat_cost: if let Some(ldis) = l.dissat_cost {
                Some(2.0 + ldis)
            } else if let Some(rdis) = r.dissat_cost {
                Some(1.0 + rdis)
            } else {
                None
            },
        })
    }

    fn and_or(_a: Self, _b: Self, _c: Self) -> Result<Self, types::ErrorKind> {
        unimplemented!("compiler doesn't support andor yet")
    }

    fn threshold<S>(k: usize, n: usize, mut sub_ck: S) -> Result<Self, types::ErrorKind>
    where
        S: FnMut(usize) -> Result<Self, types::ErrorKind>,
    {
        let k_over_n = k as f64 / n as f64;
        let mut sat_cost = 0.0;
        let mut dissat_cost = 0.0;
        for i in 0..n {
            let sub = sub_ck(i)?;
            sat_cost += sub.sat_cost;
            dissat_cost += sub.dissat_cost.unwrap();
        }
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: sat_cost * k_over_n,
            dissat_cost: Some(dissat_cost),
        })
    }
}

/// Miniscript AST fragment with additional data needed by the compiler
#[derive(Clone, Debug)]
struct AstElemExt<Pk: MiniscriptKey> {
    /// The actual Miniscript fragment with type information
    ms: Arc<Miniscript<Pk>>,
    /// Its "type" in terms of compiler data
    comp_ext_data: CompilerExtData,
}

impl CompilerExtData {
    /// Compute a 1-dimensional cost, given a probability of satisfaction
    /// and a probability of dissatisfaction; if `dissat_prob` is `None`
    /// then it is assumed that dissatisfaction never occurs
    fn cost_1d(&self, pk_cost: usize, sat_prob: f64, dissat_prob: Option<f64>) -> f64 {
        pk_cost as f64
            + self.sat_cost * sat_prob
            + match (dissat_prob, self.dissat_cost) {
                (Some(prob), Some(cost)) => prob * cost,
                (Some(_), None) => unreachable!(),
                (None, Some(_)) => 0.0,
                (None, None) => 0.0,
            }
    }
}

impl<Pk: MiniscriptKey> AstElemExt<Pk> where {
    fn terminal(ast: Terminal<Pk>) -> AstElemExt<Pk> {
        AstElemExt {
            comp_ext_data: CompilerExtData::type_check(&ast, |_| None).unwrap(),
            ms: Arc::new(Miniscript::from_ast(ast).expect("Terminal creation must always succeed")),
        }
    }

    fn nonterminal(
        ast: Terminal<Pk>,
        l: &AstElemExt<Pk>,
        r: &AstElemExt<Pk>,
    ) -> Result<AstElemExt<Pk>, types::Error<Pk>> {
        let lookup_ext = |n| match n {
            0 => Some(l.comp_ext_data),
            1 => Some(r.comp_ext_data),
            _ => unreachable!(),
        };
        //Types and ExtData are already cached and stored in children. So, we can
        //type_check without cache. For Compiler extra data, we supply a cache.
        let ty = types::Type::type_check(&ast, |_| None)?;
        let ext = types::ExtData::type_check(&ast, |_| None)?;
        let comp_ext_data = CompilerExtData::type_check(&ast, lookup_ext)?;
        Ok(AstElemExt {
            ms: Arc::new(Miniscript {
                ty: ty,
                ext: ext,
                node: ast,
            }),
            comp_ext_data: comp_ext_data,
        })
    }
}

impl<Pk: MiniscriptKey> AstElemExt<Pk> {
    fn wrappings(&self, sat_prob: f64, dissat_prob: Option<f64>) -> WrappingIter<Pk> {
        WrappingIter::new(self, sat_prob, dissat_prob)
    }
}

#[derive(Copy, Clone)]
struct Cast<Pk: MiniscriptKey> {
    node: fn(Arc<Miniscript<Pk>>) -> Terminal<Pk>,
    ast_type: fn(types::Type) -> Result<types::Type, ErrorKind>,
    ext_data: fn(types::ExtData) -> Result<types::ExtData, ErrorKind>,
    comp_ext_data: fn(CompilerExtData) -> Result<CompilerExtData, types::ErrorKind>,
}

fn all_casts<Pk: MiniscriptKey>() -> [Cast<Pk>; 9] {
    [
        Cast {
            node: Terminal::Alt,
            ast_type: types::Type::cast_alt,
            ext_data: types::ExtData::cast_alt,
            comp_ext_data: CompilerExtData::cast_alt,
        },
        Cast {
            ext_data: types::ExtData::cast_swap,
            node: Terminal::Swap,
            ast_type: types::Type::cast_swap,
            comp_ext_data: CompilerExtData::cast_swap,
        },
        Cast {
            ext_data: types::ExtData::cast_check,
            node: Terminal::Check,
            ast_type: types::Type::cast_check,
            comp_ext_data: CompilerExtData::cast_check,
        },
        Cast {
            ext_data: types::ExtData::cast_dupif,
            node: Terminal::DupIf,
            ast_type: types::Type::cast_dupif,
            comp_ext_data: CompilerExtData::cast_dupif,
        },
        Cast {
            ext_data: types::ExtData::cast_verify,
            node: Terminal::Verify,
            ast_type: types::Type::cast_verify,
            comp_ext_data: CompilerExtData::cast_verify,
        },
        Cast {
            ext_data: types::ExtData::cast_nonzero,
            node: Terminal::NonZero,
            ast_type: types::Type::cast_nonzero,
            comp_ext_data: CompilerExtData::cast_nonzero,
        },
        Cast {
            ext_data: types::ExtData::cast_true,
            node: |ms| {
                Terminal::AndV(
                    ms,
                    Arc::new(
                        Miniscript::from_ast(Terminal::True).expect("True Miniscript creation"),
                    ),
                )
            },
            ast_type: types::Type::cast_true,
            comp_ext_data: CompilerExtData::cast_true,
        },
        Cast {
            ext_data: types::ExtData::cast_unlikely,
            node: |ms| {
                Terminal::OrI(
                    ms,
                    Arc::new(
                        Miniscript::from_ast(Terminal::False).expect("False Miniscript creation"),
                    ),
                )
            },
            ast_type: types::Type::cast_unlikely,
            comp_ext_data: CompilerExtData::cast_unlikely,
        },
        Cast {
            ext_data: types::ExtData::cast_likely,
            node: |ms| {
                Terminal::OrI(
                    Arc::new(
                        Miniscript::from_ast(Terminal::False).expect("False Miniscript creation"),
                    ),
                    ms,
                )
            },
            ast_type: types::Type::cast_likely,
            comp_ext_data: CompilerExtData::cast_likely,
        },
    ]
}

struct WrappingIter<Pk: MiniscriptKey> {
    /// Stack of indices of thus-far applied casts
    cast_stack: Vec<(usize, AstElemExt<Pk>)>,
    /// Set of types that we've already seen (and should ignore on
    /// future visits). Maps to the cheapest expected cost we've
    /// seen when constructing this type
    visited_types: HashMap<types::Type, f64>,
    /// Original un-casted astelem. Set to `None` when the iterator
    /// is exhausted
    origin: Option<AstElemExt<Pk>>,
    /// Probability that this fragment will be satisfied
    sat_prob: f64,
    /// Probability that this fragment will be dissatisfied
    dissat_prob: Option<f64>,
}

impl<Pk: MiniscriptKey> WrappingIter<Pk> {
    fn new(elem: &AstElemExt<Pk>, sat_prob: f64, dissat_prob: Option<f64>) -> WrappingIter<Pk> {
        WrappingIter {
            cast_stack: vec![],
            visited_types: HashMap::new(),
            origin: Some(elem.clone()),
            sat_prob: sat_prob,
            dissat_prob: dissat_prob,
        }
    }
}

impl<Pk: MiniscriptKey> Iterator for WrappingIter<Pk> {
    type Item = AstElemExt<Pk>;

    fn next(&mut self) -> Option<AstElemExt<Pk>> {
        let current = match self.cast_stack.last() {
            Some(&(_, ref astext)) => astext.clone(),
            None => match self.origin.as_ref() {
                Some(astext) => astext.clone(),
                None => return None,
            },
        };
        let all_casts = all_casts::<Pk>();

        // Try applying a new cast
        for i in 0..all_casts.len() {
            if let Ok(ms_type) = (all_casts[i].ast_type)(current.ms.ty) {
                if !ms_type.mall.non_malleable {
                    continue;
                }

                let comp_ext_data = (all_casts[i].comp_ext_data)(current.comp_ext_data)
                    .expect("if AST typeck passes then compiler ext typeck must");
                let ms_ext_data = (all_casts[i].ext_data)(current.ms.ext)
                    .expect("if AST typeck passes then ext typeck must");

                let cost =
                    comp_ext_data.cost_1d(ms_ext_data.pk_cost, self.sat_prob, self.dissat_prob);
                let old_best_cost = self
                    .visited_types
                    .get(&ms_type)
                    .map(|x| *x)
                    .unwrap_or(f64::INFINITY);

                if cost < old_best_cost {
                    let new_ext = AstElemExt {
                        ms: Arc::new(Miniscript {
                            node: (all_casts[i].node)(Arc::clone(&current.ms)),
                            ty: ms_type,
                            ext: ms_ext_data,
                        }),
                        comp_ext_data: comp_ext_data,
                    };
                    self.visited_types.insert(ms_type, cost);
                    self.cast_stack.push((i, new_ext));
                    return self.next();
                }
            }
        }
        // If none were applicable, return the current result
        match self.cast_stack.pop() {
            Some((_, astelem)) => Some(astelem),
            None => self.origin.take(),
        }
    }
}

fn insert_best<Pk: MiniscriptKey>(
    map: &mut HashMap<types::Type, AstElemExt<Pk>>,
    elem: AstElemExt<Pk>,
    sat_prob: f64,
    dissat_prob: Option<f64>,
) {
    match map.entry(elem.ms.ty) {
        hash_map::Entry::Vacant(x) => {
            x.insert(elem);
        }
        hash_map::Entry::Occupied(mut x) => {
            let existing = x.get_mut();
            if elem
                .comp_ext_data
                .cost_1d(elem.ms.ext.pk_cost, sat_prob, dissat_prob)
                < existing
                    .comp_ext_data
                    .cost_1d(existing.ms.ext.pk_cost, sat_prob, dissat_prob)
            {
                *existing = elem;
            }
        }
    }
}

fn insert_best_wrapped<Pk: MiniscriptKey>(
    map: &mut HashMap<types::Type, AstElemExt<Pk>>,
    data: AstElemExt<Pk>,
    sat_prob: f64,
    dissat_prob: Option<f64>,
) {
    for wrapped in data.wrappings(sat_prob, dissat_prob) {
        let mut wrap_dissat_prob = dissat_prob;
        match wrapped.ms.node {
            Terminal::DupIf(_) | Terminal::Verify(_) | Terminal::NonZero(_) => {
                wrap_dissat_prob = None
            }
            // propagate dissat prob for rest of the wrappers.
            _ => (),
        }
        insert_best(map, wrapped, sat_prob, wrap_dissat_prob);
    }
}

fn best_compilations<Pk: MiniscriptKey>(
    policy: &Concrete<Pk>,
    sat_prob: f64,
    dissat_prob: Option<f64>,
) -> HashMap<types::Type, AstElemExt<Pk>> {
    let mut ret = HashMap::new();
    match *policy {
        Concrete::Key(ref pk) => insert_best_wrapped(
            &mut ret,
            AstElemExt::terminal(Terminal::Pk(pk.clone())),
            sat_prob,
            dissat_prob,
        ),
        Concrete::After(n) => {
            insert_best_wrapped(
                &mut ret,
                AstElemExt::terminal(Terminal::After(n)),
                sat_prob,
                dissat_prob,
            );
        }
        Concrete::Older(n) => {
            insert_best_wrapped(
                &mut ret,
                AstElemExt::terminal(Terminal::Older(n)),
                sat_prob,
                dissat_prob,
            );
        }
        Concrete::Sha256(hash) => insert_best_wrapped(
            &mut ret,
            AstElemExt::terminal(Terminal::Sha256(hash)),
            sat_prob,
            dissat_prob,
        ),
        Concrete::Hash256(hash) => insert_best_wrapped(
            &mut ret,
            AstElemExt::terminal(Terminal::Hash256(hash)),
            sat_prob,
            dissat_prob,
        ),
        Concrete::Ripemd160(hash) => insert_best_wrapped(
            &mut ret,
            AstElemExt::terminal(Terminal::Ripemd160(hash)),
            sat_prob,
            dissat_prob,
        ),
        Concrete::Hash160(hash) => insert_best_wrapped(
            &mut ret,
            AstElemExt::terminal(Terminal::Hash160(hash)),
            sat_prob,
            dissat_prob,
        ),
        Concrete::And(ref subs) => {
            assert_eq!(subs.len(), 2, "and takes 2 args");
            let left = best_compilations(&subs[0], sat_prob, dissat_prob);
            let right = best_compilations(&subs[1], sat_prob, dissat_prob);
            for l in left.values() {
                let lref = Arc::clone(&l.ms);
                for r in right.values() {
                    #[derive(Clone)]
                    struct Try<'l, 'r, Pk: MiniscriptKey + 'l + 'r> {
                        left: &'l AstElemExt<Pk>,
                        right: &'r AstElemExt<Pk>,
                        ast: Terminal<Pk>,
                    }

                    impl<'l, 'r, Pk: MiniscriptKey + 'l + 'r> Try<'l, 'r, Pk> {
                        fn swap(self) -> Try<'r, 'l, Pk> {
                            Try {
                                left: self.right,
                                right: self.left,
                                ast: match self.ast {
                                    Terminal::AndB(l, r) => Terminal::AndB(r, l),
                                    Terminal::AndV(l, r) => Terminal::AndV(r, l),
                                    _ => unreachable!(),
                                },
                            }
                        }
                    }

                    let rref = Arc::clone(&r.ms);
                    let mut tries = [
                        Some(Terminal::AndB(Arc::clone(&lref), Arc::clone(&rref))),
                        Some(Terminal::AndV(Arc::clone(&lref), Arc::clone(&rref))),
                        // FIXME do and_n
                    ];
                    for opt in &mut tries {
                        let c = Try {
                            left: l,
                            right: r,
                            ast: opt.take().unwrap(),
                        };
                        let ast = c.ast.clone();
                        if let Ok(new_ext) = AstElemExt::nonterminal(ast, c.left, c.right) {
                            insert_best_wrapped(&mut ret, new_ext, sat_prob, dissat_prob);
                        }

                        let c = c.swap();
                        if let Ok(new_ext) = AstElemExt::nonterminal(c.ast, c.left, c.right) {
                            insert_best_wrapped(&mut ret, new_ext, sat_prob, dissat_prob);
                        }
                    }
                }
            }
        }
        Concrete::Or(ref subs) => {
            assert_eq!(subs.len(), 2, "or takes 2 args");
            // FIXME sat_prob and dissat_prob are wrong here
            let mut left = best_compilations(&subs[0].1, sat_prob, dissat_prob);
            let mut right = best_compilations(&subs[1].1, sat_prob, dissat_prob);
            let total = (subs[0].0 + subs[1].0) as f64;
            let lweight = subs[0].0 as f64 / total;
            let rweight = subs[1].0 as f64 / total;
            for l in left.values_mut() {
                let lref = Arc::clone(&l.ms);
                for r in right.values_mut() {
                    struct Try<'l, 'r, Pk: MiniscriptKey + 'l + 'r> {
                        left: &'l AstElemExt<Pk>,
                        right: &'r AstElemExt<Pk>,
                        ast: Terminal<Pk>,
                    }

                    impl<'l, 'r, Pk: MiniscriptKey + 'l + 'r> Try<'l, 'r, Pk> {
                        fn swap(self) -> Try<'r, 'l, Pk> {
                            Try {
                                left: self.right,
                                right: self.left,
                                ast: match self.ast {
                                    Terminal::OrB(l, r) => Terminal::OrB(r, l),
                                    Terminal::OrD(l, r) => Terminal::OrD(r, l),
                                    Terminal::OrC(l, r) => Terminal::OrC(r, l),
                                    Terminal::OrI(l, r) => Terminal::OrI(r, l),
                                    _ => unreachable!(),
                                },
                            }
                        }
                    }

                    let rref = Arc::clone(&r.ms);
                    let mut tries = [
                        Some(Terminal::OrB(Arc::clone(&lref), Arc::clone(&rref))),
                        Some(Terminal::OrD(Arc::clone(&lref), Arc::clone(&rref))),
                        Some(Terminal::OrC(Arc::clone(&lref), Arc::clone(&rref))),
                        Some(Terminal::OrI(Arc::clone(&lref), Arc::clone(&rref))),
                    ];
                    for opt in &mut tries {
                        l.comp_ext_data.branch_prob = Some(lweight);
                        r.comp_ext_data.branch_prob = Some(rweight);
                        let d = Try {
                            left: l,
                            right: r,
                            ast: opt.take().unwrap(),
                        };
                        let ast = d.ast.clone();
                        if let Ok(new_ext) = AstElemExt::nonterminal(ast, d.left, d.right) {
                            insert_best_wrapped(&mut ret, new_ext, sat_prob, dissat_prob);
                        }

                        let d = d.swap();
                        if let Ok(new_ext) = AstElemExt::nonterminal(d.ast, d.left, d.right) {
                            insert_best_wrapped(&mut ret, new_ext, sat_prob, dissat_prob);
                        }
                    }
                }
            }
        }
        Concrete::Threshold(k, ref subs) => {
            let n = subs.len();
            let k_over_n = k as f64 / n as f64;

            let mut sub_ast = Vec::with_capacity(n);
            let mut sub_ext_data = Vec::with_capacity(n);

            for (i, ast) in subs.iter().enumerate() {
                let sp = sat_prob * k_over_n;
                let dp = dissat_prob.map(|p| p + sat_prob * (1.0 - k_over_n));
                let best_ext = if i == 0 {
                    best_e(ast, sp, dp)
                } else {
                    best_w(ast, sp, dp)
                };
                sub_ast.push(best_ext.ms);
                sub_ext_data.push(best_ext.comp_ext_data);
            }

            let ast = Terminal::Thresh(k, sub_ast);
            let ast_ext = AstElemExt {
                ms: Arc::new(
                    Miniscript::from_ast(ast)
                        .expect("threshold subs, which we just compiled, typeck"),
                ),
                comp_ext_data: CompilerExtData::threshold(k, n, |i| Ok(sub_ext_data[i]))
                    .expect("threshold subs, which we just compiled, typeck"),
            };
            insert_best_wrapped(&mut ret, ast_ext, sat_prob, dissat_prob);

            let key_vec: Vec<Pk> = subs
                .iter()
                .filter_map(|s| {
                    if let Concrete::Key(ref pk) = *s {
                        Some(pk.clone())
                    } else {
                        None
                    }
                })
                .collect();
            if key_vec.len() == subs.len() && subs.len() <= 20 {
                insert_best_wrapped(
                    &mut ret,
                    AstElemExt::terminal(Terminal::ThreshM(k, key_vec)),
                    sat_prob,
                    dissat_prob,
                );
            }
        }
    }
    ret
}

pub fn best_compilation<Pk: MiniscriptKey>(policy: &Concrete<Pk>) -> Miniscript<Pk> {
    let x = &*best_t(policy, 1.0, None).ms;
    x.clone()
}

fn best_t<Pk: MiniscriptKey>(
    policy: &Concrete<Pk>,
    sat_prob: f64,
    dissat_prob: Option<f64>,
) -> AstElemExt<Pk> {
    best_compilations(policy, 1.0, None)
        .into_iter()
        .filter(|&(key, _)| key.corr.base == types::Base::B)
        .map(|(_, val)| val)
        .min_by_key(|ext| {
            OrdF64(
                ext.comp_ext_data
                    .cost_1d(ext.ms.ext.pk_cost, sat_prob, dissat_prob),
            )
        })
        .unwrap()
}

fn best_e<Pk: MiniscriptKey>(
    policy: &Concrete<Pk>,
    sat_prob: f64,
    dissat_prob: Option<f64>,
) -> AstElemExt<Pk> {
    best_compilations(policy, sat_prob, dissat_prob)
        .into_iter()
        .filter(|&(ref key, ref val)| {
            key.corr.base == types::Base::B
                && key.corr.unit
                && val.ms.ty.mall.dissat == types::Dissat::Unique
        })
        .map(|(_, val)| val)
        .min_by_key(|ext| {
            OrdF64(
                ext.comp_ext_data
                    .cost_1d(ext.ms.ext.pk_cost, sat_prob, dissat_prob),
            )
        })
        .unwrap()
}

fn best_w<Pk: MiniscriptKey>(
    policy: &Concrete<Pk>,
    sat_prob: f64,
    dissat_prob: Option<f64>,
) -> AstElemExt<Pk> {
    best_compilations(policy, sat_prob, dissat_prob)
        .into_iter()
        .filter(|&(ref key, ref val)| {
            key.corr.base == types::Base::W
                && key.corr.unit
                && val.ms.ty.mall.dissat == types::Dissat::Unique
        })
        .map(|(_, val)| val)
        .min_by_key(|ext| {
            OrdF64(
                ext.comp_ext_data
                    .cost_1d(ext.ms.ext.pk_cost, sat_prob, dissat_prob),
            )
        })
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin;
    use bitcoin::blockdata::{opcodes, script};
    use secp256k1;
    use std::str::FromStr;

    use hex_script;
    use policy::{Liftable, Semantic};
    use BitcoinSig;
    use DummyKey;
    use DummyKeyHash;
    use Satisfier;

    type SPolicy = Concrete<String>;
    type DummyPolicy = Concrete<DummyKey>;
    type BPolicy = Concrete<bitcoin::PublicKey>;

    fn pubkeys_and_a_sig(n: usize) -> (Vec<bitcoin::PublicKey>, secp256k1::Signature) {
        let mut ret = Vec::with_capacity(n);
        let secp = secp256k1::Secp256k1::new();
        let mut sk = [0; 32];
        for i in 1..n + 1 {
            sk[0] = i as u8;
            sk[1] = (i >> 8) as u8;
            sk[2] = (i >> 16) as u8;

            let pk = bitcoin::PublicKey {
                key: secp256k1::PublicKey::from_secret_key(
                    &secp,
                    &secp256k1::SecretKey::from_slice(&sk[..]).expect("sk"),
                ),
                compressed: true,
            };
            ret.push(pk);
        }
        let sig = secp.sign(
            &secp256k1::Message::from_slice(&sk[..]).expect("secret key"),
            &secp256k1::SecretKey::from_slice(&sk[..]).expect("secret key"),
        );
        (ret, sig)
    }

    #[test]
    fn compile_basic() {
        let policy = DummyPolicy::from_str("pk()").expect("parse");
        let miniscript = policy.compile();
        assert_eq!(policy.lift(), Semantic::KeyHash(DummyKeyHash));
        assert_eq!(miniscript.lift(), Semantic::KeyHash(DummyKeyHash));
    }

    #[test]
    fn compile_q() {
        let policy = SPolicy::from_str("or(1@and(pk(),pk()),127@pk())").expect("parsing");
        let compilation = best_t(&policy, 1.0, None);

        assert_eq!(
            compilation
                .comp_ext_data
                .cost_1d(compilation.ms.ext.pk_cost, 1.0, None),
            108.0 + 73.578125
        );
        assert_eq!(policy.lift().sorted(), compilation.ms.lift().sorted());

        /*
                let policy = SPolicy::from_str(
                    "and(and(and(or(127@thresh(2,pk(),pk(),thresh(2,or(127@pk(),1@pk()),after(100),or(and(pk(),after(200)),and(pk(),sha256(66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925))),pk())),1@pk()),sha256(66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925)),or(127@pk(),1@after(300))),or(127@after(400),pk()))"
                ).expect("parsing");
                    "thresh(2,after(100),pk(),pk())"
        */
        let policy = SPolicy::from_str(
            "and(and(and(or(127@thresh(2,pk(),pk(),thresh(2,or(127@pk(),1@pk()),after(100),or(and(pk(),after(200)),and(pk(),sha256(66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925))),pk())),1@pk()),sha256(66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925)),or(127@pk(),1@after(300))),or(127@after(400),pk()))"
        ).expect("parsing");
        let compilation = best_t(&policy, 1.0, None);
        assert_eq!(
            compilation
                .comp_ext_data
                .cost_1d(compilation.ms.ext.pk_cost, 1.0, None),
            770.5416666666666
        );
        assert_eq!(policy.lift().sorted(), compilation.ms.lift().sorted());
    }

    #[test]
    fn compile_misc() {
        let (keys, sig) = pubkeys_and_a_sig(10);
        let key_pol: Vec<BPolicy> = keys.iter().map(|k| Concrete::Key(*k)).collect();
        let policy: BPolicy = Concrete::After(100);
        let desc = policy.compile();
        assert_eq!(desc.encode(), hex_script("0164b2"));

        let policy: BPolicy = Concrete::Key(keys[0].clone());
        let desc = policy.compile();
        assert_eq!(
            desc.encode(),
            script::Builder::new()
                .push_key(&keys[0])
                .push_opcode(opcodes::all::OP_CHECKSIG)
                .into_script()
        );

        // CSV reordering trick
        let policy: BPolicy = policy_str!(
            "and(after(10000),thresh(2,pk({}),pk({}),pk({})))",
            keys[5],
            keys[6],
            keys[7]
        );
        let desc = policy.compile();
        assert_eq!(
            desc.encode(),
            script::Builder::new()
                .push_opcode(opcodes::all::OP_PUSHNUM_2)
                .push_key(&keys[5])
                .push_key(&keys[6])
                .push_key(&keys[7])
                .push_opcode(opcodes::all::OP_PUSHNUM_3)
                .push_opcode(opcodes::all::OP_CHECKMULTISIGVERIFY)
                .push_int(10000)
                .push_opcode(opcodes::OP_CSV)
                .into_script()
        );

        // Liquid policy
        let policy: BPolicy = Concrete::Or(vec![
            (127, Concrete::Threshold(3, key_pol[0..5].to_owned())),
            (
                1,
                Concrete::And(vec![
                    Concrete::After(10000),
                    Concrete::Threshold(2, key_pol[5..8].to_owned()),
                ]),
            ),
        ]);
        let desc = policy.compile();
        assert_eq!(
            desc.encode(),
            script::Builder::new()
                .push_opcode(opcodes::all::OP_PUSHNUM_3)
                .push_key(&keys[0])
                .push_key(&keys[1])
                .push_key(&keys[2])
                .push_key(&keys[3])
                .push_key(&keys[4])
                .push_opcode(opcodes::all::OP_PUSHNUM_5)
                .push_opcode(opcodes::all::OP_CHECKMULTISIG)
                .push_opcode(opcodes::all::OP_IFDUP)
                .push_opcode(opcodes::all::OP_NOTIF)
                .push_opcode(opcodes::all::OP_PUSHNUM_2)
                .push_key(&keys[5])
                .push_key(&keys[6])
                .push_key(&keys[7])
                .push_opcode(opcodes::all::OP_PUSHNUM_3)
                .push_opcode(opcodes::all::OP_CHECKMULTISIGVERIFY)
                .push_int(10000)
                .push_opcode(opcodes::OP_CSV)
                .push_opcode(opcodes::all::OP_ENDIF)
                .into_script()
        );

        let mut abs = policy.lift();
        assert_eq!(abs.n_keys(), 8);
        assert_eq!(abs.minimum_n_keys(), 2);
        abs = abs.at_age(10000);
        assert_eq!(abs.n_keys(), 8);
        assert_eq!(abs.minimum_n_keys(), 2);
        abs = abs.at_age(9999);
        assert_eq!(abs.n_keys(), 5);
        assert_eq!(abs.minimum_n_keys(), 3);
        abs = abs.at_age(0);
        assert_eq!(abs.n_keys(), 5);
        assert_eq!(abs.minimum_n_keys(), 3);

        let mut sigvec = sig.serialize_der();
        sigvec.push(1); // sighash all

        struct BadSat;
        struct GoodSat(secp256k1::Signature);
        struct LeftSat<'a>(&'a [bitcoin::PublicKey], secp256k1::Signature);

        impl<Pk: MiniscriptKey> Satisfier<Pk> for BadSat {}
        impl<Pk: MiniscriptKey> Satisfier<Pk> for GoodSat {
            fn lookup_pk(&self, _: &Pk) -> Option<BitcoinSig> {
                Some((self.0, bitcoin::SigHashType::All))
            }
        }
        impl<'a> Satisfier<bitcoin::PublicKey> for LeftSat<'a> {
            fn lookup_pk(&self, pk: &bitcoin::PublicKey) -> Option<BitcoinSig> {
                for (n, target_pk) in self.0.iter().enumerate() {
                    if pk == target_pk && n < 5 {
                        return Some((self.1, bitcoin::SigHashType::All));
                    }
                }
                None
            }
        }

        assert!(desc.satisfy(&BadSat, 0, 0).is_none());
        assert!(desc.satisfy(&GoodSat(sig), 0, 0).is_some());
        assert!(desc.satisfy(&LeftSat(&keys[..], sig), 0, 0).is_some());

        assert_eq!(
            desc.satisfy(&LeftSat(&keys[..], sig), 0, 0).unwrap(),
            vec![
                // sat for left branch
                vec![],
                sigvec.clone(),
                sigvec.clone(),
                sigvec.clone(),
            ]
        );

        assert_eq!(
            desc.satisfy(&GoodSat(sig), 10000, 0).unwrap(),
            vec![
                // sat for right branch
                vec![],
                sigvec.clone(),
                sigvec.clone(),
                // dissat for left branch
                vec![],
                vec![],
                vec![],
                vec![],
            ]
        );
    }
}

#[cfg(all(test, feature = "unstable"))]
mod benches {
    use secp256k1;
    use std::str::FromStr;
    use test::{black_box, Bencher};

    use Concrete;
    use ParseTree;

    #[bench]
    pub fn compile(bh: &mut Bencher) {
        let desc = Concrete::<secp256k1::PublicKey>::from_str(
            "and(thresh(2,and(sha256(),or(sha256(),pk())),pk(),pk(),pk(),sha256()),pkh())",
        )
        .expect("parsing");
        bh.iter(|| {
            let pt = ParseTree::compile(&desc);
            black_box(pt);
        });
    }

    #[bench]
    pub fn compile_large(bh: &mut Bencher) {
        let desc = Concrete::<secp256k1::PublicKey>::from_str(
            "or(pkh(),thresh(9,sha256(),pkh(),pk(),and(or(pkh(),pk()),pk()),time_e(),pk(),pk(),pk(),pk(),and(pk(),pk())))"
        ).expect("parsing");
        bh.iter(|| {
            let pt = ParseTree::compile(&desc);
            black_box(pt);
        });
    }

    #[bench]
    pub fn compile_xlarge(bh: &mut Bencher) {
        let desc = Concrete::<secp256k1::PublicKey>::from_str(
            "or(pk(),thresh(4,pkh(),time_e(),multi(),and(after(),or(pkh(),or(pkh(),and(pkh(),thresh(2,multi(),or(pkh(),and(thresh(5,sha256(),or(pkh(),pkh()),pkh(),pkh(),pkh(),multi(),pkh(),multi(),pk(),pkh(),pk()),pkh())),pkh(),or(and(pkh(),pk()),pk()),after()))))),pkh()))"
        ).expect("parsing");
        bh.iter(|| {
            let pt = ParseTree::compile(&desc);
            black_box(pt);
        });
    }
}
