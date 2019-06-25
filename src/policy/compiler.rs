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
use std::{cmp, f64, fmt};

use policy::Concrete;
use miniscript::astelem::AstElem;
use miniscript::types;

#[derive(Copy, Clone, PartialEq, PartialOrd, Debug)]
struct OrdF64(f64);

impl Eq for OrdF64 {}
impl Ord for OrdF64 {
    fn cmp(&self, other: &OrdF64) -> cmp::Ordering {
        // will panic if given NaN
        self.0.partial_cmp(&other.0).unwrap()
    }
}

/// Miniscript AST fragment with additional data needed by the compiler
#[derive(Clone, Debug)]
struct AstElemExt<Pk: Clone, Pkh: Clone> {
    /// The actual AST fragment
    ast: AstElem<Pk, Pkh>,
    /// Its (cached) type
    type_map: types::Type,
    /// The number of bytes needed to encode its scriptpubkey fragment
    pk_cost: usize,
    /// The number of bytes needed to satisfy the fragment in segwit format
    /// (total length of all witness pushes, plus their own length prefixes)
    sat_cost: f64,
    /// The number of bytes needed to dissatisfy the fragment in segwit format
    /// (total length of all witness pushes, plus their own length prefixes)
    /// for fragments that can be dissatisfied without failing the script.
    dissat_cost: Option<f64>,
}

impl<Pk, Pkh> AstElemExt<Pk, Pkh>
where
    Pk: Clone + fmt::Debug,
    Pkh: Clone + fmt::Debug,
{
    fn from_terminal(ast: AstElem<Pk, Pkh>) -> AstElemExt<Pk, Pkh> {
        let (pk_cost, sat_cost, dissat_cost) = match ast {
            AstElem::Pk(..) => (34, 73.0, Some(1.0)),
            AstElem::PkH(..) => (24, 73.0 + 34.0, None),
            AstElem::After(n) => (script_num_cost(n) + 1, 0.0, None),
            AstElem::Older(n) => (script_num_cost(n) + 1, 0.0, None),
            AstElem::Sha256(..) => (33 + 6, 33.0, None),
            AstElem::Hash256(..) => (33 + 6, 33.0, None),
            AstElem::Ripemd160(..) => (21 + 6, 33.0, None),
            AstElem::Hash160(..) => (21 + 6, 33.0, None),
            AstElem::True
                | AstElem::False => unreachable!(), // only used in casts
            AstElem::ThreshM(k, ref keys) => {
                let num_cost = match(k > 16, keys.len() > 16) {
                    (true, true) => 4,
                    (false, true) => 3,
                    (true, false) => 3,
                    (false, false) => 2,
                };
                (
                    num_cost + 34 * keys.len() + 1,
                    1.0 + 72.0 * k as f64,
                    Some(1.0 + k as f64),
                )
            },
            _ => unreachable!("ast elem has children"),
        };
        AstElemExt {
            type_map: types::Type::from_fragment(&ast, None).unwrap(),
            ast: ast,
            pk_cost: pk_cost,
            sat_cost: sat_cost,
            dissat_cost: dissat_cost,
        }
    }

    fn from_conjunction(
        ast: AstElem<Pk, Pkh>,
        l: &AstElemExt<Pk, Pkh>,
        r: &AstElemExt<Pk, Pkh>,
    ) -> Result<AstElemExt<Pk, Pkh>, types::Error<Pk, Pkh>> {
        let type_map = types::Type::from_fragment(
            &ast,
            Some(&[l.type_map, r.type_map][..]),
        )?;

        let (pk_cost, sat_cost, dissat_cost) = match ast {
            AstElem::AndV(..) => (
                l.pk_cost + r.pk_cost,
                l.sat_cost + r.sat_cost,
                None,
            ),
            AstElem::AndB(..) => (
                l.pk_cost + r.pk_cost + 1,
                l.sat_cost + r.sat_cost,
                match (l.dissat_cost, r.dissat_cost) {
                    (Some(l), Some(r)) => Some(l + r),
                    _ => None,
                },
            ),
            _ => unreachable!("ast element is not a conjunction"),
        };
        Ok(AstElemExt {
            type_map: type_map,
            ast: ast,
            pk_cost: pk_cost,
            sat_cost: sat_cost,
            dissat_cost: dissat_cost,
        })
    }

    fn from_disjunction(
        ast: AstElem<Pk, Pkh>,
        l: &AstElemExt<Pk, Pkh>,
        r: &AstElemExt<Pk, Pkh>,
        lweight: f64,
        rweight: f64,
    ) -> Result<AstElemExt<Pk, Pkh>, types::Error<Pk, Pkh>> {
        let type_map = types::Type::from_fragment(
            &ast,
            Some(&[l.type_map, r.type_map][..]),
        )?;

        let (pk_cost, sat_cost, dissat_cost) = match ast {
            AstElem::OrB(..) => (
                l.pk_cost + r.pk_cost + 1,
                lweight * (l.sat_cost + r.dissat_cost.unwrap())
                    + rweight * (r.sat_cost + l.dissat_cost.unwrap()),
                Some(l.dissat_cost.unwrap() + r.dissat_cost.unwrap()),
            ),
            AstElem::OrD(..) => (
                l.pk_cost + r.pk_cost + 3,
                lweight * l.sat_cost
                    + rweight * (r.sat_cost + l.dissat_cost.unwrap()),
                r.dissat_cost.map(|rdcost| l.dissat_cost.unwrap() + rdcost),
            ),
            AstElem::OrC(..) => (
                l.pk_cost + r.pk_cost + 2,
                lweight * l.sat_cost
                    + rweight * (r.sat_cost + l.dissat_cost.unwrap()),
                None,
            ),
            AstElem::OrI(..) => (
                l.pk_cost + r.pk_cost + 3,
                lweight * (2.0 + l.sat_cost) + rweight * (1.0 + r.sat_cost),
                if let Some(ldis) = l.dissat_cost {
                    Some(2.0 + ldis)
                } else if let Some(rdis) = r.dissat_cost {
                    Some(1.0 + rdis)
                } else {
                    None
                },
            ),
            _ => unreachable!("ast is not a disjunction"),
        };
        Ok(AstElemExt {
            type_map: type_map,
            ast: ast,
            pk_cost: pk_cost,
            sat_cost: sat_cost,
            dissat_cost: dissat_cost,
        })
    }

    fn expected_cost(&self, sat_prob: f64, dissat_prob: Option<f64>) -> f64 {
        self.pk_cost as f64
            + self.sat_cost * sat_prob
            + match (dissat_prob, self.dissat_cost) {
                (Some(prob), Some(cost)) => prob * cost,
                (Some(_), None) => unreachable!(),
                (None, Some(_)) => 0.0,
                (None, None) => 0.0,
            }
    }
}

impl<Pk, Pkh> AstElemExt<Pk, Pkh>
where
    Pk: Clone + fmt::Debug,
    Pkh: Clone + fmt::Debug,
{
    fn wrappings(
        &self,
        sat_prob: f64,
        dissat_prob: Option<f64>,
    ) -> WrappingIter<Pk, Pkh> {
        WrappingIter::new(self, sat_prob, dissat_prob)
    }
}

#[derive(Copy, Clone)]
struct Cast<Pk, Pkh> {
    cast: fn(Box<AstElem<Pk, Pkh>>) -> AstElem<Pk, Pkh>,
    type_cast: fn(&types::Type) -> Result<types::Type, types::ErrorKind>,
    cost_cast: fn(bool, usize, f64, Option<f64>) -> (usize, f64, Option<f64>),
}

fn all_casts<Pk, Pkh>() -> [Cast<Pk, Pkh>; 9]
where
    Pk: Clone + fmt::Debug,
    Pkh: Clone + fmt::Debug,
{
    [
        Cast {
            cast: AstElem::Alt,
            type_cast: types::Type::cast_alt,
            cost_cast: |_, pk, sat, dissat| (pk + 2, sat, dissat),
        },
        Cast {
            cast: AstElem::Swap,
            type_cast: types::Type::cast_swap,
            cost_cast: |_, pk, sat, dissat| (pk + 1, sat, dissat),
        },
        Cast {
            cast: AstElem::Check,
            type_cast: types::Type::cast_check,
            cost_cast: |_, pk, sat, dissat| (pk + 1, sat, dissat),
        },
        Cast {
            cast: AstElem::DupIf,
            type_cast: types::Type::cast_dupif,
            cost_cast: |_, pk, sat, _| (pk + 3, 2.0 + sat, Some(1.0)),
        },
        Cast {
            cast: AstElem::Verify,
            type_cast: types::Type::cast_verify,
            cost_cast: |free_v, pk, sat, _| (
                pk + if free_v { 0 } else { 1 },
                sat,
                None,
            ),
        },
        Cast {
            cast: AstElem::NonZero,
            type_cast: types::Type::cast_nonzero,
            cost_cast: |_, pk, sat, _| (pk + 4, sat, Some(1.0)),
        },
        Cast {
            cast: |x| AstElem::AndV(x, Box::new(AstElem::True)),
            type_cast: types::Type::cast_true,
            cost_cast: |_, pk, sat, _| (pk + 1, sat, None),
        },
        Cast {
            cast: |x| AstElem::OrI(x, Box::new(AstElem::False)),
            type_cast: types::Type::cast_or_i_false,
            cost_cast: |_, pk, sat, _| (pk + 4, sat + 2.0, Some(1.0)),
        },
        Cast {
            cast: |x| AstElem::OrI(Box::new(AstElem::False), x),
            type_cast: types::Type::cast_or_i_false,
            cost_cast: |_, pk, sat, _| (pk + 4, sat + 1.0, Some(2.0)),
        },
    ]
}

struct WrappingIter<Pk: Clone, Pkh: Clone> {
    /// Stack of indices of thus-far applied casts
    cast_stack: Vec<(usize, AstElemExt<Pk, Pkh>)>,
    /// Set of types that we've already seen (and should ignore on
    /// future visits). Maps to the cheapest expected cost we've
    /// seen when constructing this type
    visited_types: HashMap<types::Type, f64>,
    /// Original un-casted astelem. Set to `None` when the iterator
    /// is exhausted
    origin: Option<AstElemExt<Pk, Pkh>>,
    /// Probability that this fragment will be satisfied
    sat_prob: f64,
    /// Probability that this fragment will be dissatisfied
    dissat_prob: Option<f64>,
}

impl<Pk, Pkh> WrappingIter<Pk, Pkh>
where
    Pk: Clone + fmt::Debug,
    Pkh: Clone + fmt::Debug,
{
    fn new(
        elem: &AstElemExt<Pk, Pkh>,
        sat_prob: f64,
        dissat_prob: Option<f64>,
    ) -> WrappingIter<Pk, Pkh> {
        WrappingIter {
            cast_stack: vec![],
            visited_types: HashMap::new(),
            origin: Some(elem.clone()),
            sat_prob: sat_prob,
            dissat_prob: dissat_prob,
        }
    }
}

impl<Pk, Pkh> Iterator for WrappingIter<Pk, Pkh>
where
    Pk: Clone + fmt::Debug,
    Pkh: Clone + fmt::Debug,
{
    type Item = AstElemExt<Pk, Pkh>;

    fn next(&mut self) -> Option<AstElemExt<Pk, Pkh>> {
        let current = match self.cast_stack.last() {
            Some(&(_, ref astext)) => astext.clone(),
            None => match self.origin.as_ref() {
                Some(astext) => astext.clone(),
                None => return None,
            }
        };
        let all_casts = all_casts::<Pk, Pkh>();

        // Try applying a new cast
        for i in 0..all_casts.len() {
            if let Ok(type_map) = (all_casts[i].type_cast)(&current.type_map) {
                let (new_pk, new_sat, new_dis) = (all_casts[i].cost_cast)(
                    current.type_map.has_verify_form,
                    current.pk_cost,
                    current.sat_cost,
                    current.dissat_cost,
                );
                let new_ext = AstElemExt {
                    ast: (all_casts[i].cast)(Box::new(current.ast.clone())),
                    type_map: type_map,
                    pk_cost: new_pk,
                    sat_cost: new_sat,
                    dissat_cost: new_dis,
                };

                let new_cost = new_ext.expected_cost(
                    self.sat_prob,
                    self.dissat_prob,
                );
                let old_best_cost = self
                    .visited_types
                    .get(&type_map)
                    .map(|x| *x)
                    .unwrap_or(f64::INFINITY);
                if new_cost < old_best_cost {
                    self.visited_types.insert(type_map, new_cost);
                    self.cast_stack.push((i, new_ext));
                    return self.next();
                }
            }
        }
        // If none were applicable, return the current result
        match self.cast_stack.pop() {
            Some((_, astelem)) => Some(astelem),
            None => self.origin.take()
        }
    }
}

fn script_num_cost(n: u32) -> usize {
    if n <= 16 {
        1
    } else if n < 0x80 {
        2
    } else if n < 0x8000 {
        3
    } else if n < 0x800000 {
        4
    } else {
        5
    }
}

fn insert_best<Pk, Pkh>(
    map: &mut HashMap<types::Type, AstElemExt<Pk, Pkh>>,
    elem: AstElemExt<Pk, Pkh>,
    sat_prob: f64,
    dissat_prob: Option<f64>,
) where
    Pk: Clone + fmt::Debug,
    Pkh: Clone + fmt::Debug,
{
    match map.entry(elem.type_map) {
        hash_map::Entry::Vacant(x) => {
            x.insert(elem);
        },
        hash_map::Entry::Occupied(mut x) => {
            let existing = x.get_mut();
            if elem.expected_cost(sat_prob, dissat_prob)
                < existing.expected_cost(sat_prob, dissat_prob)
            {
                *existing = elem;
            }
        },
    }
}

fn insert_best_wrapped<Pk: Clone, Pkh: Clone>(
    map: &mut HashMap<types::Type, AstElemExt<Pk, Pkh>>,
    data: AstElemExt<Pk, Pkh>,
    sat_prob: f64,
    dissat_prob: Option<f64>,
) where
    Pk: Clone + fmt::Debug,
    Pkh: Clone + fmt::Debug,
{
    for wrapped in data.wrappings(sat_prob, dissat_prob) {
        insert_best(
            map,
            wrapped,
            sat_prob,
            dissat_prob,
        );
    }
}

fn best_compilations<Pk: Clone, Pkh: Clone>(
    policy: &Concrete<Pk, Pkh>,
    sat_prob: f64,
    dissat_prob: Option<f64>,
) -> HashMap<types::Type, AstElemExt<Pk, Pkh>> where
    Pk: Clone + fmt::Debug,
    Pkh: Clone + fmt::Debug,
{
    let mut ret = HashMap::new();
    match *policy {
        Concrete::Key(ref pk) => insert_best_wrapped(
            &mut ret,
            AstElemExt::from_terminal(AstElem::Pk(pk.clone())),
            sat_prob,
            dissat_prob,
        ),
        Concrete::KeyHash(ref pkh) => insert_best_wrapped(
            &mut ret,
            AstElemExt::from_terminal(AstElem::PkH(pkh.clone())),
            sat_prob,
            dissat_prob,
        ),
        Concrete::After(n) => {
            insert_best_wrapped(
                &mut ret,
                AstElemExt::from_terminal(AstElem::After(n)),
                sat_prob,
                dissat_prob,
            );
        },
        Concrete::Older(n) => {
            insert_best_wrapped(
                &mut ret,
                AstElemExt::from_terminal(AstElem::Older(n)),
                sat_prob,
                dissat_prob,
            );
        },
        Concrete::Sha256(hash) => insert_best_wrapped(
            &mut ret,
            AstElemExt::from_terminal(AstElem::Sha256(hash)),
            sat_prob,
            dissat_prob,
        ),
        Concrete::Hash256(hash) => insert_best_wrapped(
            &mut ret,
            AstElemExt::from_terminal(AstElem::Hash256(hash)),
            sat_prob,
            dissat_prob,
        ),
        Concrete::Ripemd160(hash) => insert_best_wrapped(
            &mut ret,
            AstElemExt::from_terminal(AstElem::Ripemd160(hash)),
            sat_prob,
            dissat_prob,
        ),
        Concrete::Hash160(hash) => insert_best_wrapped(
            &mut ret,
            AstElemExt::from_terminal(AstElem::Hash160(hash)),
            sat_prob,
            dissat_prob,
        ),
        Concrete::And(ref subs) => {
            assert_eq!(subs.len(), 2, "and takes 2 args");
            let left = best_compilations(&subs[0], sat_prob, dissat_prob);
            let right = best_compilations(&subs[1], sat_prob, dissat_prob);
            for l in left.values() {
                let lbox = Box::new(l.ast.clone());
                for r in right.values() {
                    let rbox = Box::new(r.ast.clone());
                    let mut tries = [
                        Some((l, r, AstElem::AndB(lbox.clone(), rbox.clone()))),
                        Some((l, r, AstElem::AndV(lbox.clone(), rbox.clone()))),
                        Some((r, l, AstElem::AndB(rbox.clone(), lbox.clone()))),
                        Some((r, l, AstElem::AndV(rbox.clone(), lbox.clone()))),
                    ];
                    for tri in &mut tries {
                        let (l_ext, r_ext, tri) = tri.take().unwrap();
                        if let Ok(new_ext) = AstElemExt::from_conjunction(
                            tri,
                            l_ext,
                            r_ext,
                        ) {
                            insert_best_wrapped(
                                &mut ret,
                                new_ext,
                                sat_prob,
                                dissat_prob,
                            );
                        }
                    }
                }
            }
        },
        Concrete::Or(ref subs) => {
            assert_eq!(subs.len(), 2, "or takes 2 args");
            let left = best_compilations(&subs[0].1, sat_prob, dissat_prob);
            let right = best_compilations(&subs[1].1, sat_prob, dissat_prob);
            let total = (subs[0].0 + subs[1].0) as f64;
            let lw = subs[0].0 as f64 / total;
            let rw = subs[1].0 as f64 / total;
            for l in left.values() {
                let lb = Box::new(l.ast.clone());
                for r in right.values() {
                    let rb = Box::new(r.ast.clone());
                    let mut tries = [
                        Some((l, r, lw, rw, AstElem::OrB(lb.clone(), rb.clone()))),
                        Some((l, r, lw, rw, AstElem::OrC(lb.clone(), rb.clone()))),
                        Some((l, r, lw, rw, AstElem::OrD(lb.clone(), rb.clone()))),
                        Some((l, r, lw, rw, AstElem::OrI(lb.clone(), rb.clone()))),
                        Some((r, l, rw, lw, AstElem::OrB(rb.clone(), lb.clone()))),
                        Some((r, l, rw, lw, AstElem::OrC(rb.clone(), lb.clone()))),
                        Some((r, l, rw, lw, AstElem::OrD(rb.clone(), lb.clone()))),
                        Some((r, l, rw, lw, AstElem::OrI(rb.clone(), lb.clone()))),
                    ];
                    for tri in &mut tries {
                        let (l_ext, r_ext, lw, rw, tri) = tri.take().unwrap();
                        if let Ok(new_ext) = AstElemExt::from_disjunction(
                            tri,
                            l_ext,
                            r_ext,
                            lw,
                            rw,
                        ) {
                            insert_best_wrapped(
                                &mut ret,
                                new_ext,
                                sat_prob,
                                dissat_prob,
                            );
                        }
                    }
                }
            }
        },
        Concrete::Threshold(k, ref subs) => {
            let k_o_n = k as f64 / subs.len() as f64;

            let mut pk_cost = 1 + script_num_cost(k as u32);
            let mut sat_cost = 0.0;
            let mut dissat_cost = 0.0;
            let mut sub_types = Vec::with_capacity(subs.len());
            let ast_subs = subs
                .iter()
                .enumerate()
                .map(|(n, ast)| {
                    let best_ext = if n == 0 {
                        best_e(
                            ast,
                            sat_prob * k_o_n,
                            dissat_prob.map(|p| p + sat_prob * (1.0 - k_o_n)),
                        )
                    } else {
                        pk_cost += 1;
                        best_w(
                            ast,
                            sat_prob * k_o_n,
                            dissat_prob.map(|p| p + sat_prob * (1.0 - k_o_n)),
                        )
                    };
                    pk_cost += best_ext.pk_cost;
                    sat_cost += best_ext.sat_cost;
                    dissat_cost += best_ext.dissat_cost.unwrap();
                    sub_types.push(best_ext.type_map);
                    best_ext.ast
                })
                .collect();

            let ast = AstElem::Thresh(k, ast_subs);
            insert_best_wrapped(
                &mut ret,
                AstElemExt {
                    type_map: types::Type::from_fragment(
                        &ast,
                        Some(&sub_types[..]),
                    ).unwrap(),
                    ast: ast,
                    pk_cost: pk_cost,
                    sat_cost: sat_cost * k_o_n,
                    dissat_cost: Some(dissat_cost),
                },
                sat_prob,
                dissat_prob,
            );

            let key_vec: Vec<Pk> = subs
                .iter()
                .filter_map(|s| if let Concrete::Key(ref pk) = *s {
                    Some(pk.clone())
                } else {
                    None
                })
                .collect();
            if key_vec.len() == subs.len() && subs.len() <= 20 {
                insert_best_wrapped(
                    &mut ret,
                    AstElemExt::from_terminal(AstElem::ThreshM(k, key_vec)),
                    sat_prob,
                    dissat_prob,
                );
            }
        },
    }
    ret
}

pub fn best_compilation<Pk, Pkh>(
    policy: &Concrete<Pk, Pkh>,
) -> AstElem<Pk, Pkh> where
    Pk: Clone + fmt::Debug,
    Pkh: Clone + fmt::Debug,
{
    best_t(policy, 1.0, None).ast
}

fn best_t<Pk, Pkh>(
    policy: &Concrete<Pk, Pkh>,
    sat_prob: f64,
    dissat_prob: Option<f64>,
) -> AstElemExt<Pk, Pkh> where
    Pk: Clone + fmt::Debug,
    Pkh: Clone + fmt::Debug,
{
    best_compilations(policy, 1.0, None)
        .into_iter()
        .filter(|&(key, _)| key.base == types::Base::B)
        .map(|(_, val)| val)
        .min_by_key(|ext| OrdF64(ext.expected_cost(sat_prob, dissat_prob)))
        .unwrap()
}

fn best_e<Pk, Pkh>(
    policy: &Concrete<Pk, Pkh>,
    sat_prob: f64,
    dissat_prob: Option<f64>,
) -> AstElemExt<Pk, Pkh> where
    Pk: Clone + fmt::Debug,
    Pkh: Clone + fmt::Debug,
{
    best_compilations(policy, sat_prob, dissat_prob)
        .into_iter()
        .filter(|&(key, _)| key.base == types::Base::B
                && key.unit
                && key.dissat == types::Dissat::Unique
        )
        .map(|(_, val)| val)
        .min_by_key(|ext| OrdF64(ext.expected_cost(sat_prob, dissat_prob)))
        .unwrap()
}

fn best_w<Pk, Pkh>(
    policy: &Concrete<Pk, Pkh>,
    sat_prob: f64,
    dissat_prob: Option<f64>,
) -> AstElemExt<Pk, Pkh> where
    Pk: Clone + fmt::Debug,
    Pkh: Clone + fmt::Debug,
{
    best_compilations(policy, sat_prob, dissat_prob)
        .into_iter()
        .filter(|&(key, _)| key.base == types::Base::W
                && key.unit
                && key.dissat == types::Dissat::Unique
        )
        .map(|(_, val)| val)
        .min_by_key(|ext| OrdF64(ext.expected_cost(sat_prob, dissat_prob)))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use bitcoin;
    use bitcoin::blockdata::{opcodes, script};
    use bitcoin_hashes::hash160;
    use secp256k1;
    use std::str::FromStr;
    use super::*;

    use hex_script;
    use policy::{Liftable, Semantic};
    use DummyKey;
    use DummyKeyHash;
    use Satisfier;
    use BitcoinSig;

    type SPolicy = Concrete<String, String>;
    type DummyPolicy = Concrete<DummyKey, DummyKeyHash>;
    type BPolicy = Concrete<bitcoin::PublicKey, hash160::Hash>;

    fn pubkeys_and_a_sig(
        n: usize,
    )-> (Vec<bitcoin::PublicKey>, secp256k1::Signature) {
        let mut ret = Vec::with_capacity(n);
        let secp = secp256k1::Secp256k1::new();
        let mut sk = [0; 32];
        for i in 1..n+1 {
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
        assert_eq!(policy.into_lift(), Semantic::Key(DummyKey));
        assert_eq!(miniscript.into_lift(), Semantic::Key(DummyKey));

        let policy = DummyPolicy::from_str("pkh()").expect("parse");
        let miniscript = policy.compile();
        assert_eq!(policy.into_lift(), Semantic::KeyHash(DummyKeyHash));
        assert_eq!(miniscript.into_lift(), Semantic::KeyHash(DummyKeyHash));
    }

    #[test]
    fn compile_q() {
        let policy = SPolicy::from_str("or(1@and(pk(),pk()),127@pk())")
            .expect("parsing");
        let compilation = best_t(&policy, 1.0, None);

        assert_eq!(compilation.expected_cost(1.0, None), 108.0 + 73.578125);
        assert_eq!(
            policy.into_lift().sorted(),
            compilation.ast.into_lift().sorted()
        );

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

        assert_eq!(compilation.expected_cost(1.0, None), 480.0 + 283.234375);
        assert_eq!(
            policy.into_lift().sorted(),
            compilation.ast.into_lift().sorted()
        );
    }

    #[test]
    fn compile_misc() {
        let (keys, sig) = pubkeys_and_a_sig(10);
        let key_pol: Vec<BPolicy>
            = keys.iter().map(|k| Concrete::Key(*k)).collect();
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
        let policy: BPolicy = Concrete::And(vec![
            Concrete::After(10000),
            Concrete::Threshold(2, key_pol[5..8].to_owned()),
        ]);
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
            (1, Concrete::And(vec![
                Concrete::After(10000),
                Concrete::Threshold(2, key_pol[5..8].to_owned()),
            ])),
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

        let mut abs = policy.into_lift();
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

        impl<Pk, Pkh> Satisfier<Pk, Pkh> for BadSat { }
        impl<Pk, Pkh> Satisfier<Pk, Pkh> for GoodSat {
            fn lookup_pk(&self, _: &Pk) -> Option<BitcoinSig> {
                Some((self.0, bitcoin::SigHashType::All))
            }
        }
        impl<'a, Pkh> Satisfier<bitcoin::PublicKey, Pkh> for LeftSat<'a> {
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
    use test::{Bencher, black_box};

    use ParseTree;
    use Concrete;

    #[bench]
    pub fn compile(bh: &mut Bencher) {
        let desc = Concrete::<secp256k1::PublicKey>::from_str(
            "and(thresh(2,and(sha256(),or(sha256(),pk())),pk(),pk(),pk(),sha256()),pkh())"
        ).expect("parsing");
        bh.iter( || {
            let pt = ParseTree::compile(&desc);
            black_box(pt);
        });
    }

    #[bench]
    pub fn compile_large(bh: &mut Bencher) {
        let desc = Concrete::<secp256k1::PublicKey>::from_str(
            "or(pkh(),thresh(9,sha256(),pkh(),pk(),and(or(pkh(),pk()),pk()),time_e(),pk(),pk(),pk(),pk(),and(pk(),pk())))"
        ).expect("parsing");
        bh.iter( || {
            let pt = ParseTree::compile(&desc);
            black_box(pt);
        });
    }

    #[bench]
    pub fn compile_xlarge(bh: &mut Bencher) {
        let desc = Concrete::<secp256k1::PublicKey>::from_str(
            "or(pk(),thresh(4,pkh(),time_e(),multi(),and(after(),or(pkh(),or(pkh(),and(pkh(),thresh(2,multi(),or(pkh(),and(thresh(5,sha256(),or(pkh(),pkh()),pkh(),pkh(),pkh(),multi(),pkh(),multi(),pk(),pkh(),pk()),pkh())),pkh(),or(and(pkh(),pk()),pk()),after()))))),pkh()))"
        ).expect("parsing");
        bh.iter( || {
            let pt = ParseTree::compile(&desc);
            black_box(pt);
        });
    }
}

