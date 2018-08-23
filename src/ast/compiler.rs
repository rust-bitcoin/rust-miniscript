// Script Descriptor Language
// Written in 2018 by
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

//! # Descriptor Compiler
//!
//! Optimizing compiler from script descriptors to the AST representation of Bitcoin Script
//! described in the `astelem` module.
//!

use std::collections::HashMap;
use std::cell::RefCell;

use secp256k1;

use bitcoin::blockdata::script;
use bitcoin::util::hash::{Hash160, Sha256dHash};

use Descriptor;
use ast::astelem::{AstElem, E, W, F, V, T};

pub enum CompiledNodeContent {
    Pk(secp256k1::PublicKey),
    Pkh(secp256k1::PublicKey),
    Multi(usize, Vec<secp256k1::PublicKey>),
    Time(u32),
    Hash(Sha256dHash),

    And(Box<CompiledNode>, Box<CompiledNode>),
    Or(Box<CompiledNode>, Box<CompiledNode>, f64, f64),
    Thresh(usize, Vec<CompiledNode>),
}

pub struct CompiledNode {
    pub content: CompiledNodeContent,
    // All of these are actually maps from (f64, f64) pairs, but we transmute them
    // to u64 to allow them to be used as hashmap keys, since f64's by themselves
    // do not implement Eq. This is OK because we only need f64's to compare equal
    // when they were derived from exactly the same sequence of operations, and
    // in that case they'll have the same bit representation.
    pub best_e: RefCell<HashMap<(u64, u64), Cost<E>>>,
    pub best_w: RefCell<HashMap<(u64, u64), Cost<W>>>,
    pub best_f: RefCell<HashMap<(u64, u64), Cost<F>>>,
    pub best_v: RefCell<HashMap<(u64, u64), Cost<V>>>,
    pub best_t: RefCell<HashMap<(u64, u64), Cost<T>>>,
}

#[derive(Clone, PartialEq, Debug)]
/// AST element and associated costs
pub struct Cost<T: AstElem> {
    /// The actual AST element
    pub ast: T,
    /// The number of bytes needed to encode its scriptpubkey fragment
    pub pk_cost: usize,
    /// The number of bytes needed to satisfy the fragment in segwit (total length
    /// of all witness pushes, plus their own length prefixes)
    pub sat_cost: f64,
    /// The number of bytes needed to dissatisfy the fragment in segwit (total length
    /// of all witness pushes, plus their own length prefixes) for fragments that
    /// can be dissatisfied without failing the script.
    pub dissat_cost: f64,
}

impl Cost<E> {
    fn likely(fcost: Cost<F>) -> Cost<E> {
        Cost {
            ast: E::Likely(fcost.ast),
            pk_cost: fcost.pk_cost + 4,
            sat_cost: fcost.sat_cost + 1.0,
            dissat_cost: 2.0,
        }
    }

    fn unlikely(fcost: Cost<F>) -> Cost<E> {
        Cost {
            ast: E::Unlikely(fcost.ast),
            pk_cost: fcost.pk_cost + 4,
            sat_cost: fcost.sat_cost + 2.0,
            dissat_cost: 1.0,
        }
    }

    fn from_pair<L: AstElem, R: AstElem, FF: FnOnce(Box<L>, Box<R>) -> E>(
        left: Cost<L>,
        right: Cost<R>,
        combine: FF,
        lweight: f64,
        rweight: f64
    ) -> Cost<E> {
        let new_ast = combine(Box::new(left.ast), Box::new(right.ast));
        match new_ast {
            E::CheckSig(..) | E::CheckSigHash(..) | E::CheckMultiSig(..) | E::Time(..) |
            E::Threshold(..) | E::Likely(..) | E::Unlikely(..) => unreachable!(),
            E::ParallelAnd(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 1,
                sat_cost: left.sat_cost + right.sat_cost,
                dissat_cost: left.dissat_cost + right.dissat_cost,
            },
            E::CascadeAnd(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 4,
                sat_cost: left.sat_cost + right.sat_cost,
                dissat_cost: left.dissat_cost,
            },
            E::ParallelOr(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 1,
                sat_cost: (left.sat_cost + right.dissat_cost) * lweight + (right.sat_cost + left.dissat_cost) * rweight,
                dissat_cost: left.dissat_cost + right.dissat_cost,
            },
            E::CascadeOr(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 3,
                sat_cost: left.sat_cost * lweight + (right.sat_cost + left.dissat_cost) * rweight,
                dissat_cost: left.dissat_cost + right.dissat_cost,
            },
            E::SwitchOrLeft(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 3,
                sat_cost: (left.sat_cost + 2.0) * lweight + (right.sat_cost + 1.0) * rweight,
                dissat_cost: left.dissat_cost + 2.0,
            },
            E::SwitchOrRight(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 3,
                sat_cost: (left.sat_cost + 1.0) * lweight + (right.sat_cost + 2.0) * rweight,
                dissat_cost: left.dissat_cost + 1.0,
            },
        }
    }
}

impl Cost<W> {
    fn wrapped(c: Cost<E>) -> Cost<W> {
        match c.ast {
            E::CheckSig(key) => Cost {
                ast: W::CheckSig(key),
                pk_cost: c.pk_cost + 1,
                sat_cost: c.sat_cost,
                dissat_cost: c.dissat_cost,
            },
            E::Time(key) => Cost {
                ast: W::Time(key),
                pk_cost: c.pk_cost + 1,
                sat_cost: c.sat_cost,
                dissat_cost: c.dissat_cost,
            },
            E::Likely(F::HashEqual(hash)) | E::Unlikely(F::HashEqual(hash)) => Cost {
                ast: W::HashEqual(hash),
                pk_cost: 45,
                sat_cost: 33.0,
                dissat_cost: 1.0,
            },
            x => Cost {
                ast: W::CastE(Box::new(x)),
                pk_cost: c.pk_cost + 2,
                sat_cost: c.sat_cost,
                dissat_cost: c.dissat_cost,
            },
        }
    }
}

impl Cost<F> {
    fn from_pair<L: AstElem, R: AstElem, FF: FnOnce(Box<L>, Box<R>) -> F>(
        left: Cost<L>,
        right: Cost<R>,
        combine: FF,
        lweight: f64,
        rweight: f64
    ) -> Cost<F> {
        let new_ast = combine(Box::new(left.ast), Box::new(right.ast));
        match new_ast {
            F::CheckSig(..) | F::CheckMultiSig(..) | F::CheckSigHash(..) | F::Time(..) |
            F::HashEqual(..) | F::Threshold(..) => unreachable!(),
            F::And(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost,
                sat_cost: left.sat_cost + right.sat_cost,
                dissat_cost: 0.0,
            },
            F::CascadeOr(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 3,
                sat_cost: left.sat_cost * lweight + (right.sat_cost + left.dissat_cost) * rweight,
                dissat_cost: 0.0,
            },
            F::SwitchOr(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 3,
                sat_cost: (left.sat_cost + 2.0) * lweight + (right.sat_cost + 1.0) * rweight,
                dissat_cost: 0.0,
            },
            F::SwitchOrV(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 4,
                sat_cost: (left.sat_cost + 2.0) * lweight + (right.sat_cost + 1.0) * rweight,
                dissat_cost: 0.0,
            },
        }
    }
}

impl Cost<V> {
    fn from_pair<L: AstElem, R: AstElem, FF: FnOnce(Box<L>, Box<R>) -> V>(
        left: Cost<L>,
        right: Cost<R>,
        combine: FF,
        lweight: f64,
        rweight: f64
    ) -> Cost<V> {
        let new_ast = combine(Box::new(left.ast), Box::new(right.ast));
        match new_ast {
            V::CheckSig(..) | V::CheckMultiSig(..) | V::CheckSigHash(..) | V::Time(..) |
            V::HashEqual(..) | V::Threshold(..) => unreachable!(),
            V::And(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost,
                sat_cost: left.sat_cost + right.sat_cost,
                dissat_cost: 0.0,
            },
            V::CascadeOr(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 2,
                sat_cost: left.sat_cost * lweight + (right.sat_cost + left.dissat_cost) * rweight,
                dissat_cost: 0.0,
            },
            V::SwitchOr(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 3,
                sat_cost: (left.sat_cost + 2.0) * lweight + (right.sat_cost + 1.0) * rweight,
                dissat_cost: 0.0,
            },
            V::SwitchOrT(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 4,
                sat_cost: (left.sat_cost + 2.0) * lweight + (right.sat_cost + 1.0) * rweight,
                dissat_cost: 0.0,
            },
        }
    }
}

impl Cost<T> {
    fn from_pair<L: AstElem, R: AstElem, FF: FnOnce(Box<L>, Box<R>) -> T>(
        left: Cost<L>,
        right: Cost<R>,
        combine: FF,
        lweight: f64,
        rweight: f64
    ) -> Cost<T> {
        let new_ast = combine(Box::new(left.ast), Box::new(right.ast));
        match new_ast {
            T::Time(..) | T::HashEqual(..) | T::CastE(..) => unreachable!(),
            T::And(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost,
                sat_cost: left.sat_cost + right.sat_cost,
                dissat_cost: 0.0,
            },
            T::ParallelOr(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 1,
                sat_cost: (left.sat_cost + right.dissat_cost) * lweight + (right.sat_cost + left.dissat_cost) * rweight,
                dissat_cost: 0.0,
            },
            T::CascadeOr(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 3,
                sat_cost: left.sat_cost * lweight + (right.sat_cost + left.dissat_cost) * rweight,
                dissat_cost: 0.0,
            },
            T::CascadeOrV(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 3,
                sat_cost: left.sat_cost * lweight + (right.sat_cost + left.dissat_cost) * rweight,
                dissat_cost: 0.0,
            },
            T::SwitchOr(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 3,
                sat_cost: (left.sat_cost + 2.0) * lweight + (right.sat_cost + 1.0) * rweight,
                dissat_cost: 0.0,
            },
            T::SwitchOrV(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 4,
                sat_cost: (left.sat_cost + 2.0) * lweight + (right.sat_cost + 1.0) * rweight,
                dissat_cost: 0.0,
            },
        }
    }
}

fn min_cost<T: AstElem + ::std::fmt::Debug>(one: Cost<T>, two: Cost<T>, p_sat: f64, p_dissat: f64) -> Cost<T> {
    let weight_one = one.pk_cost as f64 + p_sat * one.sat_cost + p_dissat * one.dissat_cost;
    let weight_two = two.pk_cost as f64 + p_sat * two.sat_cost + p_dissat * two.dissat_cost;

    if weight_one <= weight_two {
        one
    } else {
        two
    }
}

#[cfg(not(feature="trace"))]
fn fold_cost_vec<T: AstElem+::std::fmt::Debug>(mut v: Vec<Cost<T>>, p_sat: f64, p_dissat: f64) -> Cost<T> {
    let last = v.pop().unwrap();
    v.into_iter().fold(last, |acc, n| min_cost(acc, n, p_sat, p_dissat))
}

#[cfg(feature="trace")]
fn fold_cost_vec<T: AstElem+::std::fmt::Debug>(mut v: Vec<Cost<T>>, p_sat: f64, p_dissat: f64) -> Cost<T> {
    println!("");
    println!("Considering p_sat {}   p_dissat {}", p_sat, p_dissat);
    for cost in &v {
        println!("    {:?} (sat {} dissat {} pk {})", cost.ast, cost.sat_cost, cost.dissat_cost, cost.pk_cost);
    }
    
    let last = v.pop().unwrap();
    let win = 
    v.into_iter().fold(last, |acc, n| min_cost(acc, n, p_sat, p_dissat))
    ;
        println!("    \\-- {:?}", win.ast);
    win
}

macro_rules! rules(
    ($ast_type:ty, $p_sat:expr, $p_dissat:expr, $lweight:expr, $rweight:expr;
     $($combine:expr => $l:expr, $r:expr $(=> $lswap:expr, $rswap:expr)*;)*
     $(-> $condcombine:expr => $lcond:expr, $rcond:expr $(=> $lcondswap:expr, $rcondswap:expr)*;)*
    ) => ({
        let mut options = Vec::with_capacity(16);
        $(
        options.push(Cost::<$ast_type>::from_pair($l, $r, $combine, $lweight, $rweight));
        $(options.push(Cost::<$ast_type>::from_pair($lswap, $rswap, $combine, $rweight, $lweight)))*;
        )*
        $(
        let casted = Cost::<F>::from_pair($lcond, $rcond, $condcombine, $lweight, $rweight);
        options.push(Cost::likely(casted.clone()));
        options.push(Cost::unlikely(casted));
        $(
        let casted = Cost::<F>::from_pair($lcondswap, $rcondswap, $condcombine, $rweight, $lweight);
        options.push(Cost::likely(casted.clone()));
        options.push(Cost::unlikely(casted));
        )*
        )*
        fold_cost_vec(options, $p_sat, $p_dissat)
    })
);

impl CompiledNode {
    /// Build a compiled-node tree (without any compilations) from a Descriptor;
    /// basically just copy the descriptor contents into a richer data structure.
    pub fn from_descriptor(desc: &Descriptor<secp256k1::PublicKey>) -> CompiledNode {
        let mut ret = CompiledNode {
            content: CompiledNodeContent::Time(0), // Time(0) used as "uninitialized"
            best_e: RefCell::new(HashMap::new()),
            best_w: RefCell::new(HashMap::new()),
            best_f: RefCell::new(HashMap::new()),
            best_v: RefCell::new(HashMap::new()),
            best_t: RefCell::new(HashMap::new()),
        };

        match *desc {
            Descriptor::Key(ref pk) => ret.content = CompiledNodeContent::Pk(pk.clone()),
            Descriptor::KeyHash(ref pk) => ret.content = CompiledNodeContent::Pkh(pk.clone()),
            Descriptor::Multi(k, ref pks) => ret.content = CompiledNodeContent::Multi(k, pks.clone()),
            Descriptor::Hash(ref hash) =>  ret.content = CompiledNodeContent::Hash(hash.clone()),
            Descriptor::Time(n) =>  ret.content = CompiledNodeContent::Time(n),
            Descriptor::And(ref left, ref right) => {
                ret.content = CompiledNodeContent::And(
                    Box::new(CompiledNode::from_descriptor(left)),
                    Box::new(CompiledNode::from_descriptor(right)),
                );
            }
            Descriptor::Or(ref left, ref right) => {
                ret.content = CompiledNodeContent::Or(
                    Box::new(CompiledNode::from_descriptor(left)),
                    Box::new(CompiledNode::from_descriptor(right)),
                    0.5,
                    0.5,
                );
            }
            Descriptor::AsymmetricOr(ref left, ref right) => {
                ret.content = CompiledNodeContent::Or(
                    Box::new(CompiledNode::from_descriptor(left)),
                    Box::new(CompiledNode::from_descriptor(right)),
                    127.0 / 128.0,
                    1.0 / 128.0,
                );
            }
            Descriptor::Threshold(k, ref subs) => {
                if subs.is_empty() {
                    panic!("Cannot have empty threshold in a descriptor");
                }

                ret.content = CompiledNodeContent::Thresh(
                    k,
                    subs.iter().map(|s| CompiledNode::from_descriptor(s)).collect(),
                );
            }
            Descriptor::Wpkh(_) | Descriptor::Sh(_) | Descriptor::Wsh(_) => {
                // handled at at the ParseTree::from_descriptor layer
                unreachable!()
            }
        }

        ret
    }

    /// Compute or lookup the best compilation of this node as an E
    pub fn best_e(&self, p_sat: f64, p_dissat: f64) -> Cost<E> {
        let hashkey = (p_sat.to_bits(), p_dissat.to_bits());
        if let Some(cost) = self.best_e.borrow().get(&hashkey) {
            return cost.clone();
        }

        match self.content {
            // For terminals we just compute the best value and return it.
            CompiledNodeContent::Pk(ref key) => Cost {
                ast: E::CheckSig(key.clone()),
                pk_cost: 35,
                sat_cost: 72.0,
                dissat_cost: 1.0,
            },
            CompiledNodeContent::Pkh(ref key) => {
                let mut options = Vec::with_capacity(3);

                let hash = Hash160::from_data(&key.serialize()[..]);
                options.push(Cost {
                    ast: E::CheckSigHash(hash),
                    pk_cost: 25,
                    sat_cost: 34.0 + 72.0,
                    dissat_cost: 34.0 + 1.0,
                });

                if p_dissat > 0.0 {
                    let fcost = self.best_f(p_sat, p_dissat);
                    options.push(Cost::likely(fcost.clone()));
                    options.push(Cost::unlikely(fcost));
                }
                fold_cost_vec(options, p_sat, p_dissat)
            }
            CompiledNodeContent::Multi(k, ref pks) => {
                let mut options = Vec::with_capacity(3);

                let num_cost = match(k > 16, pks.len() > 16) {
                    (true, true) => 4,
                    (false, true) => 3,
                    (true, false) => 3,
                    (false, false) => 2,
                };
                options.push(Cost {
                    ast: E::CheckMultiSig(k, pks.clone()),
                    pk_cost: num_cost + 34 * pks.len() + 1,
                    sat_cost: 1.0 + 72.0*k as f64,
                    dissat_cost: 1.0 + k as f64,
                });

                if p_dissat > 0.0 {
                    let fcost = self.best_f(p_sat, p_dissat);
                    options.push(Cost::likely(fcost.clone()));
                    options.push(Cost::unlikely(fcost));
                }
                fold_cost_vec(options, p_sat, p_dissat)
            }
            CompiledNodeContent::Time(n) => {
                let num_cost = script::Builder::new().push_int(n as i64).into_script().len();
                Cost {
                    ast: E::Time(n),
                    pk_cost: 5 + num_cost,
                    sat_cost: 2.0,
                    dissat_cost: 1.0,
                }
            }
            CompiledNodeContent::Hash(_) => {
                let fcost = self.best_f(p_sat, p_dissat);
                min_cost(
                    Cost::likely(fcost.clone()),
                    Cost::unlikely(fcost),
                    p_sat,
                    p_dissat,
                )
            }
            // The non-terminals are more interesting
            CompiledNodeContent::And(ref left, ref right) => {
                let l_e = left.best_e(p_sat, p_dissat);
                let r_e = right.best_e(p_sat, p_dissat);

                let l_f = left.best_f(p_sat, 0.0);
                let r_f = right.best_f(p_sat, 0.0);
                let l_v = left.best_v(p_sat, 0.0);
                let r_v = right.best_v(p_sat, 0.0);

                let ret = rules!(
                    E, p_sat, p_dissat, 0.0, 0.0;
                    E::ParallelAnd => l_e.clone(), Cost::wrapped(r_e.clone())
                                   => r_e.clone(), Cost::wrapped(l_e.clone());
                    E::CascadeAnd => l_e, r_f.clone()
                                  => r_e, l_f.clone();
                    -> F::And => l_v, r_f
                              => r_v, l_f;
                );
                // Memoize and return
                self.best_e.borrow_mut().insert(hashkey, ret.clone());
                ret
            }
            CompiledNodeContent::Or(ref left, ref right, lweight, rweight) => {
                let l_e_par = left.best_e(p_sat * lweight, p_dissat + p_sat * rweight);
                let r_e_par = right.best_e(p_sat * rweight, p_dissat + p_sat * lweight);
                let l_e_cas = left.best_e(p_sat * lweight, p_dissat);
                let r_e_cas = right.best_e(p_sat * rweight, p_dissat);

                let l_e_cond_par = left.best_e(p_sat * lweight, p_sat * rweight);
                let r_e_cond_par = right.best_e(p_sat * rweight, p_sat * lweight);
                let l_v = left.best_v(p_sat * lweight, 0.0);
                let r_v = right.best_v(p_sat * rweight, 0.0);
                let l_f = left.best_f(p_sat * lweight, 0.0);
                let r_f = right.best_f(p_sat * rweight, 0.0);

                let ret = rules!(
                    E, p_sat, p_dissat, lweight, rweight;
                    E::ParallelOr => l_e_par.clone(), Cost::wrapped(r_e_par.clone())
                                  => r_e_par.clone(), Cost::wrapped(l_e_par.clone());
                    E::CascadeOr => l_e_par, r_e_cas.clone()
                                 => r_e_par, l_e_cas.clone();
                    E::SwitchOrLeft => l_e_cas.clone(), r_f.clone()
                                    => r_e_cas.clone(), l_f.clone();
                    E::SwitchOrRight => l_e_cas.clone(), r_f.clone()
                                     => r_e_cas.clone(), l_f.clone();
                    -> F::CascadeOr => l_e_cond_par, r_v.clone()
                                    => r_e_cond_par, l_v.clone();
                    -> F::SwitchOr => l_f.clone(), r_f.clone()
                                   => r_f, l_f;
                    -> F::SwitchOrV => l_v.clone(), r_v.clone()
                                    => r_v, l_v;
                );
                // Memoize and return
                self.best_e.borrow_mut().insert(hashkey, ret.clone());
                ret
            }
            CompiledNodeContent::Thresh(k, ref subs) => {
                let num_cost = script::Builder::new().push_int(k as i64).into_script().len();
                let avg_cost = k as f64 / subs.len() as f64;

                let e = subs[0].best_e(p_sat * avg_cost, p_dissat + p_sat * (1.0 - avg_cost));
                let mut pk_cost = 1 + num_cost + e.pk_cost;
                let mut sat_cost = e.sat_cost;
                let mut dissat_cost = e.dissat_cost;
                let mut ws = vec![];

                for expr in &subs[1..] {
                    let w = expr.best_w(p_sat * avg_cost, p_dissat + p_sat * (1.0 - avg_cost));
                    pk_cost += w.pk_cost + 1;
                    sat_cost += w.sat_cost;
                    dissat_cost += w.dissat_cost;
                    ws.push(w.ast);
                }

                let noncond = Cost {
                    ast: E::Threshold(k, Box::new(e.ast.clone()), ws.clone()),
                    pk_cost: pk_cost,
                    sat_cost: sat_cost * avg_cost + dissat_cost * (1.0 - avg_cost),
                    dissat_cost: dissat_cost,
                };
                // Also compute the F version directly from the E version rather than
                // redoing the recursion; save this in the best_f table.
                let cond = {
                    let mut borrow_f_map = self.best_f.borrow_mut();
                    let f = borrow_f_map.entry(hashkey).or_insert(Cost {
                        ast: F::Threshold(k, Box::new(e.ast), ws),
                        pk_cost: noncond.pk_cost + 1,
                        sat_cost: noncond.sat_cost,
                        dissat_cost: noncond.dissat_cost,
                    });
                    let cond1 = Cost::likely(f.clone());
                    let cond2 = Cost::unlikely(f.clone());
                    min_cost(cond1, cond2, p_sat, p_dissat)
                };

                let ret = min_cost(cond, noncond, p_sat, p_dissat);
                // Memoize the E version, and return
                self.best_e.borrow_mut().insert(hashkey, ret.clone());
                ret
            }
        }
    }

    /// Compute or lookup the best compilation of this node as a W
    pub fn best_w(&self, p_sat: f64, p_dissat: f64) -> Cost<W> {
        Cost::wrapped(self.best_e(p_sat, p_dissat))
    }

    /// Compute or lookup the best compilation of this node as an F
    pub fn best_f(&self, p_sat: f64, p_dissat: f64) -> Cost<F> {
        debug_assert_eq!(p_dissat, 0.0);
        let hashkey = (p_sat.to_bits(), p_dissat.to_bits());
        if let Some(cost) = self.best_f.borrow().get(&hashkey) {
            return cost.clone();
        }

        match self.content {
            // For terminals we just compute the best value and return it.
            CompiledNodeContent::Pk(ref key) => Cost {
                ast: F::CheckSig(key.clone()),
                pk_cost: 36,
                sat_cost: 72.0,
                dissat_cost: 1.0,
            },
            CompiledNodeContent::Pkh(ref key) => Cost {
                ast: F::CheckSigHash(Hash160::from_data(&key.serialize()[..])),
                pk_cost: 26,
                sat_cost: 34.0 + 72.0,
                dissat_cost: 0.0,
            },
            CompiledNodeContent::Multi(k, ref pks) => {
                let num_cost = match(k > 16, pks.len() > 16) {
                    (true, true) => 4,
                    (false, true) => 3,
                    (true, false) => 3,
                    (false, false) => 2,
                };
                Cost {
                    ast: F::CheckMultiSig(k, pks.clone()),
                    pk_cost: num_cost + 34 * pks.len() + 2,
                    sat_cost: 1.0 + 72.0 * k as f64,
                    dissat_cost: 0.0,
                }
            },
            CompiledNodeContent::Time(n) => {
                let num_cost = script::Builder::new().push_int(n as i64).into_script().len();
                Cost {
                    ast: F::Time(n),
                    pk_cost: 2 + num_cost,
                    sat_cost: 0.0,
                    dissat_cost: 0.0,
                }
            },
            CompiledNodeContent::Hash(hash) => Cost {
                ast: F::HashEqual(hash),
                pk_cost: 40,
                sat_cost: 33.0,
                dissat_cost: 0.0,
            },
            // The non-terminals are more interesting
            CompiledNodeContent::And(ref left, ref right) => {
                let vl = left.best_v(p_sat, 0.0);
                let vr = right.best_v(p_sat, 0.0);
                let fl = left.best_f(p_sat, 0.0);
                let fr = right.best_f(p_sat, 0.0);

                let ret = rules!(
                    F, p_sat, 0.0, 0.0, 0.0;
                    F::And => vl, fr
                           => vr, fl;
                );
                // Memoize and return
                self.best_f.borrow_mut().insert(hashkey, ret.clone());
                ret
            },
            CompiledNodeContent::Or(ref left, ref right, lweight, rweight) => {
                let l_e_par = left.best_e(p_sat * lweight, p_sat * rweight);
                let r_e_par = right.best_e(p_sat * rweight, p_sat * lweight);

                let l_f = left.best_f(p_sat * lweight, 0.0);
                let r_f = right.best_f(p_sat * rweight, 0.0);
                let l_v = left.best_v(p_sat * lweight, 0.0);
                let r_v = right.best_v(p_sat * rweight, 0.0);

                let ret = rules!(
                    F, p_sat, 0.0, lweight, rweight;
                    F::CascadeOr => l_e_par, r_v.clone()
                                 => r_e_par, l_v.clone();
                    F::SwitchOr => l_f.clone(), r_f.clone()
                                => r_f, l_f;
                    F::SwitchOrV => l_v.clone(), r_v.clone()
                                 => r_v, l_v;
                );
                // Memoize and return
                self.best_f.borrow_mut().insert(hashkey, ret.clone());
                ret
            }
            CompiledNodeContent::Thresh(k, ref subs) => {
                let num_cost = script::Builder::new().push_int(k as i64).into_script().len();
                let avg_cost = k as f64 / subs.len() as f64;

                let e = subs[0].best_e(p_sat * avg_cost, p_dissat + p_sat * (1.0 - avg_cost));
                let mut pk_cost = 2 + num_cost + e.pk_cost;
                let mut sat_cost = e.sat_cost;
                let mut dissat_cost = e.dissat_cost;
                let mut ws = vec![];

                for expr in &subs[1..] {
                    let w = expr.best_w(p_sat * avg_cost, p_dissat + p_sat * (1.0 - avg_cost));
                    pk_cost += w.pk_cost + 1;
                    sat_cost += w.sat_cost;
                    dissat_cost += w.dissat_cost;
                    ws.push(w.ast);
                }

                // Don't bother memoizing because it's always the same
                Cost {
                    ast: F::Threshold(k, Box::new(e.ast), ws),
                    pk_cost: pk_cost,
                    sat_cost: sat_cost * avg_cost + dissat_cost * (1.0 - avg_cost),
                    dissat_cost: 0.0,
                }
            }
        }
    }

    /// Compute or lookup the best compilation of this node as a V
    pub fn best_v(&self, p_sat: f64, p_dissat: f64) -> Cost<V> {
        debug_assert_eq!(p_dissat, 0.0);
        let hashkey = (p_sat.to_bits(), p_dissat.to_bits());
        if let Some(cost) = self.best_v.borrow().get(&hashkey) {
            return cost.clone();
        }

        match self.content {
            // For terminals we just compute the best value and return it.
            CompiledNodeContent::Pk(ref key) => Cost {
                ast: V::CheckSig(key.clone()),
                pk_cost: 35,
                sat_cost: 72.0,
                dissat_cost: 0.0,
            },
            CompiledNodeContent::Pkh(ref key) => Cost {
                ast: V::CheckSigHash(Hash160::from_data(&key.serialize()[..])),
                pk_cost: 25,
                sat_cost: 34.0 + 72.0,
                dissat_cost: 0.0,
            },
            CompiledNodeContent::Multi(k, ref pks) => {
                let num_cost = match(k > 16, pks.len() > 16) {
                    (true, true) => 4,
                    (false, true) => 3,
                    (true, false) => 3,
                    (false, false) => 2,
                };
                Cost {
                    ast: V::CheckMultiSig(k, pks.clone()),
                    pk_cost: num_cost + 34 * pks.len() + 1,
                    sat_cost: 1.0 + 72.0*k as f64,
                    dissat_cost: 0.0,
                }
            },
            CompiledNodeContent::Time(n) => {
                let num_cost = script::Builder::new().push_int(n as i64).into_script().len();
                Cost {
                    ast: V::Time(n),
                    pk_cost: 2 + num_cost,
                    sat_cost: 0.0,
                    dissat_cost: 0.0,
                }
            },
            CompiledNodeContent::Hash(hash) => Cost {
                ast: V::HashEqual(hash),
                pk_cost: 39,
                sat_cost: 33.0,
                dissat_cost: 0.0,
            },
            // For V, we can also avoid memoizing AND because it's just a passthrough
            CompiledNodeContent::And(ref left, ref right) => {
                let l = left.best_v(p_sat, 0.0);
                let r = right.best_v(p_sat, 0.0);
                Cost {
                    pk_cost: l.pk_cost + r.pk_cost,
                    sat_cost: l.sat_cost + r.sat_cost,
                    dissat_cost: 0.0,
                    ast: V::And(Box::new(l.ast), Box::new(r.ast)),
                }
            },
            // Other terminals, as usual, are more interesting
            CompiledNodeContent::Or(ref left, ref right, lweight, rweight) => {
                let l_e_par = left.best_e(p_sat * lweight, p_sat * rweight);
                let r_e_par = right.best_e(p_sat * rweight, p_sat * lweight);

                let l_t = left.best_t(p_sat * lweight, 0.0);
                let r_t = right.best_t(p_sat * rweight, 0.0);
                let l_v = left.best_v(p_sat * lweight, 0.0);
                let r_v = right.best_v(p_sat * rweight, 0.0);

                let ret = rules!(
                    V, p_sat, 0.0, lweight, rweight;
                    V::CascadeOr => l_e_par, r_v.clone()
                                 => r_e_par, l_v.clone();
                    V::SwitchOr => l_v.clone(), r_v.clone()
                                => r_v, l_v;
                    V::SwitchOrT => l_t.clone(), r_t.clone()
                                 => r_t, l_t;
                );
                // Memoize and return
                self.best_v.borrow_mut().insert(hashkey, ret.clone());
                ret
            }
            CompiledNodeContent::Thresh(k, ref subs) => {
                let num_cost = script::Builder::new().push_int(k as i64).into_script().len();
                let avg_cost = k as f64 / subs.len() as f64;

                let e = subs[0].best_e(p_sat * avg_cost, p_sat * (1.0 - avg_cost));
                let mut pk_cost = 1 + num_cost + e.pk_cost;
                let mut sat_cost = e.sat_cost;
                let mut dissat_cost = e.dissat_cost;
                let mut ws = vec![];

                for sub in &subs[1..] {
                    let w = sub.best_w(p_sat * avg_cost, p_sat * (1.0 - avg_cost));
                    pk_cost += w.pk_cost + 1;
                    sat_cost += w.sat_cost;
                    dissat_cost += w.dissat_cost;
                    ws.push(w.ast);
                }

                // Don't bother memoizing because it's always the same
                Cost {
                    ast: V::Threshold(k, Box::new(e.ast), ws),
                    pk_cost: pk_cost,
                    sat_cost: sat_cost * avg_cost + dissat_cost * (1.0 - avg_cost),
                    dissat_cost: 0.0,
                }
            }
        }
    }

    /// Compute or lookup the best compilation of this node as a T
    pub fn best_t(&self, p_sat: f64, p_dissat: f64) -> Cost<T> {
        debug_assert_eq!(p_dissat, 0.0);
        let hashkey = (p_sat.to_bits(), p_dissat.to_bits());
        if let Some(cost) = self.best_t.borrow().get(&hashkey) {
            return cost.clone();
        }

        match self.content {
            // For most terminals, and thresholds, we just pass though to E
            CompiledNodeContent::Pk(..) | CompiledNodeContent::Pkh(..) |
            CompiledNodeContent::Multi(..) | CompiledNodeContent::Thresh(..) => {
                let e = self.best_e(p_sat, 0.0);
                Cost {
                    ast: T::CastE(e.ast),
                    pk_cost: e.pk_cost,
                    sat_cost: e.sat_cost,
                    dissat_cost: 0.0,
                }
            },
            CompiledNodeContent::Time(n) => {
                let num_cost = script::Builder::new().push_int(n as i64).into_script().len();
                Cost {
                    ast: T::Time(n),
                    pk_cost: 1 + num_cost,
                    sat_cost: 0.0,
                    dissat_cost: 0.0,
                }
            }
            CompiledNodeContent::Hash(hash) => Cost {
                ast: T::HashEqual(hash),
                pk_cost: 39,
                sat_cost: 33.0,
                dissat_cost: 0.0,
            },
            // AND and OR are slightly more involved, but not much
            CompiledNodeContent::And(ref left, ref right) => {
                let vl = left.best_v(p_sat, 0.0);
                let vr = right.best_v(p_sat, 0.0);
                let tl = left.best_t(p_sat, 0.0);
                let tr = right.best_t(p_sat, 0.0);

                let ret = rules!(
                    T, p_sat, 0.0, 0.0, 0.0;
                    T::And => vl, tr
                           => vr, tl;
                );
                // Memoize and return
                self.best_t.borrow_mut().insert(hashkey, ret.clone());
                ret
            },
            CompiledNodeContent::Or(ref left, ref right, lweight, rweight) => {
                let l_e_par = left.best_e(p_sat * lweight, p_sat * rweight);
                let r_e_par = right.best_e(p_sat * rweight, p_sat * lweight);

                let l_t = left.best_t(p_sat * lweight, 0.0);
                let r_t = right.best_t(p_sat * rweight, 0.0);
                let l_v = left.best_v(p_sat * lweight, 0.0);
                let r_v = right.best_v(p_sat * rweight, 0.0);

                let ret = rules!(
                    T, p_sat, 0.0, lweight, rweight;
                    T::ParallelOr => l_e_par.clone(), Cost::wrapped(r_e_par.clone())
                                  => r_e_par.clone(), Cost::wrapped(l_e_par.clone());
                    T::CascadeOr => l_e_par.clone(), r_t.clone()
                                 => r_e_par.clone(), l_t.clone();
                    T::CascadeOrV => l_e_par, r_v.clone()
                                  => r_e_par, l_v.clone();
                    T::SwitchOr => l_t.clone(), r_t.clone()
                                => r_t, l_t;
                    T::SwitchOrV => l_v.clone(), r_v.clone()
                                 => r_v, l_v;
                );
                // Memoize and return
                self.best_t.borrow_mut().insert(hashkey, ret.clone());
                ret
            }
        }
    }
}

#[cfg(all(test, feature = "unstable"))]
mod benches {
    use secp256k1;
    use std::str::FromStr;
    use test::{Bencher, black_box};

    use ParseTree;
    use Descriptor;

    #[bench]
    pub fn compile(bh: &mut Bencher) {
        let desc = Descriptor::<secp256k1::PublicKey>::from_str(
            "and(thres(2,and(hash(),or(hash(),pk())),pk(),pk(),pk(),hash()),pkh())"
        ).expect("parsing");
        bh.iter( || {
            let pt = ParseTree::compile(&desc);
            black_box(pt);
        });
    }

    #[bench]
    pub fn compile_large(bh: &mut Bencher) {
        let desc = Descriptor::<secp256k1::PublicKey>::from_str(
            "or(pkh(),thres(9,hash(),pkh(),pk(),and(or(pkh(),pk()),pk()),time(),pk(),pk(),pk(),pk(),and(pk(),pk())))"
        ).expect("parsing");
        bh.iter( || {
            let pt = ParseTree::compile(&desc);
            black_box(pt);
        });
    }

    #[bench]
    pub fn compile_xlarge(bh: &mut Bencher) {
        let desc = Descriptor::<secp256k1::PublicKey>::from_str(
            "or(pk(),thres(4,pkh(),time(),multi(),and(time(),or(pkh(),or(pkh(),and(pkh(),thres(2,multi(),or(pkh(),and(thres(5,hash(),or(pkh(),pkh()),pkh(),pkh(),pkh(),multi(),pkh(),multi(),pk(),pkh(),pk()),pkh())),pkh(),or(and(pkh(),pk()),pk()),time()))))),pkh()))"
        ).expect("parsing");
        bh.iter( || {
            let pt = ParseTree::compile(&desc);
            black_box(pt);
        });
    }
}

