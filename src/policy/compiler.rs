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

//! # Policy Compiler
//!
//! Optimizing compiler from script descriptors to the AST representation of Bitcoin Script
//! described in the `astelem` module.
//!

use std::collections::HashMap;
use std::cell::RefCell;
use std::rc::Rc;
use std::fmt;

use arrayvec::{self, ArrayVec};
use bitcoin::blockdata::script;
use bitcoin_hashes::sha256;

use policy::Policy;
use miniscript::astelem::{E, Q, W, F, V, T};

pub enum CompiledNodeContent<P> {
    Pk(P),
    Multi(usize, Vec<P>),
    Time(u32),
    Hash(sha256::Hash),

    And(Box<CompiledNode<P>>, Box<CompiledNode<P>>),
    Or(Box<CompiledNode<P>>, Box<CompiledNode<P>>, f64, f64),
    Thresh(usize, Vec<CompiledNode<P>>),
}

pub struct CompiledNode<P> {
    pub content: CompiledNodeContent<P>,
    // All of these are actually maps from (f64, f64) pairs, but we transmute them
    // to u64 to allow them to be used as hashmap keys, since f64's by themselves
    // do not implement Eq. This is OK because we only need f64's to compare equal
    // when they were derived from exactly the same sequence of operations, and
    // in that case they'll have the same bit representation.
    pub best_e: RefCell<HashMap<(u64, u64), Cost<E<P>>>>,
    pub best_q: RefCell<HashMap<(u64, u64), Cost<Q<P>>>>,
    pub best_w: RefCell<HashMap<(u64, u64), Cost<W<P>>>>,
    pub best_f: RefCell<HashMap<(u64, u64), Cost<F<P>>>>,
    pub best_v: RefCell<HashMap<(u64, u64), Cost<V<P>>>>,
    pub best_t: RefCell<HashMap<(u64, u64), Cost<T<P>>>>,
}

#[derive(Clone, PartialEq, Debug)]
/// AST element and associated costs
pub struct Cost<T> {
    /// The actual AST element
    pub ast: Rc<T>,
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

impl<P> Cost<E<P>> {
    fn likely(fcost: Cost<F<P>>) -> Cost<E<P>> {
        Cost {
            ast: Rc::new(E::Likely(fcost.ast)),
            pk_cost: fcost.pk_cost + 4,
            sat_cost: fcost.sat_cost + 1.0,
            dissat_cost: 2.0,
        }
    }

    fn unlikely(fcost: Cost<F<P>>) -> Cost<E<P>> {
        Cost {
            ast: Rc::new(E::Unlikely(fcost.ast)),
            pk_cost: fcost.pk_cost + 4,
            sat_cost: fcost.sat_cost + 2.0,
            dissat_cost: 1.0,
        }
    }

    fn from_pair<L, R, FF: FnOnce(Rc<L>, Rc<R>) -> E<P>>(
        left: Cost<L>,
        right: Cost<R>,
        combine: FF,
        lweight: f64,
        rweight: f64
    ) -> Cost<E<P>> {
        let new_ast = Rc::new(combine(left.ast, right.ast));
        match *new_ast {
            E::CheckSig(..) | E::CheckMultiSig(..) | E::Time(..) |
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

impl<P> Cost<F<P>> {
    fn from_pair<L, R, FF: FnOnce(Rc<L>, Rc<R>) -> F<P>>(
        left: Cost<L>,
        right: Cost<R>,
        combine: FF,
        lweight: f64,
        rweight: f64
    ) -> Cost<F<P>> {
        debug_assert_eq!(lweight + rweight, 1.0);
        let new_ast = Rc::new(combine(left.ast, right.ast));
        match *new_ast {
            F::CheckSig(..) | F::CheckMultiSig(..) | F::Time(..) |
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
            F::DelayedOr(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 5,
                sat_cost: 72.0 + (left.sat_cost + 2.0) * lweight + (right.sat_cost + 1.0) * rweight,
                dissat_cost: 0.0,
            },
        }
    }
}

impl<P> Cost<V<P>> {
    fn from_pair<L, R, FF: FnOnce(Rc<L>, Rc<R>) -> V<P>>(
        left: Cost<L>,
        right: Cost<R>,
        combine: FF,
        lweight: f64,
        rweight: f64
    ) -> Cost<V<P>> {
        let new_ast = Rc::new(combine(left.ast, right.ast));
        match *new_ast {
            V::CheckSig(..) | V::CheckMultiSig(..) | V::Time(..) |
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
            V::DelayedOr(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 4,
                sat_cost: (72.0 + left.sat_cost + 2.0) * lweight + (72.0 + right.sat_cost + 1.0) * rweight,
                dissat_cost: 0.0,
            },
        }
    }
}

impl<P> Cost<T<P>> {
    fn from_pair<L, R, FF: FnOnce(Rc<L>, Rc<R>) -> T<P>>(
        left: Cost<L>,
        right: Cost<R>,
        combine: FF,
        lweight: f64,
        rweight: f64
    ) -> Cost<T<P>> {
        let new_ast = Rc::new(combine(left.ast, right.ast));
        match *new_ast {
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
            T::DelayedOr(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 4,
                sat_cost: 72.0 + (left.sat_cost + 2.0) * lweight + (right.sat_cost + 1.0) * rweight,
                dissat_cost: 0.0,
            },
        }
    }
}

fn script_num_cost(n: u32) -> usize {
    if n <= 16 {
        1
    } else if n <= 0x100 {
        2
    } else if n <= 0x10000 {
        3
    } else if n <= 0x1000000 {
        4
    } else {
        5
    }
}

fn min_cost<T>(one: Cost<T>, two: Cost<T>, p_sat: f64, p_dissat: f64) -> Cost<T> {
    let weight_one = one.pk_cost as f64 + p_sat * one.sat_cost + p_dissat * one.dissat_cost;
    let weight_two = two.pk_cost as f64 + p_sat * two.sat_cost + p_dissat * two.dissat_cost;

    if weight_one < weight_two {
        one
    } else if weight_two < weight_one {
        two
    } else {
        if one.sat_cost < two.sat_cost {
            one
        } else {
            two
        }
    }
}

fn fold_cost_vec<A, T: fmt::Debug>(mut v: ArrayVec<A>, p_sat: f64, p_dissat: f64) -> Cost<T>
    where A: arrayvec::Array<Item=Cost<T>>
{
    let last = v.pop().unwrap();
    v.into_iter().fold(last, |acc, n| min_cost(acc, n, p_sat, p_dissat))
}

macro_rules! rules(
    ($ast_type:ty, $p_sat:expr, $p_dissat:expr, $lweight:expr, $rweight:expr;
     $($combine:expr => $l:expr, $r:expr $(=> $lswap:expr, $rswap:expr)*;)*
     $(-> $condcombine:expr => $lcond:expr, $rcond:expr $(=> $lcondswap:expr, $rcondswap:expr)*;)*
     $(? $qcombine:expr => $lq:expr, $rq:expr;)*
     $(? -> $qcondcombine:expr => $lqcond:expr, $rqcond:expr;)*
    ) => ({
        let mut options = ArrayVec::<[_; 32]>::new();
        $(
        options.push(Cost::<$ast_type>::from_pair($l, $r, $combine, $lweight, $rweight));
        $(options.push(Cost::<$ast_type>::from_pair($lswap, $rswap, $combine, $rweight, $lweight)))*;
        )*
        $(
        let casted = Cost::<F<P>>::from_pair($lcond, $rcond, $condcombine, $lweight, $rweight);
        options.push(Cost::likely(casted.clone()));
        options.push(Cost::unlikely(casted));
        $(
        let casted = Cost::<F<P>>::from_pair($lcondswap, $rcondswap, $condcombine, $rweight, $lweight);
        options.push(Cost::likely(casted.clone()));
        options.push(Cost::unlikely(casted));
        )*
        )*
        $(
        if let (Some(left), Some(right)) = ($lq, $rq) {
            options.push(Cost::<$ast_type>::from_pair(left.clone(), right.clone(), $qcombine, $lweight, $rweight));
            options.push(Cost::<$ast_type>::from_pair(right, left, $qcombine, $rweight, $lweight));
        }
        )*
        $(
        if let (Some(left), Some(right)) = ($lqcond, $rqcond) {
            let casted = Cost::<F<P>>::from_pair(left.clone(), right.clone(), $qcondcombine, $lweight, $rweight);
            options.push(Cost::likely(casted.clone()));
            options.push(Cost::unlikely(casted));
            let casted = Cost::<F<P>>::from_pair(right.clone(), left.clone(), $qcondcombine, $rweight, $lweight);
            options.push(Cost::likely(casted.clone()));
            options.push(Cost::unlikely(casted));
        }
        )*
        fold_cost_vec(options, $p_sat, $p_dissat)
    })
);

impl<P: Clone + fmt::Debug> CompiledNode<P> {
    /// Build a compiled-node tree (without any compilations) from a Policy;
    /// basically just copy the descriptor contents into a richer data structure.
    pub fn from_policy(desc: &Policy<P>) -> CompiledNode<P> {
        let mut ret = CompiledNode {
            content: CompiledNodeContent::Time(0), // Time(0) used as "uninitialized"
            best_e: RefCell::new(HashMap::new()),
            best_q: RefCell::new(HashMap::new()),
            best_w: RefCell::new(HashMap::new()),
            best_f: RefCell::new(HashMap::new()),
            best_v: RefCell::new(HashMap::new()),
            best_t: RefCell::new(HashMap::new()),
        };

        match *desc {
            Policy::Key(ref pk) => ret.content = CompiledNodeContent::Pk(pk.clone()),
            Policy::Multi(k, ref pks) => ret.content = CompiledNodeContent::Multi(k, pks.clone()),
            Policy::Hash(ref hash) =>  ret.content = CompiledNodeContent::Hash(hash.clone()),
            Policy::Time(n) =>  ret.content = CompiledNodeContent::Time(n),
            Policy::And(ref left, ref right) => {
                ret.content = CompiledNodeContent::And(
                    Box::new(CompiledNode::from_policy(left)),
                    Box::new(CompiledNode::from_policy(right)),
                );
            }
            Policy::Or(ref left, ref right) => {
                ret.content = CompiledNodeContent::Or(
                    Box::new(CompiledNode::from_policy(left)),
                    Box::new(CompiledNode::from_policy(right)),
                    0.5,
                    0.5,
                );
            }
            Policy::AsymmetricOr(ref left, ref right) => {
                ret.content = CompiledNodeContent::Or(
                    Box::new(CompiledNode::from_policy(left)),
                    Box::new(CompiledNode::from_policy(right)),
                    127.0 / 128.0,
                    1.0 / 128.0,
                );
            }
            Policy::Threshold(k, ref subs) => {
                if subs.is_empty() {
                    panic!("Cannot have empty threshold in a descriptor");
                }

                ret.content = CompiledNodeContent::Thresh(
                    k,
                    subs.iter().map(|s| CompiledNode::from_policy(s)).collect(),
                );
            }
        }

        ret
    }

    /// Compute or lookup the best compilation of this node as an E
    pub fn best_e(&self, p_sat: f64, p_dissat: f64) -> Cost<E<P>> {
        let hashkey = (p_sat.to_bits(), p_dissat.to_bits());
        if let Some(cost) = self.best_e.borrow().get(&hashkey) {
            return cost.clone();
        }

        match self.content {
            // For terminals we just compute the best value and return it.
            CompiledNodeContent::Pk(ref key) => Cost {
                ast: Rc::new(E::CheckSig(key.clone())),
                pk_cost: 35,
                sat_cost: 72.0,
                dissat_cost: 1.0,
            },
            CompiledNodeContent::Multi(k, ref pks) => {
                let mut options = ArrayVec::<[_; 3]>::new();

                let num_cost = match(k > 16, pks.len() > 16) {
                    (true, true) => 4,
                    (false, true) => 3,
                    (true, false) => 3,
                    (false, false) => 2,
                };
                options.push(Cost {
                    ast: Rc::new(E::CheckMultiSig(k, pks.clone())),
                    pk_cost: num_cost + 34 * pks.len() + 1,
                    sat_cost: 1.0 + 72.0*k as f64,
                    dissat_cost: 1.0 + k as f64,
                });

                if p_dissat > 0.0 {
                    let fcost = self.best_f(p_sat, 0.0);
                    options.push(Cost::likely(fcost.clone()));
                    options.push(Cost::unlikely(fcost));
                }
                fold_cost_vec(options, p_sat, p_dissat)
            }
            CompiledNodeContent::Time(n) => {
                let num_cost = script_num_cost(n);
                Cost {
                    ast: Rc::new(E::Time(n)),
                    pk_cost: 5 + num_cost,
                    sat_cost: 2.0,
                    dissat_cost: 1.0,
                }
            }
            CompiledNodeContent::Hash(_) => {
                let fcost = self.best_f(p_sat, 0.0);
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
                let l_w = left.best_w(p_sat, p_dissat);
                let r_w = right.best_w(p_sat, p_dissat);

                let l_f = left.best_f(p_sat, 0.0);
                let r_f = right.best_f(p_sat, 0.0);
                let l_v = left.best_v(p_sat, 0.0);
                let r_v = right.best_v(p_sat, 0.0);

                let ret = rules!(
                    E<P>, p_sat, p_dissat, 0.5, 0.5;
                    E::ParallelAnd => l_e.clone(), r_w
                                   => r_e.clone(), l_w;
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
                let l_w_par = left.best_w(p_sat * lweight, p_dissat + p_sat * rweight);
                let r_w_par = right.best_w(p_sat * rweight, p_dissat + p_sat * lweight);
                let l_e_cas = left.best_e(p_sat * lweight, p_dissat);
                let r_e_cas = right.best_e(p_sat * rweight, p_dissat);

                let l_e_cond_par = left.best_e(p_sat * lweight, p_sat * rweight);
                let r_e_cond_par = right.best_e(p_sat * rweight, p_sat * lweight);
                let l_v = left.best_v(p_sat * lweight, 0.0);
                let r_v = right.best_v(p_sat * rweight, 0.0);
                let l_f = left.best_f(p_sat * lweight, 0.0);
                let r_f = right.best_f(p_sat * rweight, 0.0);
                let l_q = left.best_q(p_sat * lweight, 0.0);
                let r_q = right.best_q(p_sat * rweight, 0.0);

                let ret = rules!(
                    E<P>, p_sat, p_dissat, lweight, rweight;
                    E::ParallelOr => l_e_par.clone(), r_w_par
                                  => r_e_par.clone(), l_w_par;
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
                    ? -> F::DelayedOr => l_q, r_q;
                );
                // Memoize and return
                self.best_e.borrow_mut().insert(hashkey, ret.clone());
                ret
            }
            CompiledNodeContent::Thresh(k, ref subs) => {
                let num_cost = script_num_cost(k as u32);
                let avg_cost = k as f64 / subs.len() as f64;

                let e = subs[0].best_e(p_sat * avg_cost, p_dissat + p_sat * (1.0 - avg_cost));
                let mut pk_cost = 1 + num_cost + e.pk_cost;
                let mut sat_cost = e.sat_cost;
                let mut dissat_cost = e.dissat_cost;
                let mut ws = Vec::with_capacity(subs.len());

                for expr in &subs[1..] {
                    let w = expr.best_w(p_sat * avg_cost, p_dissat + p_sat * (1.0 - avg_cost));
                    pk_cost += w.pk_cost + 1;
                    sat_cost += w.sat_cost;
                    dissat_cost += w.dissat_cost;
                    ws.push(w.ast);
                }

                let noncond = Cost {
                    ast: Rc::new(E::Threshold(k, e.ast.clone(), ws.clone())),
                    pk_cost: pk_cost,
                    sat_cost: sat_cost * avg_cost + dissat_cost * (1.0 - avg_cost),
                    dissat_cost: dissat_cost,
                };
                let cond = {
                    let f = self.best_f(p_sat, 0.0);
                    let cond1 = Cost::likely(f.clone());
                    let cond2 = Cost::unlikely(f);
                    min_cost(cond1, cond2, p_sat, p_dissat)
                };
                let ret = min_cost(cond, noncond, p_sat, p_dissat);

                // Memoize the E version, and return
                self.best_e.borrow_mut().insert(hashkey, ret.clone());
                ret
            }
        }
    }

    /// Compute or lookup the best compilation of this node as an Q
    pub fn best_q(&self, p_sat: f64, p_dissat: f64) -> Option<Cost<Q<P>>> {
        debug_assert_eq!(p_dissat, 0.0);
        let hashkey = (p_sat.to_bits(), p_dissat.to_bits());
        if let Some(cost) = self.best_q.borrow().get(&hashkey) {
            return Some(cost.clone());
        }

        match self.content {
            // For most terminals, and thresholds, we just pass though to E
            // For terminals we just compute the best value and return it.
            CompiledNodeContent::Pk(ref key) => Some(Cost {
                ast: Rc::new(Q::Pubkey(key.clone())),
                pk_cost: 34,
                sat_cost: 0.0,
                dissat_cost: 0.0,
            }),
            CompiledNodeContent::And(ref left, ref right) => {
                let mut options = ArrayVec::<[_; 2]>::new();
                if let Some(rq) = right.best_q(p_sat, p_dissat) {
                    let lv = left.best_v(p_sat, p_dissat);
                    options.push(Cost {
                        ast: Rc::new(Q::And(lv.ast, rq.ast)),
                        pk_cost: lv.pk_cost + rq.pk_cost,
                        sat_cost: lv.sat_cost + rq.sat_cost,
                        dissat_cost: 0.0,
                    })
                }
                if let Some(lq) = left.best_q(p_sat, p_dissat) {
                    let rv = right.best_v(p_sat, p_dissat);
                    options.push(Cost {
                        ast: Rc::new(Q::And(rv.ast, lq.ast)),
                        pk_cost: rv.pk_cost + lq.pk_cost,
                        sat_cost: rv.sat_cost + lq.sat_cost,
                        dissat_cost: 0.0,
                    })
                }
                if options.is_empty() {
                    None
                } else {
                    Some(fold_cost_vec(options, p_sat, p_dissat))
                }
            }
            CompiledNodeContent::Or(ref left, ref right, lweight, rweight) => {
                if let (Some(lq), Some(rq)) = (left.best_q(p_sat * lweight, 0.0), right.best_q(p_sat * rweight, 0.0)) {
                    let mut options = ArrayVec::<[_; 2]>::new();
                    options.push(Cost {
                        ast: Rc::new(Q::Or(lq.ast.clone(), rq.ast.clone())),
                        pk_cost: lq.pk_cost + rq.pk_cost + 3,
                        sat_cost: lweight * (2.0 + lq.sat_cost) + rweight * (1.0 + rq.sat_cost),
                        dissat_cost: 0.0,
                    });
                    options.push(Cost {
                        ast: Rc::new(Q::Or(rq.ast, lq.ast)),
                        pk_cost: rq.pk_cost + lq.pk_cost + 3,
                        sat_cost: lweight * (1.0 + lq.sat_cost) + rweight * (2.0 + rq.sat_cost),
                        dissat_cost: 0.0,
                    });
                    Some(fold_cost_vec(options, p_sat, p_dissat))
                } else {
                    None
                }
            }
            CompiledNodeContent::Multi(..) | CompiledNodeContent::Time(..) |
            CompiledNodeContent::Hash(..) | CompiledNodeContent::Thresh(..) => None,
        }
    }

    /// Compute or lookup the best compilation of this node as a W
    pub fn best_w(&self, p_sat: f64, p_dissat: f64) -> Cost<W<P>> {
        // Special case `Hash` because it isn't really "wrapped"
        match self.content {
            CompiledNodeContent::Pk(ref key) => Cost {
                ast: Rc::new(W::CheckSig(key.clone())),
                pk_cost: 36,
                sat_cost: 72.0,
                dissat_cost: 1.0,
            },
            CompiledNodeContent::Time(n) => {
                let num_cost = script_num_cost(n);
                Cost {
                    ast: Rc::new(W::Time(n)),
                    pk_cost: 6 + num_cost,
                    sat_cost: 2.0,
                    dissat_cost: 1.0,
                }
            },
            CompiledNodeContent::Hash(hash) => Cost {
                ast: Rc::new(W::HashEqual(hash)),
                pk_cost: 45,
                sat_cost: 33.0,
                dissat_cost: 1.0,
            },
            _ => {
                let c = self.best_e(p_sat, p_dissat);
                Cost {
                    ast: Rc::new(W::CastE(c.ast)),
                    pk_cost: c.pk_cost + 2,
                    sat_cost: c.sat_cost,
                    dissat_cost: c.dissat_cost,
                }
            },
        }
    }

    /// Compute or lookup the best compilation of this node as an F
    pub fn best_f(&self, p_sat: f64, p_dissat: f64) -> Cost<F<P>> {
        debug_assert_eq!(p_dissat, 0.0);
        let hashkey = (p_sat.to_bits(), p_dissat.to_bits());
        if let Some(cost) = self.best_f.borrow().get(&hashkey) {
            return cost.clone();
        }

        match self.content {
            // For terminals we just compute the best value and return it.
            CompiledNodeContent::Pk(ref key) => Cost {
                ast: Rc::new(F::CheckSig(key.clone())),
                pk_cost: 36,
                sat_cost: 72.0,
                dissat_cost: 1.0,
            },
            CompiledNodeContent::Multi(k, ref pks) => {
                let num_cost = match(k > 16, pks.len() > 16) {
                    (true, true) => 4,
                    (false, true) => 3,
                    (true, false) => 3,
                    (false, false) => 2,
                };
                Cost {
                    ast: Rc::new(F::CheckMultiSig(k, pks.clone())),
                    pk_cost: num_cost + 34 * pks.len() + 2,
                    sat_cost: 1.0 + 72.0 * k as f64,
                    dissat_cost: 0.0,
                }
            },
            CompiledNodeContent::Time(n) => {
                let num_cost = script_num_cost(n);
                Cost {
                    ast: Rc::new(F::Time(n)),
                    pk_cost: 2 + num_cost,
                    sat_cost: 0.0,
                    dissat_cost: 0.0,
                }
            },
            CompiledNodeContent::Hash(hash) => Cost {
                ast: Rc::new(F::HashEqual(hash)),
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
                    F<P>, p_sat, 0.0, 0.5, 0.5;
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
                let l_q = left.best_q(p_sat * lweight, 0.0);
                let r_q = right.best_q(p_sat * rweight, 0.0);

                let ret = rules!(
                    F<P>, p_sat, 0.0, lweight, rweight;
                    F::CascadeOr => l_e_par, r_v.clone()
                                 => r_e_par, l_v.clone();
                    F::SwitchOr => l_f.clone(), r_f.clone()
                                => r_f, l_f;
                    F::SwitchOrV => l_v.clone(), r_v.clone()
                                 => r_v, l_v;
                    ? F::DelayedOr => l_q, r_q;
                );
                // Memoize and return
                self.best_f.borrow_mut().insert(hashkey, ret.clone());
                ret
            }
            CompiledNodeContent::Thresh(k, ref subs) => {
                let num_cost = script_num_cost(k as u32);
                let avg_cost = k as f64 / subs.len() as f64;

                let e = subs[0].best_e(p_sat * avg_cost, p_dissat + p_sat * (1.0 - avg_cost));
                let mut pk_cost = 2 + num_cost + e.pk_cost;
                let mut sat_cost = e.sat_cost;
                let mut dissat_cost = e.dissat_cost;
                let mut ws = Vec::with_capacity(subs.len());

                for expr in &subs[1..] {
                    let w = expr.best_w(p_sat * avg_cost, p_dissat + p_sat * (1.0 - avg_cost));
                    pk_cost += w.pk_cost + 1;
                    sat_cost += w.sat_cost;
                    dissat_cost += w.dissat_cost;
                    ws.push(w.ast);
                }

                // Don't bother memoizing because it's always the same
                Cost {
                    ast: Rc::new(F::Threshold(k, e.ast, ws)),
                    pk_cost: pk_cost,
                    sat_cost: sat_cost * avg_cost + dissat_cost * (1.0 - avg_cost),
                    dissat_cost: 0.0,
                }
            }
        }
    }

    /// Compute or lookup the best compilation of this node as a V
    pub fn best_v(&self, p_sat: f64, p_dissat: f64) -> Cost<V<P>> {
        debug_assert_eq!(p_dissat, 0.0);
        let hashkey = (p_sat.to_bits(), p_dissat.to_bits());
        if let Some(cost) = self.best_v.borrow().get(&hashkey) {
            return cost.clone();
        }

        match self.content {
            // For terminals we just compute the best value and return it.
            CompiledNodeContent::Pk(ref key) => Cost {
                ast: Rc::new(V::CheckSig(key.clone())),
                pk_cost: 35,
                sat_cost: 72.0,
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
                    ast: Rc::new(V::CheckMultiSig(k, pks.clone())),
                    pk_cost: num_cost + 34 * pks.len() + 1,
                    sat_cost: 1.0 + 72.0*k as f64,
                    dissat_cost: 0.0,
                }
            },
            CompiledNodeContent::Time(n) => {
                let num_cost = script_num_cost(n);
                Cost {
                    ast: Rc::new(V::Time(n)),
                    pk_cost: 2 + num_cost,
                    sat_cost: 0.0,
                    dissat_cost: 0.0,
                }
            },
            CompiledNodeContent::Hash(hash) => Cost {
                ast: Rc::new(V::HashEqual(hash)),
                pk_cost: 39,
                sat_cost: 33.0,
                dissat_cost: 0.0,
            },
            // For V, we can also avoid memoizing AND because it's just a passthrough
            CompiledNodeContent::And(ref left, ref right) => {
                let l = left.best_v(p_sat, 0.0);
                let r = right.best_v(p_sat, 0.0);
                Cost {
                    ast: Rc::new(V::And(l.ast, r.ast)),
                    pk_cost: l.pk_cost + r.pk_cost,
                    sat_cost: l.sat_cost + r.sat_cost,
                    dissat_cost: 0.0,
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
                let l_q = left.best_q(p_sat * lweight, 0.0);
                let r_q = right.best_q(p_sat * rweight, 0.0);

                let ret = rules!(
                    V<P>, p_sat, 0.0, lweight, rweight;
                    V::CascadeOr => l_e_par, r_v.clone()
                                 => r_e_par, l_v.clone();
                    V::SwitchOr => l_v.clone(), r_v.clone()
                                => r_v, l_v;
                    V::SwitchOrT => l_t.clone(), r_t.clone()
                                 => r_t, l_t;
                    ? V::DelayedOr => l_q, r_q;
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
                let mut ws = Vec::with_capacity(subs.len());

                for sub in &subs[1..] {
                    let w = sub.best_w(p_sat * avg_cost, p_sat * (1.0 - avg_cost));
                    pk_cost += w.pk_cost + 1;
                    sat_cost += w.sat_cost;
                    dissat_cost += w.dissat_cost;
                    ws.push(w.ast);
                }

                // Don't bother memoizing because it's always the same
                Cost {
                    ast: Rc::new(V::Threshold(k, e.ast, ws)),
                    pk_cost: pk_cost,
                    sat_cost: sat_cost * avg_cost + dissat_cost * (1.0 - avg_cost),
                    dissat_cost: 0.0,
                }
            }
        }
    }

    /// Compute or lookup the best compilation of this node as a T
    pub fn best_t(&self, p_sat: f64, p_dissat: f64) -> Cost<T<P>> {
        debug_assert_eq!(p_dissat, 0.0);
        let hashkey = (p_sat.to_bits(), p_dissat.to_bits());
        if let Some(cost) = self.best_t.borrow().get(&hashkey) {
            return cost.clone();
        }

        match self.content {
            // For most terminals, and thresholds, we just pass though to E
            CompiledNodeContent::Pk(..) | CompiledNodeContent::Multi(..) | CompiledNodeContent::Thresh(..) => {
                let e = self.best_e(p_sat, 0.0);
                Cost {
                    ast: Rc::new(T::CastE((*e.ast).clone())),
                    pk_cost: e.pk_cost,
                    sat_cost: e.sat_cost,
                    dissat_cost: 0.0,
                }
            },
            CompiledNodeContent::Time(n) => {
                let num_cost = script::Builder::new().push_int(n as i64).into_script().len();
                Cost {
                    ast: Rc::new(T::Time(n)),
                    pk_cost: 1 + num_cost,
                    sat_cost: 0.0,
                    dissat_cost: 0.0,
                }
            }
            CompiledNodeContent::Hash(hash) => Cost {
                ast: Rc::new(T::HashEqual(hash)),
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
                    T<P>, p_sat, 0.0, 0.0, 0.0;
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
                let l_w_par = left.best_w(p_sat * lweight, p_sat * rweight);
                let r_w_par = right.best_w(p_sat * rweight, p_sat * lweight);

                let l_t = left.best_t(p_sat * lweight, 0.0);
                let r_t = right.best_t(p_sat * rweight, 0.0);
                let l_v = left.best_v(p_sat * lweight, 0.0);
                let r_v = right.best_v(p_sat * rweight, 0.0);
                let l_q = left.best_q(p_sat * lweight, 0.0);
                let r_q = right.best_q(p_sat * rweight, 0.0);

                let ret = rules!(
                    T<P>, p_sat, 0.0, lweight, rweight;
                    T::ParallelOr => l_e_par.clone(), r_w_par
                                  => r_e_par.clone(), l_w_par;
                    T::CascadeOr => l_e_par.clone(), r_t.clone()
                                 => r_e_par.clone(), l_t.clone();
                    T::CascadeOrV => l_e_par, r_v.clone()
                                  => r_e_par, l_v.clone();
                    T::SwitchOr => l_t.clone(), r_t.clone()
                                => r_t, l_t;
                    T::SwitchOrV => l_v.clone(), r_v.clone()
                                 => r_v, l_v;
                    ? T::DelayedOr => l_q, r_q;
                );
                // Memoize and return
                self.best_t.borrow_mut().insert(hashkey, ret.clone());
                ret
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use super::*;

    #[test]
    fn compile_q() {
        let policy = Policy::<String>::from_str(
            "aor(and(pk(),pk()),pk())"
        ).expect("parsing");
        let descriptor = policy.compile();
        assert_eq!(
            format!("{:?}", descriptor),
            "T.or_d(Q.pk(\"\"),Q.and_p(V.pk(\"\"),Q.pk(\"\")))"
        );

        let policy = Policy::<String>::from_str(
            "and(and(and(aor(thres(2,pk(),pk(),thres(2,aor(pk(),pk()),time(),or(and(pk(),time()),and(pk(),hash())),pk())),pk()),hash()),aor(pk(),time())),aor(time(),pk()))"
        ).expect("parsing");
        let descriptor = policy.compile();
        assert_eq!(
            format!("{:?}", descriptor),
            "T.and_p(V.and_p(V.and_p(V.or_v(E.thres(2,E.pk(\"\"),W.pk(\"\"),WE.thres(2,E.or_p(E.pk(\"\"),W.pk(\"\")),W.time(268435456),WE.lift_u(F.or_d(Q.and_p(V.time(268435456),Q.pk(\"\")),Q.and_p(V.hash(66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925),Q.pk(\"\")))),W.pk(\"\"))),V.pk(\"\")),V.hash(66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925)),V.or_v(E.pk(\"\"),V.time(268435456))),T.or_c(E.pk(\"\"),T.time(268435456)))"
        );
    }
}

#[cfg(all(test, feature = "unstable"))]
mod benches {
    use secp256k1;
    use std::str::FromStr;
    use test::{Bencher, black_box};

    use ParseTree;
    use Policy;

    #[bench]
    pub fn compile(bh: &mut Bencher) {
        let desc = Policy::<secp256k1::PublicKey>::from_str(
            "and(thres(2,and(hash(),or(hash(),pk())),pk(),pk(),pk(),hash()),pkh())"
        ).expect("parsing");
        bh.iter( || {
            let pt = ParseTree::compile(&desc);
            black_box(pt);
        });
    }

    #[bench]
    pub fn compile_large(bh: &mut Bencher) {
        let desc = Policy::<secp256k1::PublicKey>::from_str(
            "or(pkh(),thres(9,hash(),pkh(),pk(),and(or(pkh(),pk()),pk()),time(),pk(),pk(),pk(),pk(),and(pk(),pk())))"
        ).expect("parsing");
        bh.iter( || {
            let pt = ParseTree::compile(&desc);
            black_box(pt);
        });
    }

    #[bench]
    pub fn compile_xlarge(bh: &mut Bencher) {
        let desc = Policy::<secp256k1::PublicKey>::from_str(
            "or(pk(),thres(4,pkh(),time(),multi(),and(time(),or(pkh(),or(pkh(),and(pkh(),thres(2,multi(),or(pkh(),and(thres(5,hash(),or(pkh(),pkh()),pkh(),pkh(),pkh(),multi(),pkh(),multi(),pk(),pkh(),pk()),pkh())),pkh(),or(and(pkh(),pk()),pk()),time()))))),pkh()))"
        ).expect("parsing");
        bh.iter( || {
            let pt = ParseTree::compile(&desc);
            black_box(pt);
        });
    }
}

