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
use std::fmt;

use arrayvec::ArrayVec;
use bitcoin::blockdata::script;
use bitcoin_hashes::sha256;

use policy::Policy;
use miniscript::astelem::AstElem;

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
    pub best_e: RefCell<HashMap<(u64, u64), Cost<P>>>,
    pub best_q: RefCell<HashMap<(u64, u64), Cost<P>>>,
    pub best_w: RefCell<HashMap<(u64, u64), Cost<P>>>,
    pub best_f: RefCell<HashMap<(u64, u64), Cost<P>>>,
    pub best_v: RefCell<HashMap<(u64, u64), Cost<P>>>,
    pub best_t: RefCell<HashMap<(u64, u64), Cost<P>>>,
}

#[derive(Clone, PartialEq, Debug)]
/// AST element and associated costs
pub struct Cost<P> {
    /// The actual AST element
    pub ast: AstElem<P>,
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

impl<P> Cost<P> {
    fn dummy() -> Cost<P> {
        Cost {
            ast: AstElem::Time(0),
            pk_cost: 1024 * 1024,
            sat_cost: 1024.0 * 1024.0,
            dissat_cost: 1024.0 * 1024.0,
        }
    }

    fn wrap(ecost: Cost<P>) -> Cost<P> {
        debug_assert!(ecost.ast.is_e());
        Cost {
            ast: AstElem::Wrap(Box::new(ecost.ast)),
            pk_cost: ecost.pk_cost + 2,
            sat_cost: ecost.sat_cost,
            dissat_cost: ecost.dissat_cost,
        }
    }

    fn tru(vcost: Cost<P>) -> Cost<P> {
        debug_assert!(vcost.ast.is_v());
        Cost {
            ast: AstElem::True(Box::new(vcost.ast)),
            pk_cost: vcost.pk_cost + 1,
            sat_cost: vcost.sat_cost,
            dissat_cost: 0.0,
        }
    }

    fn likely(fcost: Cost<P>) -> Cost<P> {
        debug_assert!(fcost.ast.is_f());
        Cost {
            ast: AstElem::Likely(Box::new(fcost.ast)),
            pk_cost: fcost.pk_cost + 4,
            sat_cost: fcost.sat_cost + 1.0,
            dissat_cost: 2.0,
        }
    }

    fn unlikely(fcost: Cost<P>) -> Cost<P> {
        debug_assert!(fcost.ast.is_f());
        Cost {
            ast: AstElem::Unlikely(Box::new(fcost.ast)),
            pk_cost: fcost.pk_cost + 4,
            sat_cost: fcost.sat_cost + 2.0,
            dissat_cost: 1.0,
        }
    }

    fn from_terminal(ast: AstElem<P>) -> Cost<P> {
        let ret = match ast {
            AstElem::Pk(..) => Cost {
                ast: ast,
                pk_cost: 35,
                sat_cost: 72.0,
                dissat_cost: 1.0,
            },
            AstElem::PkV(..) => Cost {
                ast: ast,
                pk_cost: 35,
                sat_cost: 72.0,
                dissat_cost: 0.0,
            },
            AstElem::PkQ(..) => Cost {
                ast: ast,
                pk_cost: 34,
                sat_cost: 0.0,
                dissat_cost: 0.0,
            },
            AstElem::PkW(..) => Cost {
                ast: ast,
                pk_cost: 36,
                sat_cost: 72.0,
                dissat_cost: 1.0,
            },
            AstElem::Multi(k, keys) => {
                let num_cost = match(k > 16, keys.len() > 16) {
                    (true, true) => 4,
                    (false, true) => 3,
                    (true, false) => 3,
                    (false, false) => 2,
                };
                Cost {
                    pk_cost: num_cost + 34 * keys.len() + 1,
                    sat_cost: 1.0 + 72.0 * k as f64,
                    dissat_cost: 1.0 + k as f64,
                    ast: AstElem::Multi(k, keys),
                }
            },
            AstElem::MultiV(k, keys) => {
                let num_cost = match(k > 16, keys.len() > 16) {
                    (true, true) => 4,
                    (false, true) => 3,
                    (true, false) => 3,
                    (false, false) => 2,
                };
                Cost {
                    pk_cost: num_cost + 34 * keys.len() + 1,
                    sat_cost: 1.0 + 72.0 * k as f64,
                    dissat_cost: 0.0,
                    ast: AstElem::MultiV(k, keys),
                }
            },
            AstElem::TimeT(t) => {
                let num_cost = script_num_cost(t);
                Cost {
                    ast: ast,
                    pk_cost: 1 + num_cost,
                    sat_cost: 0.0,
                    dissat_cost: 0.0,
                }
            },
            AstElem::TimeV(t) => {
                let num_cost = script_num_cost(t);
                Cost {
                    ast: ast,
                    pk_cost: 2 + num_cost,
                    sat_cost: 0.0,
                    dissat_cost: 0.0,
                }
            },
            AstElem::TimeF(t) => {
                let num_cost = script_num_cost(t);
                Cost {
                    ast: ast,
                    pk_cost: 2 + num_cost,
                    sat_cost: 0.0,
                    dissat_cost: 0.0,
                }
            },
            AstElem::Time(t) => {
                let num_cost = script_num_cost(t);
                Cost {
                    ast: ast,
                    pk_cost: 5 + num_cost,
                    sat_cost: 2.0,
                    dissat_cost: 1.0,
                }
            },
            AstElem::TimeW(t) => {
                let num_cost = script_num_cost(t);
                Cost {
                    ast: ast,
                    pk_cost: 6 + num_cost,
                    sat_cost: 2.0,
                    dissat_cost: 1.0,
                }
            },
            AstElem::HashT(..) => Cost {
                ast: ast,
                pk_cost: 39,
                sat_cost: 33.0,
                dissat_cost: 0.0,
            },
            AstElem::HashV(..) => Cost {
                ast: ast,
                pk_cost: 39,
                sat_cost: 33.0,
                dissat_cost: 0.0,
            },
            AstElem::HashW(..) => Cost {
                ast: ast,
                pk_cost: 45,
                sat_cost: 33.0,
                dissat_cost: 1.0,
            },
            AstElem::True(..) |
            AstElem::Wrap(..) |
            AstElem::Likely(..) |
            AstElem::Unlikely(..) |
            AstElem::AndCat(..) |
            AstElem::AndBool(..) |
            AstElem::AndCasc(..) |
            AstElem::OrBool(..) |
            AstElem::OrCasc(..) |
            AstElem::OrCont(..) |
            AstElem::OrKey(..) |
            AstElem::OrKeyV(..) |
            AstElem::OrIf(..) |
            AstElem::OrIfV(..) |
            AstElem::OrNotif(..) |
            AstElem::Thresh(..) |
            AstElem::ThreshV(..) => unreachable!(),
        };
        ret
    }

    fn from_pair<FF: FnOnce(Box<AstElem<P>>, Box<AstElem<P>>) -> AstElem<P>>(
        left: Cost<P>,
        right: Cost<P>,
        combine: FF,
        lweight: f64,
        rweight: f64
    ) -> Cost<P> {
        let new_ast = combine(Box::new(left.ast), Box::new(right.ast));
        match new_ast {
            AstElem::Pk(..) |
            AstElem::PkV(..) |
            AstElem::PkQ(..) |
            AstElem::PkW(..) |
            AstElem::Multi(..) |
            AstElem::MultiV(..) |
            AstElem::TimeT(..) |
            AstElem::TimeV(..) |
            AstElem::TimeF(..) |
            AstElem::Time(..) |
            AstElem::TimeW(..) |
            AstElem::HashT(..) |
            AstElem::HashV(..) |
            AstElem::HashW(..) |
            AstElem::True(..) |
            AstElem::Wrap(..) |
            AstElem::Likely(..) |
            AstElem::Unlikely(..) |
            AstElem::Thresh(..) |
            AstElem::ThreshV(..) => unreachable!(),
            AstElem::AndCat(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost,
                sat_cost: left.sat_cost + right.sat_cost,
                dissat_cost: 0.0,
            },
            AstElem::AndBool(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 1,
                sat_cost: left.sat_cost + right.sat_cost,
                dissat_cost: left.dissat_cost + right.dissat_cost,
            },
            AstElem::AndCasc(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 4,
                sat_cost: left.sat_cost + right.sat_cost,
                dissat_cost: left.dissat_cost,
            },
            AstElem::OrBool(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 1,
                sat_cost: (left.sat_cost + right.dissat_cost) * lweight + (right.sat_cost + left.dissat_cost) * rweight,
                dissat_cost: left.dissat_cost + right.dissat_cost,
            },
            AstElem::OrCasc(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 3,
                sat_cost: left.sat_cost * lweight + (right.sat_cost + left.dissat_cost) * rweight,
                dissat_cost: left.dissat_cost + right.dissat_cost,
            },
            AstElem::OrCont(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 2,
                sat_cost: left.sat_cost * lweight + (left.dissat_cost + right.sat_cost) * rweight,
                dissat_cost: 0.0,
            },
            AstElem::OrKey(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 4,
                sat_cost: 72.0 + (left.sat_cost + 2.0) * lweight + (right.sat_cost + 1.0) * rweight,
                dissat_cost: 0.0,
            },
            AstElem::OrKeyV(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 4,
                sat_cost: 72.0 + (left.sat_cost + 2.0) * lweight + (right.sat_cost + 1.0) * rweight,
                dissat_cost: 0.0,
            },
            AstElem::OrIf(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 3,
                sat_cost: (left.sat_cost + 2.0) * lweight + (right.sat_cost + 1.0) * rweight,
                dissat_cost: 1.0 + right.dissat_cost,
            },
            AstElem::OrIfV(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 4,
                sat_cost: (left.sat_cost + 2.0) * lweight + (right.sat_cost + 1.0) * rweight,
                dissat_cost: 0.0,
            },
            AstElem::OrNotif(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 3,
                sat_cost: (left.sat_cost + 1.0) * lweight + (right.sat_cost + 2.0) * rweight,
                dissat_cost: left.dissat_cost + 1.0,
            },
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

fn min_cost<P>(one: Cost<P>, two: Cost<P>, p_sat: f64, p_dissat: f64) -> Cost<P> {
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

fn fold_cost_vec<V, P: fmt::Debug>(v: V, p_sat: f64, p_dissat: f64) -> Cost<P>
    where V: Iterator<Item=Cost<P>>
{
    let mut iter = v.into_iter();
    let last = iter.next().unwrap();
    iter.fold(last, |acc, n| min_cost(acc, n, p_sat, p_dissat))
}

macro_rules! min_cost_of {
    (
        $p_sat:expr, $p_dissat:expr, $lweight:expr, $rweight:expr;
        $(base $basecombine:ident, $lbase:expr, $rbase:expr;)*
        $(swap $swapcombine:ident, $rswap:expr, $lswap:expr;)*
        $(cond_base $condbasecombine:ident, $condlbase:expr, $condrbase:expr;)*
        $(cond_swap $condswapcombine:ident, $condrswap:expr, $condlswap:expr;)*
        $(true_base $truebasecombine:ident, $truelbase:expr, $truerbase:expr;)*
        $(true_swap $trueswapcombine:ident, $truerswap:expr, $truelswap:expr;)*
        $(key_base $keycombine:ident, $lkey:expr, $rkey:expr;)*
        $(key_cond $condlkey:expr, $condrkey:expr;)*
    ) => ({
        let mut best = Cost::dummy();

        $(
            best = min_cost(
                best,
                Cost::from_pair(
                    $lbase,
                    $rbase,
                    AstElem::$basecombine,
                    $lweight,
                    $rweight,
                ),
                $p_sat,
                $p_dissat,
            );
        )*

        $(
            best = min_cost(
                best,
                Cost::from_pair(
                    $rswap,
                    $lswap,
                    AstElem::$swapcombine,
                    $rweight,
                    $lweight,
                ),
                $p_sat,
                $p_dissat,
            );
        )*

        $(
            let mut base = Cost::from_pair(
                $condlbase,
                $condrbase,
                AstElem::$condbasecombine,
                $lweight,
                $rweight,
            );
            if base.ast.is_v() {
                base = Cost::tru(base);
            }
            best = min_cost(
                best,
                Cost::likely(base.clone()),
                $p_sat,
                $p_dissat,
            );
            best = min_cost(
                best,
                Cost::unlikely(base.clone()),
                $p_sat,
                $p_dissat,
            );
        )*

        $(
            let mut swap = Cost::from_pair(
                $condrswap,
                $condlswap,
                AstElem::$condswapcombine,
                $rweight,
                $lweight,
            );
            if swap.ast.is_v() {
                swap = Cost::tru(swap);
            }
            best = min_cost(
                best,
                Cost::likely(swap.clone()),
                $p_sat,
                $p_dissat,
            );
            best = min_cost(
                best,
                Cost::unlikely(swap.clone()),
                $p_sat,
                $p_dissat,
            );
        )*

        $(
            let base = Cost::from_pair(
                $truelbase,
                $truerbase,
                AstElem::$truebasecombine,
                $lweight,
                $rweight,
            );
            best = min_cost(
                best,
                Cost::tru(base),
                $p_sat,
                $p_dissat,
            );
        )*

        $(
            let swap = Cost::from_pair(
                $truerswap,
                $truelswap,
                AstElem::$trueswapcombine,
                $rweight,
                $lweight,
            );
            best = min_cost(
                best,
                Cost::tru(swap),
                $p_sat,
                $p_dissat,
            );
        )*

        $(
            if let (Some(left), Some(right)) = ($lkey, $rkey) {
                best = min_cost(
                    best,
                    Cost::from_pair(
                        left.clone(),
                        right.clone(),
                        AstElem::$keycombine,
                        $lweight,
                        $rweight,
                    ),
                    $p_sat,
                    $p_dissat,
                );
                best = min_cost(
                    best,
                    Cost::from_pair(
                        right,
                        left,
                        AstElem::$keycombine,
                        $rweight,
                        $lweight,
                    ),
                    $p_sat,
                    $p_dissat,
                );
            }
        )*

        $(
            if let (Some(left), Some(right)) = ($condlkey, $condrkey) {
                let base = Cost::tru(Cost::from_pair(
                    left.clone(),
                    right.clone(),
                    AstElem::OrKeyV,
                    $lweight,
                    $rweight,
                ));
                best = min_cost(
                    best,
                    Cost::unlikely(base.clone()),
                    $p_sat,
                    $p_dissat,
                );
                best = min_cost(
                    best,
                    Cost::likely(base),
                    $p_sat,
                    $p_dissat,
                );

                let swap = Cost::tru(Cost::from_pair(
                    right,
                    left,
                    AstElem::OrKeyV,
                    $rweight,
                    $lweight,
                ));
                best = min_cost(
                    best,
                    Cost::unlikely(swap.clone()),
                    $p_sat,
                    $p_dissat,
                );
                best = min_cost(
                    best,
                    Cost::likely(swap),
                    $p_sat,
                    $p_dissat,
                );
            }
        )*

        best
    })
}

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
    pub fn best_e(&self, p_sat: f64, p_dissat: f64) -> Cost<P> {
        let hashkey = (p_sat.to_bits(), p_dissat.to_bits());
        if let Some(cost) = self.best_e.borrow().get(&hashkey) {
            return cost.clone();
        }

        match self.content {
            // For terminals we just compute the best value and return it.
            CompiledNodeContent::Pk(ref key) => {
                Cost::from_terminal(AstElem::Pk(key.clone()))
            },
            CompiledNodeContent::Multi(k, ref pks) => {
                let mut options = ArrayVec::<[_; 3]>::new();

                options.push(Cost::from_terminal(AstElem::Multi(k, pks.clone())));

                if p_dissat > 0.0 {
                    let fcost = self.best_f(p_sat, 0.0);
                    options.push(Cost::likely(fcost.clone()));
                    options.push(Cost::unlikely(fcost));
                }
                fold_cost_vec(options.into_iter(), p_sat, p_dissat)
            }
            CompiledNodeContent::Time(t) => {
                Cost::from_terminal(AstElem::Time(t))
            },
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

                let ret = min_cost_of!(
                    p_sat, p_dissat, 0.5, 0.5;
                    base AndBool, l_e.clone(), r_w;
                    base AndCasc, l_e, r_f.clone();
                    swap AndBool, r_e.clone(), l_w;
                    swap AndCasc, r_e, l_f.clone();
                    cond_base AndCat, l_v, r_f;
                    cond_swap AndCat, r_v, l_f;
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

                let ret = min_cost_of!(
                    p_sat, p_dissat, lweight, rweight;
                    base OrBool, l_e_par.clone(), r_w_par;
                    base OrCasc, l_e_par, r_e_cas.clone();
                    base OrIf,   l_f.clone(), r_e_cas.clone();
                    base OrNotif, l_f.clone(), r_e_cas.clone();
                    swap OrBool, r_e_par.clone(), l_w_par;
                    swap OrCasc, r_e_par, l_e_cas.clone();
                    swap OrIf,   r_f.clone(), l_e_cas.clone();
                    swap OrNotif, r_f.clone(), l_e_cas.clone();
                    cond_base OrCont, l_e_cond_par, r_v.clone();
                    cond_base OrIf, l_f.clone(), r_f.clone();
                    cond_base OrIf, l_v.clone(), r_v.clone();
                    cond_swap OrCont, r_e_cond_par, l_v.clone();
                    cond_swap OrIf, r_f, l_f;
                    cond_swap OrIf, r_v, l_v;
                    key_cond l_q, r_q;
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
                let mut sub_asts = Vec::with_capacity(subs.len());

                sub_asts.push(e.ast.clone());
                for expr in &subs[1..] {
                    let w = expr.best_w(p_sat * avg_cost, p_dissat + p_sat * (1.0 - avg_cost));
                    pk_cost += w.pk_cost + 1;
                    sat_cost += w.sat_cost;
                    dissat_cost += w.dissat_cost;
                    sub_asts.push(w.ast);
                }

                let noncond = Cost {
                    ast: AstElem::Thresh(k, sub_asts),
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
    pub fn best_q(&self, p_sat: f64, p_dissat: f64) -> Option<Cost<P>> {
        debug_assert_eq!(p_dissat, 0.0);
        let hashkey = (p_sat.to_bits(), p_dissat.to_bits());
        if let Some(cost) = self.best_q.borrow().get(&hashkey) {
            return Some(cost.clone());
        }

        match self.content {
            CompiledNodeContent::Pk(ref key) => Some(
                Cost::from_terminal(AstElem::PkQ(key.clone()))
            ),
            CompiledNodeContent::And(ref left, ref right) => {
                let mut options = ArrayVec::<[_; 2]>::new();
                if let Some(rq) = right.best_q(p_sat, p_dissat) {
                    let lv = left.best_v(p_sat, p_dissat);
                    options.push(Cost {
                        ast: AstElem::AndCat(Box::new(lv.ast), Box::new(rq.ast)),
                        pk_cost: lv.pk_cost + rq.pk_cost,
                        sat_cost: lv.sat_cost + rq.sat_cost,
                        dissat_cost: 0.0,
                    })
                }
                if let Some(lq) = left.best_q(p_sat, p_dissat) {
                    let rv = right.best_v(p_sat, p_dissat);
                    options.push(Cost {
                        ast: AstElem::AndCat(Box::new(rv.ast), Box::new(lq.ast)),
                        pk_cost: rv.pk_cost + lq.pk_cost,
                        sat_cost: rv.sat_cost + lq.sat_cost,
                        dissat_cost: 0.0,
                    })
                }
                if options.is_empty() {
                    None
                } else {
                    Some(fold_cost_vec(options.into_iter(), p_sat, p_dissat))
                }
            }
            CompiledNodeContent::Or(ref left, ref right, lweight, rweight) => {
                if let (Some(lq), Some(rq)) = (left.best_q(p_sat * lweight, 0.0), right.best_q(p_sat * rweight, 0.0)) {
                    let mut options = ArrayVec::<[_; 2]>::new();
                    options.push(Cost {
                        ast: AstElem::OrIf(Box::new(lq.ast.clone()), Box::new(rq.ast.clone())),
                        pk_cost: lq.pk_cost + rq.pk_cost + 3,
                        sat_cost: lweight * (2.0 + lq.sat_cost) + rweight * (1.0 + rq.sat_cost),
                        dissat_cost: 0.0,
                    });
                    options.push(Cost {
                        ast: AstElem::OrIf(Box::new(rq.ast), Box::new(lq.ast)),
                        pk_cost: rq.pk_cost + lq.pk_cost + 3,
                        sat_cost: lweight * (1.0 + lq.sat_cost) + rweight * (2.0 + rq.sat_cost),
                        dissat_cost: 0.0,
                    });
                    Some(fold_cost_vec(options.into_iter(), p_sat, p_dissat))
                } else {
                    None
                }
            }
            CompiledNodeContent::Multi(..) | CompiledNodeContent::Time(..) |
            CompiledNodeContent::Hash(..) | CompiledNodeContent::Thresh(..) => None,
        }
    }

    /// Compute or lookup the best compilation of this node as a W
    pub fn best_w(&self, p_sat: f64, p_dissat: f64) -> Cost<P> {
        // Special case `Hash` because it isn't really "wrapped"
        match self.content {
            CompiledNodeContent::Pk(ref key) => {
                Cost::from_terminal(AstElem::PkW(key.clone()))
            },
            CompiledNodeContent::Time(t) => {
                Cost::from_terminal(AstElem::TimeW(t))
            },
            CompiledNodeContent::Hash(h) => {
                Cost::from_terminal(AstElem::HashW(h))
            },
            _ => Cost::wrap(self.best_e(p_sat, p_dissat)),
        }
    }

    /// Compute or lookup the best compilation of this node as an F
    pub fn best_f(&self, p_sat: f64, p_dissat: f64) -> Cost<P> {
        debug_assert_eq!(p_dissat, 0.0);
        let hashkey = (p_sat.to_bits(), p_dissat.to_bits());
        if let Some(cost) = self.best_f.borrow().get(&hashkey) {
            return cost.clone();
        }

        match self.content {
            // For terminals we just compute the best value and return it.
            CompiledNodeContent::Pk(ref key) => Cost::tru(
                Cost::from_terminal(AstElem::PkV(key.clone()))
            ),
            CompiledNodeContent::Multi(k, ref pks) => Cost::tru(
                Cost::from_terminal(AstElem::MultiV(k, pks.clone()))
            ),
            CompiledNodeContent::Time(n) => {
                Cost::from_terminal(AstElem::TimeF(n))
            },
            CompiledNodeContent::Hash(h) => Cost::tru(
                Cost::from_terminal(AstElem::HashV(h))
            ),
            // The non-terminals are more interesting
            CompiledNodeContent::And(ref left, ref right) => {
                let vl = left.best_v(p_sat, 0.0);
                let vr = right.best_v(p_sat, 0.0);
                let fl = left.best_f(p_sat, 0.0);
                let fr = right.best_f(p_sat, 0.0);

                let ret = min_cost_of!(
                    p_sat, 0.0, 0.5, 0.5;
                    base AndCat, vl, fr;
                    swap AndCat, vr, fl;
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

                let ret = min_cost_of!(
                    p_sat, 0.0, lweight, rweight;
                    base OrIf, l_f.clone(), r_f.clone();
                    swap OrIf, r_f, l_f;
                    true_base OrCont, l_e_par, r_v.clone();
                    true_base OrIf, l_v.clone(), r_v.clone();
                    true_swap OrCont, r_e_par, l_v.clone();
                    true_swap OrIf, r_v, l_v;
                    key_cond l_q, r_q;
                );

                // Memoize and return
                self.best_f.borrow_mut().insert(hashkey, ret.clone());
                ret
            }
            CompiledNodeContent::Thresh(k, ref subs) => {
                let num_cost = script_num_cost(k as u32);
                let avg_cost = k as f64 / subs.len() as f64;

                let e = subs[0].best_e(p_sat * avg_cost, p_dissat + p_sat * (1.0 - avg_cost));
                let mut pk_cost = 1 + num_cost + e.pk_cost;
                let mut sat_cost = e.sat_cost;
                let mut dissat_cost = e.dissat_cost;
                let mut sub_asts = Vec::with_capacity(subs.len());

                sub_asts.push(e.ast);
                for expr in &subs[1..] {
                    let w = expr.best_w(p_sat * avg_cost, p_dissat + p_sat * (1.0 - avg_cost));
                    pk_cost += w.pk_cost + 1;
                    sat_cost += w.sat_cost;
                    dissat_cost += w.dissat_cost;
                    sub_asts.push(w.ast);
                }

                // Don't bother memoizing because it's always the same
                Cost::tru(Cost {
                    ast: AstElem::ThreshV(k, sub_asts),
                    pk_cost: pk_cost,
                    sat_cost: sat_cost * avg_cost + dissat_cost * (1.0 - avg_cost),
                    dissat_cost: 0.0,
                })
            }
        }
    }

    /// Compute or lookup the best compilation of this node as a V
    pub fn best_v(&self, p_sat: f64, p_dissat: f64) -> Cost<P> {
        debug_assert_eq!(p_dissat, 0.0);
        let hashkey = (p_sat.to_bits(), p_dissat.to_bits());
        if let Some(cost) = self.best_v.borrow().get(&hashkey) {
            return cost.clone();
        }

        match self.content {
            // For terminals we just compute the best value and return it.
            CompiledNodeContent::Pk(ref key) => {
                Cost::from_terminal(AstElem::PkV(key.clone()))
            },
            CompiledNodeContent::Multi(k, ref pks) => {
                Cost::from_terminal(AstElem::MultiV(k, pks.clone()))
            },
            CompiledNodeContent::Time(n) => {
                Cost::from_terminal(AstElem::TimeV(n))
            },
            CompiledNodeContent::Hash(h) => {
                Cost::from_terminal(AstElem::HashV(h))
            },
            // For V, we can also avoid memoizing AND because it's just a passthrough
            CompiledNodeContent::And(ref left, ref right) => {
                Cost::from_pair(
                    left.best_v(p_sat, 0.0),
                    right.best_v(p_sat, 0.0),
                    AstElem::AndCat,
                    0.0,
                    0.0,
                )
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

                let ret = min_cost_of!(
                    p_sat, 0.0, lweight, rweight;
                    base OrCont, l_e_par, r_v.clone();
                    base OrIf, l_v.clone(), r_v.clone();
                    base OrIfV, l_t.clone(), r_t.clone();
                    swap OrCont, r_e_par, l_v.clone();
                    swap OrIf, r_v, l_v;
                    swap OrIfV, r_t, l_t;
                    key_base OrKeyV, l_q, r_q;
                );

                // Memoize and return
                self.best_v.borrow_mut().insert(hashkey, ret.clone());
                ret
            },
            CompiledNodeContent::Thresh(k, ref subs) => {
                let num_cost = script::Builder::new().push_int(k as i64).into_script().len();
                let avg_cost = k as f64 / subs.len() as f64;

                let e = subs[0].best_e(p_sat * avg_cost, p_sat * (1.0 - avg_cost));
                let mut pk_cost = 1 + num_cost + e.pk_cost;
                let mut sat_cost = e.sat_cost;
                let mut dissat_cost = e.dissat_cost;
                let mut sub_asts = Vec::with_capacity(subs.len());

                sub_asts.push(e.ast);
                for sub in &subs[1..] {
                    let w = sub.best_w(p_sat * avg_cost, p_sat * (1.0 - avg_cost));
                    pk_cost += w.pk_cost + 1;
                    sat_cost += w.sat_cost;
                    dissat_cost += w.dissat_cost;
                    sub_asts.push(w.ast);
                }

                // Don't bother memoizing because it's always the same
                Cost {
                    ast: AstElem::ThreshV(k, sub_asts),
                    pk_cost: pk_cost,
                    sat_cost: sat_cost * avg_cost + dissat_cost * (1.0 - avg_cost),
                    dissat_cost: 0.0,
                }
            }
        }
    }

    /// Compute or lookup the best compilation of this node as a T
    pub fn best_t(&self, p_sat: f64, p_dissat: f64) -> Cost<P> {
        debug_assert_eq!(p_dissat, 0.0);
        let hashkey = (p_sat.to_bits(), p_dissat.to_bits());
        if let Some(cost) = self.best_t.borrow().get(&hashkey) {
            return cost.clone();
        }

        match self.content {
            // For most terminals, and thresholds, we just pass though to E
            CompiledNodeContent::Pk(..) | CompiledNodeContent::Multi(..) | CompiledNodeContent::Thresh(..) => {
                let mut ret = self.best_e(p_sat, 0.0);
                ret.dissat_cost = 0.0;
                ret
            },
            CompiledNodeContent::Time(n) => {
                Cost::from_terminal(AstElem::TimeT(n))
            },
            CompiledNodeContent::Hash(h) => {
                Cost::from_terminal(AstElem::HashT(h))
            },
            // AND and OR are slightly more involved, but not much
            CompiledNodeContent::And(ref left, ref right) => {
                let l_v = left.best_v(p_sat, 0.0);
                let r_v = right.best_v(p_sat, 0.0);
                let l_t = left.best_t(p_sat, 0.0);
                let r_t = right.best_t(p_sat, 0.0);

                let ret = min_cost_of!(
                    p_sat, 0.0, 0.0, 0.0;
                    base AndCat, l_v, r_t;
                    swap AndCat, r_v, l_t;
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

                let ret = min_cost_of!(
                    p_sat, 0.0, lweight, rweight;
                    base OrBool, l_e_par.clone(), r_w_par;
                    base OrCasc, l_e_par.clone(), r_t.clone();
                    base OrIf, l_t.clone(), r_t.clone();
                    swap OrBool, r_e_par.clone(), l_w_par;
                    swap OrCasc, r_e_par.clone(), l_t.clone();
                    swap OrIf, r_t, l_t;
                    true_base OrCont, l_e_par, r_v.clone();
                    true_base OrIf, l_v.clone(), r_v.clone();
                    true_swap OrCont, r_e_par, l_v.clone();
                    true_swap OrIf, r_v, l_v;
                    key_base OrKey, l_q, r_q;
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
            format!("{}", descriptor),
            "or_key(pk_q(),and_cat(pk_v(),pk_q()))"
        );

        let policy = Policy::<String>::from_str(
            "and(and(and(aor(thres(2,pk(),pk(),thres(2,aor(pk(),pk()),time(100),or(and(pk(),time(200)),and(pk(),hash(66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925))),pk())),pk()),hash(66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925)),aor(pk(),time(300))),aor(time(400),pk()))"
        ).expect("parsing");
        let descriptor = policy.compile();
        assert_eq!(
            format!("{}", descriptor),
            "and_cat(or_cont(pk(),time_v(400)),and_cat(or_cont(pk(),time_v(300)),and_cat(or_cont(thres(2,pk(),pk_w(),wrap(thres(2,or_bool(pk(),pk_w()),time_w(100),wrap(unlikely(true(or_key_v(and_cat(hash_v(66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925),pk_q()),and_cat(time_v(200),pk_q()))))),pk_w()))),pk_v()),hash_t(66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925))))"
// It appears that the following (which was in the unit tests before the restructuring to a unified `AstElem` structure) is equivalent in cost, and it's not a bug that the unit test changed.
//            "and_cat(and_cat(and_cat(or_cont(thres(2,pk(),pk_w(),wrap(thres(2,or_bool(pk(),pk_w()),time_w(100),wrap(unlikely(true(or_key_v(and_cat(time_v(200),pk_q()),and_cat(hash_v(66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925),pk_q()))))),pk_w()))),pk_v()),hash_v(66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925)),or_cont(pk(),time_v(300))),or_casc(pk(),time_t(400)))"
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

