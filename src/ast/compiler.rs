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

use secp256k1;

use bitcoin::blockdata::script;
use bitcoin::util::hash::Hash160;

use Descriptor;
use ast::astelem::{AstElem, E, W, F, V, T};

pub trait Compileable: AstElem + Sized {
    fn from_descriptor(desc: &Descriptor<secp256k1::PublicKey>, p_sat: f64, p_dissat: f64) -> Cost<Self>;
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
            pk_cost: fcost.pk_cost + 6,
            sat_cost: fcost.sat_cost + 1.0,
            dissat_cost: 2.0,
        }
    }

    fn unlikely(fcost: Cost<F>) -> Cost<E> {
        Cost {
            ast: E::Unlikely(fcost.ast),
            pk_cost: fcost.pk_cost + 6,
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
            E::CheckSig(..) | E::CheckSigHash(..) | E::CheckSigHashF(..) | E::CheckMultiSig(..) |
            E::CheckMultiSigF(..) | E::Csv(..) | E::HashEqual(..) |
            E::Threshold(..) | E::Likely(..) | E::Unlikely(..) |
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
                dissat_cost: right.dissat_cost,
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
                pk_cost: left.pk_cost + right.pk_cost + 5,
                sat_cost: (left.sat_cost + 2.0) * lweight + (right.sat_cost + 1.0) * rweight,
                dissat_cost: left.dissat_cost + 2.0,
            },
            E::SwitchOrRight(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 5,
                sat_cost: (left.sat_cost + 1.0) * lweight + (right.sat_cost + 2.0) * rweight,
                dissat_cost: left.dissat_cost + 1.0,
            },
        }
    }
}

impl Cost<W> {
    fn wrapped(c: Cost<E>) -> Cost<W> {
        let (ast, pk_bump) = match c.ast {
            E::CheckSig(key) => (W::CheckSig(key), 1),
            E::HashEqual(hash) => (W::HashEqual(hash), 1),
            E::Csv(n) => (W::Csv(n), 1),
            x => (W::CastE(Box::new(x)), 2),
        };
        Cost {
            ast: ast,
            pk_cost: c.pk_cost + pk_bump,
            sat_cost: c.sat_cost,
            dissat_cost: c.dissat_cost,
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
            F::CheckSig(..) | F::CheckMultiSig(..) | F::CheckSigHash(..) | F::Csv(..) |
            F::HashEqual(..) | F::Threshold(..) => unreachable!(),
            F::And(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost,
                sat_cost: left.sat_cost + right.sat_cost,
                dissat_cost: 0.0,
            },
            F::ParallelOr(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 3,
                sat_cost: (left.sat_cost + right.dissat_cost) * lweight + (right.sat_cost + left.dissat_cost) * rweight,
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
                pk_cost: left.pk_cost + right.pk_cost + 5,
                sat_cost: (left.sat_cost + 2.0) * lweight + (right.sat_cost + 1.0) * rweight,
                dissat_cost: 0.0,
            },
            F::SwitchOrV(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 6,
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
            V::CheckSig(..) | V::CheckMultiSig(..) | V::CheckSigHash(..) | V::Csv(..) |
            V::HashEqual(..) | V::Threshold(..) => unreachable!(),
            V::And(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost,
                sat_cost: left.sat_cost + right.sat_cost,
                dissat_cost: 0.0,
            },
            V::ParallelOr(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 2,
                sat_cost: (left.sat_cost + right.dissat_cost) * lweight + (right.sat_cost + left.dissat_cost) * rweight,
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
                pk_cost: left.pk_cost + right.pk_cost + 5,
                sat_cost: (left.sat_cost + 2.0) * lweight + (right.sat_cost + 1.0) * rweight,
                dissat_cost: 0.0,
            },
            V::SwitchOrT(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 6,
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
            T::Csv(..) | T::HashEqual(..) | T::CastE(..) => unreachable!(),
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
                pk_cost: left.pk_cost + right.pk_cost + 2,
                sat_cost: left.sat_cost * lweight + (right.sat_cost + left.dissat_cost) * rweight,
                dissat_cost: 0.0,
            },
            T::SwitchOr(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 5,
                sat_cost: (left.sat_cost + 2.0) * lweight + (right.sat_cost + 1.0) * rweight,
                dissat_cost: 0.0,
            },
            T::SwitchOrV(..) => Cost {
                ast: new_ast,
                pk_cost: left.pk_cost + right.pk_cost + 6,
                sat_cost: (left.sat_cost + 2.0) * lweight + (right.sat_cost + 1.0) * rweight,
                dissat_cost: 0.0,
            },
        }
    }
}

fn min_cost<T: AstElem>(one: Cost<T>, two: Cost<T>, p_sat: f64, p_dissat: f64) -> Cost<T> {
    let weight_one = one.pk_cost as f64 + p_sat * one.sat_cost + p_dissat * one.dissat_cost;
    let weight_two = two.pk_cost as f64 + p_sat * two.sat_cost + p_dissat * two.dissat_cost;

    if weight_one <= weight_two {
        one
    } else {
        two
    }
}

fn fold_cost_vec<T: AstElem>(mut v: Vec<Cost<T>>, p_sat: f64, p_dissat: f64) -> Cost<T> {
    let last = v.pop().unwrap();
    v.into_iter().fold(last, |acc, n| min_cost(acc, n, p_sat, p_dissat))
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

impl Compileable for E {
    fn from_descriptor(desc: &Descriptor<secp256k1::PublicKey>, p_sat: f64, p_dissat: f64) -> Cost<E> {
        match *desc {
            Descriptor::Key(ref key) => {
                Cost {
                    ast: E::CheckSig(key.clone()),
                    pk_cost: 35,
                    sat_cost: 72.0,
                    dissat_cost: 1.0,
                }
            },
            Descriptor::KeyHash(ref key) => {
                let hash = Hash160::from_data(&key.serialize()[..]);
                let standard = Cost {
                    ast: E::CheckSigHash(hash),
                    pk_cost: 25,
                    sat_cost: 34.0 + 72.0,
                    dissat_cost: 34.0 + 1.0,
                };
                let cheap_dissat = Cost {
                    ast: E::CheckSigHashF(hash),
                    pk_cost: 29,
                    sat_cost: 34.0 + 72.0,
                    dissat_cost: 1.0,
                };
                min_cost(standard, cheap_dissat, p_sat, p_dissat)
            }
            Descriptor::Multi(k, ref keys) => {
                let num_cost = match(k > 16, keys.len() > 16) {
                    (true, true) => 4,
                    (false, true) => 3,
                    (true, false) => 3,
                    (false, false) => 2,
                };
                let standard = Cost {
                    ast: E::CheckMultiSig(k, keys.clone()),
                    pk_cost: num_cost + 34 * keys.len() + 1,
                    sat_cost: 1.0 + 72.0*k as f64,
                    dissat_cost: 1.0 + k as f64,
                };
                let cheap_dissat = Cost {
                    ast: E::CheckMultiSigF(k, keys.clone()),
                    pk_cost: num_cost + 34 * keys.len() + 5,
                    sat_cost: 1.0 + 72.0*k as f64,
                    dissat_cost: 1.0,
                };
                min_cost(standard, cheap_dissat, p_sat, p_dissat)
            }
            Descriptor::Time(n) => {
                let num_cost = script::Builder::new().push_int(n as i64).into_script().len();
                Cost {
                    ast: E::Csv(n),
                    pk_cost: 7 + num_cost,
                    sat_cost: 2.0,
                    dissat_cost: 1.0,
                }
            }
            Descriptor::Hash(hash) => {
                Cost {
                    ast: E::HashEqual(hash),
                    pk_cost: 43,
                    sat_cost: 33.0,
                    dissat_cost: 1.0,
                }
            }
            Descriptor::Threshold(k, ref exprs) => {
                let num_cost = script::Builder::new().push_int(k as i64).into_script().len();
                if exprs.is_empty() {
                    panic!("Cannot have empty threshold in a descriptor");
                }

                let avg_cost = k as f64 / exprs.len() as f64;

                let e = E::from_descriptor(&exprs[0], p_sat * avg_cost, p_dissat + p_sat * (1.0 - avg_cost));
                let mut pk_cost = 1 + num_cost + e.pk_cost;
                let mut sat_cost = e.sat_cost;
                let mut dissat_cost = e.dissat_cost;
                let mut ws = vec![];

                for expr in &exprs[1..] {
                    let e = E::from_descriptor(expr, p_sat * avg_cost, p_dissat + p_sat * (1.0 - avg_cost));
                    let w = Cost::wrapped(e);
                    pk_cost += w.pk_cost + 1;
                    sat_cost += w.sat_cost;
                    dissat_cost += w.dissat_cost;
                    ws.push(w.ast);
                }

                let noncond = Cost {
                    ast: E::Threshold(k, Box::new(e.ast.clone()), ws.clone()),
                    pk_cost: pk_cost,
                    sat_cost: sat_cost * avg_cost + dissat_cost * (1.0 - avg_cost),  // TODO is simply averaging here the right thing to do?
                    dissat_cost: dissat_cost,
                };
                let f = Cost {
                    ast: F::Threshold(k, Box::new(e.ast), ws),
                    pk_cost: noncond.pk_cost,
                    sat_cost: noncond.sat_cost,
                    dissat_cost: noncond.dissat_cost,
                };
                let cond1 = Cost::likely(f.clone());
                let cond2 = Cost::unlikely(f);
                let cond = min_cost(cond1, cond2, p_sat, p_dissat);

                min_cost(cond, noncond, p_sat, p_dissat)
            }
            Descriptor::And(ref left, ref right) => {
                let l_e = E::from_descriptor(left, p_sat, p_dissat);
                let r_e = E::from_descriptor(right, p_sat, p_dissat);

                let l_f = F::from_descriptor(left, p_sat, 0.0);
                let r_f = F::from_descriptor(right, p_sat, 0.0);
                let l_v = V::from_descriptor(left, p_sat, 0.0);
                let r_v = V::from_descriptor(right, p_sat, 0.0);

                rules!(
                    E, p_sat, p_dissat, 0.0, 0.0;
                    E::ParallelAnd => l_e.clone(), Cost::wrapped(r_e.clone())
                                   => r_e.clone(), Cost::wrapped(l_e.clone());
                    E::CascadeAnd => l_e, r_f.clone()
                                  => r_e, l_f.clone();
                    -> F::And => l_v, r_f
                              => r_v, l_f;
                )
            }
            Descriptor::Or(ref left, ref right) | Descriptor::AsymmetricOr(ref left, ref right) => {
                let (lweight, rweight) = if let Descriptor::Or(..) = *desc {
                    (0.5, 0.5)
                } else {
                    (127.0 / 128.0, 1.0 / 128.0)
                };

                let l_e_par = E::from_descriptor(left, p_sat * lweight, p_dissat + p_sat * rweight);
                let r_e_par = E::from_descriptor(right, p_sat * rweight, p_dissat + p_sat * lweight);
                let l_e_cas = E::from_descriptor(left, p_sat * lweight, p_dissat);
                let r_e_cas = E::from_descriptor(right, p_sat * rweight, p_dissat);

                let l_e_cond_par = E::from_descriptor(left, p_sat * lweight, p_sat * rweight);
                let r_e_cond_par = E::from_descriptor(right, p_sat * rweight, p_sat * lweight);
                let l_v = V::from_descriptor(left, p_sat * lweight, 0.0);
                let r_v = V::from_descriptor(right, p_sat * rweight, 0.0);
                let l_f = F::from_descriptor(left, p_sat * lweight, 0.0);
                let r_f = F::from_descriptor(right, p_sat * rweight, 0.0);

                rules!(
                    E, p_sat, p_dissat, lweight, rweight;
                    E::ParallelOr => l_e_par.clone(), Cost::wrapped(r_e_par.clone())
                                  => r_e_par.clone(), Cost::wrapped(l_e_par.clone());
                    E::CascadeOr => l_e_par.clone(), r_e_cas
                                 => r_e_par.clone(), l_e_cas;
                    E::SwitchOrLeft => l_e_par.clone(), r_f.clone()
                                    => r_e_par.clone(), l_f.clone();
                    E::SwitchOrRight => l_e_par.clone(), r_f.clone()
                                     => r_e_par.clone(), l_f.clone();
                    -> F::ParallelOr => l_e_cond_par.clone(), Cost::wrapped(r_e_cond_par.clone())
                                     => r_e_cond_par.clone(), Cost::wrapped(l_e_cond_par.clone());
                    -> F::CascadeOr => l_e_cond_par, r_v.clone()
                                    => r_e_cond_par, l_v.clone();
                    -> F::SwitchOr => l_f.clone(), r_f.clone()
                                   => r_f, l_f;
                    -> F::SwitchOrV => l_v.clone(), r_v.clone()
                                    => r_v, l_v;
                )
            }
            Descriptor::Wpkh(_) | Descriptor::Sh(_) | Descriptor::Wsh(_) => {
                // handled at at the ParseTree::from_descriptor layer
                unreachable!()
            }
        }
    }

}

impl Compileable for F {
    fn from_descriptor(desc: &Descriptor<secp256k1::PublicKey>, p_sat: f64, p_dissat: f64) -> Cost<F> {
        debug_assert_eq!(p_dissat, 0.0);

        match *desc {
            Descriptor::Key(ref key) => {
                Cost {
                    ast: F::CheckSig(key.clone()),
                    pk_cost: 36,
                    sat_cost: 72.0,
                    dissat_cost: 0.0,
                }
            }
            Descriptor::KeyHash(ref key) => {
                let hash = Hash160::from_data(&key.serialize()[..]);
                Cost {
                    ast: F::CheckSigHash(hash),
                    pk_cost: 26,
                    sat_cost: 34.0 + 72.0,
                    dissat_cost: 0.0,
                }
            }
            Descriptor::Multi(k, ref keys) => {
                let num_cost = match(k > 16, keys.len() > 16) {
                    (true, true) => 4,
                    (false, true) => 3,
                    (true, false) => 3,
                    (false, false) => 2,
                };
                Cost {
                    ast: F::CheckMultiSig(k, keys.clone()),
                    pk_cost: num_cost + 34 * keys.len() + 2,
                    sat_cost: 1.0 + 72.0*k as f64,
                    dissat_cost: 0.0,
                }
            }
            Descriptor::Threshold(k, ref exprs) => {
                let num_cost = script::Builder::new().push_int(k as i64).into_script().len();
                if exprs.is_empty() {
                    panic!("Cannot have empty threshold in a descriptor");
                }

                let avg_cost = k as f64 / exprs.len() as f64;

                let e = E::from_descriptor(&exprs[0], p_sat * avg_cost, p_sat * (1.0 - avg_cost));
                let mut pk_cost = 2 + num_cost + e.pk_cost;
                let mut sat_cost = e.sat_cost;
                let mut dissat_cost = e.dissat_cost;
                let mut ws = vec![];

                for expr in &exprs[1..] {
                    let e = E::from_descriptor(expr, p_sat * avg_cost, p_sat * (1.0 - avg_cost));
                    let w = Cost::wrapped(e);
                    pk_cost += w.pk_cost + 1;
                    sat_cost += w.sat_cost;
                    dissat_cost += w.dissat_cost;
                    ws.push(w.ast);
                }

                Cost {
                    ast: F::Threshold(k, Box::new(e.ast), ws),
                    pk_cost: pk_cost,
                    sat_cost: sat_cost * avg_cost + dissat_cost * (1.0 - avg_cost), // TODO is simply averaging here the right thing to do?
                    dissat_cost: 0.0,
                }
            }
            Descriptor::Time(n) => {
                let num_cost = script::Builder::new().push_int(n as i64).into_script().len();
                Cost {
                    ast: F::Csv(n),
                    pk_cost: 2 + num_cost,
                    sat_cost: 0.0,
                    dissat_cost: 0.0,
                }
            }
            Descriptor::Hash(hash) => {
                Cost {
                    ast: F::HashEqual(hash),
                    pk_cost: 40,
                    sat_cost: 33.0,
                    dissat_cost: 0.0,
                }
            }
            Descriptor::And(ref left, ref right) => {
                let vl = V::from_descriptor(left, p_sat, 0.0);
                let vr = V::from_descriptor(right, p_sat, 0.0);
                let fl = F::from_descriptor(left, p_sat, 0.0);
                let fr = F::from_descriptor(right, p_sat, 0.0);

                rules!(
                    F, p_sat, 0.0, 0.0, 0.0;
                    F::And => vl, fr
                           => vr, fl;
                )
            }
            Descriptor::Or(ref left, ref right) | Descriptor::AsymmetricOr(ref left, ref right) => {
                let (lweight, rweight) = if let Descriptor::Or(..) = *desc {
                    (0.5, 0.5)
                } else {
                    (127.0 / 128.0, 1.0 / 128.0)
                };

                let l_e_par = E::from_descriptor(left, p_sat * lweight, p_sat * rweight);
                let r_e_par = E::from_descriptor(right, p_sat * rweight, p_sat * lweight);

                let l_f = F::from_descriptor(left, p_sat * lweight, 0.0);
                let r_f = F::from_descriptor(right, p_sat * rweight, 0.0);
                let l_v = V::from_descriptor(left, p_sat * lweight, 0.0);
                let r_v = V::from_descriptor(right, p_sat * rweight, 0.0);

                rules!(
                    F, p_sat, 0.0, lweight, rweight;
                    F::ParallelOr => l_e_par.clone(), Cost::wrapped(r_e_par.clone())
                                  => r_e_par.clone(), Cost::wrapped(l_e_par.clone());
                    F::CascadeOr => l_e_par, r_v.clone()
                                 => r_e_par, l_v.clone();
                    F::SwitchOr => l_f.clone(), r_f.clone()
                                => r_f, l_f;
                    F::SwitchOrV => l_v.clone(), r_v.clone()
                                 => r_v, l_v;
                )
            }
            Descriptor::Wpkh(_) | Descriptor::Sh(_) | Descriptor::Wsh(_) => {
                // handled at at the ParseTree::from_descriptor layer
                unreachable!()
            }
        }
    }
}

impl Compileable for V {
    fn from_descriptor(desc: &Descriptor<secp256k1::PublicKey>, p_sat: f64, p_dissat: f64) -> Cost<V> {
        debug_assert_eq!(p_dissat, 0.0);

        match *desc {
            Descriptor::Key(ref key) => {
                Cost {
                    ast: V::CheckSig(key.clone()),
                    pk_cost: 35,
                    sat_cost: 72.0,
                    dissat_cost: 0.0,
                }
            }
            Descriptor::KeyHash(ref key) => {
                let hash = Hash160::from_data(&key.serialize()[..]);
                Cost {
                    ast: V::CheckSigHash(hash),
                    pk_cost: 25,
                    sat_cost: 34.0 + 72.0,
                    dissat_cost: 0.0,
                }
            }
            Descriptor::Multi(k, ref keys) => {
                let num_cost = match(k > 16, keys.len() > 16) {
                    (true, true) => 4,
                    (false, true) => 3,
                    (true, false) => 3,
                    (false, false) => 2,
                };
                Cost {
                    ast: V::CheckMultiSig(k, keys.clone()),
                    pk_cost: num_cost + 34 * keys.len() + 1,
                    sat_cost: 1.0 + 72.0*k as f64,
                    dissat_cost: 0.0,
                }
            }
            Descriptor::Time(n) => {
                let num_cost = script::Builder::new().push_int(n as i64).into_script().len();
                Cost {
                    ast: V::Csv(n),
                    pk_cost: 2 + num_cost,
                    sat_cost: 0.0,
                    dissat_cost: 0.0,
                }
            }
            Descriptor::Hash(hash) => {
                Cost {
                    ast: V::HashEqual(hash),
                    pk_cost: 39,
                    sat_cost: 33.0,
                    dissat_cost: 0.0,
                }
            }
            Descriptor::Threshold(k, ref exprs) => {
                let num_cost = script::Builder::new().push_int(k as i64).into_script().len();
                if exprs.is_empty() {
                    panic!("Cannot have empty threshold in a descriptor");
                }

                let avg_cost = k as f64 / exprs.len() as f64;

                let e = E::from_descriptor(&exprs[0], p_sat * avg_cost, p_sat * (1.0 - avg_cost));
                let mut pk_cost = 1 + num_cost + e.pk_cost;
                let mut sat_cost = e.sat_cost;
                let mut dissat_cost = e.dissat_cost;
                let mut ws = vec![];

                for expr in &exprs[1..] {
                    let e = E::from_descriptor(expr, p_sat * avg_cost, p_sat * (1.0 - avg_cost));
                    let w = Cost::wrapped(e);
                    pk_cost += w.pk_cost + 1;
                    sat_cost += w.sat_cost;
                    dissat_cost += w.dissat_cost;
                    ws.push(w.ast);
                }

                Cost {
                    ast: V::Threshold(k, Box::new(e.ast), ws),
                    pk_cost: pk_cost,
                    sat_cost: sat_cost * avg_cost + dissat_cost * (1.0 - avg_cost),  // TODO is simply averaging here the right thing to do?
                    dissat_cost: dissat_cost,
                }
            }
            Descriptor::And(ref left, ref right) => {
                let l = V::from_descriptor(left, p_sat, 0.0);
                let r = V::from_descriptor(right, p_sat, 0.0);
                Cost {
                    pk_cost: l.pk_cost + r.pk_cost,
                    sat_cost: l.sat_cost + r.sat_cost,
                    dissat_cost: 0.0,
                    ast: V::And(Box::new(l.ast), Box::new(r.ast)),
                }
            }
            Descriptor::Or(ref left, ref right) | Descriptor::AsymmetricOr(ref left, ref right) => {
                let (lweight, rweight) = if let Descriptor::Or(..) = *desc {
                    (0.5, 0.5)
                } else {
                    (127.0 / 128.0, 1.0 / 128.0)
                };

                let l_e_par = E::from_descriptor(left, p_sat * lweight, p_sat * rweight);
                let r_e_par = E::from_descriptor(right, p_sat * rweight, p_sat * lweight);

                let l_t = T::from_descriptor(left, p_sat * lweight, 0.0);
                let r_t = T::from_descriptor(right, p_sat * rweight, 0.0);
                let l_v = V::from_descriptor(left, p_sat * lweight, 0.0);
                let r_v = V::from_descriptor(right, p_sat * rweight, 0.0);

                rules!(
                    V, p_sat, 0.0, lweight, rweight;
                    V::ParallelOr => l_e_par.clone(), Cost::wrapped(r_e_par.clone())
                                  => r_e_par.clone(), Cost::wrapped(l_e_par.clone());
                    V::CascadeOr => l_e_par, r_v.clone()
                                 => r_e_par, l_v.clone();
                    V::SwitchOr => l_v.clone(), r_v.clone()
                                => r_v, l_v;
                    V::SwitchOrT => l_t.clone(), r_t.clone()
                                 => r_t, l_t;
                )
            }
            Descriptor::Wpkh(_) | Descriptor::Sh(_) | Descriptor::Wsh(_) => {
                // handled at at the ParseTree::from_descriptor layer
                unreachable!()
            }
        }
    }
}

impl Compileable for T {
    fn from_descriptor(desc: &Descriptor<secp256k1::PublicKey>, p_sat: f64, p_dissat: f64) -> Cost<T> {
        debug_assert_eq!(p_dissat, 0.0);

        match *desc {
            Descriptor::Key(..) | Descriptor::KeyHash(..) | Descriptor::Multi(..) | Descriptor::Threshold(..) => {
                let e = E::from_descriptor(desc, p_sat, 0.0);
                Cost {
                    ast: T::CastE(e.ast),
                    pk_cost: e.pk_cost,
                    sat_cost: e.sat_cost,
                    dissat_cost: 0.0,
                }
            }
            Descriptor::Time(n) => {
                let num_cost = script::Builder::new().push_int(n as i64).into_script().len();
                Cost {
                    ast: T::Csv(n),
                    pk_cost: 1 + num_cost,
                    sat_cost: 0.0,
                    dissat_cost: 0.0,
                }
            }
            Descriptor::Hash(hash) => {
                Cost {
                    ast: T::HashEqual(hash),
                    pk_cost: 39,
                    sat_cost: 33.0,
                    dissat_cost: 0.0,
                }
            }
            Descriptor::And(ref left, ref right) => {
                let vl = V::from_descriptor(left, p_sat, 0.0);
                let vr = V::from_descriptor(right, p_sat, 0.0);
                let tl = T::from_descriptor(left, p_sat, 0.0);
                let tr = T::from_descriptor(right, p_sat, 0.0);

                rules!(
                    T, p_sat, 0.0, 0.0, 0.0;
                    T::And => vl, tr
                           => vr, tl;
                )
            }
            Descriptor::Or(ref left, ref right) | Descriptor::AsymmetricOr(ref left, ref right) => {
                let (lweight, rweight) = if let Descriptor::Or(..) = *desc {
                    (0.5, 0.5)
                } else {
                    (127.0 / 128.0, 1.0 / 128.0)
                };

                let l_e_par = E::from_descriptor(left, p_sat * lweight, p_sat * rweight);
                let r_e_par = E::from_descriptor(right, p_sat * rweight, p_sat * lweight);

                let l_t = T::from_descriptor(left, p_sat * lweight, 0.0);
                let r_t = T::from_descriptor(right, p_sat * rweight, 0.0);
                let l_v = V::from_descriptor(left, p_sat * lweight, 0.0);
                let r_v = V::from_descriptor(right, p_sat * rweight, 0.0);

                rules!(
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
                )
            }
            Descriptor::Wpkh(_) | Descriptor::Sh(_) | Descriptor::Wsh(_) => {
                // handled at at the ParseTree::from_descriptor layer
                unreachable!()
            }
        }
    }
}

#[cfg(all(test, feature = "unstable"))]
mod benches {
    use secp256k1;
    use std::str::FromStr;
    use test::{Bencher, black_box};

    use super::{ParseTree, Descriptor};

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

