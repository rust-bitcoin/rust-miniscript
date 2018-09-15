// Script Policy Language
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

//! # Analysis
//!
//! Script policy analysis algorithms
//!

use std::{cmp, fmt};
use std::sync::atomic::{self, AtomicUsize, ATOMIC_USIZE_INIT};

use bitcoin::util::hash::Sha256dHash; // TODO needs to be sha256, not sha256d
// TODO use QQ instead of Field31
use groebner::{self, Field31, Monomial, Polynomial, groebner_basis};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Variable<P: Clone + Ord + fmt::Display> {
    Unique(usize, bool),
    Key(P),
    Hash(Sha256dHash),
}

impl<P: Clone + Ord + fmt::Display> PartialOrd for Variable<P> {
    fn partial_cmp(&self, other: &Variable<P>) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<P: Clone + Ord + fmt::Display> Ord for Variable<P> {
    fn cmp(&self, other: &Variable<P>) -> cmp::Ordering {
        match (self, other) {
            // Ordering is reversed for uniques
            (&Variable::Unique(ref n1, _), Variable::Unique(ref n2, _)) => n1.cmp(n2),
            // Everything else is as expected
            (&Variable::Key(ref p1), &Variable::Key(ref p2)) => p1.cmp(p2),
            (&Variable::Hash(ref h1), &Variable::Hash(ref h2)) => h1.cmp(h2),
            (&Variable::Unique(..), _) => cmp::Ordering::Greater,
            (_, &Variable::Unique(..)) => cmp::Ordering::Less,
            (&Variable::Key(..), _) => cmp::Ordering::Greater,
            (_, &Variable::Key(..)) => cmp::Ordering::Less,
        }
    }
}

impl<P: Clone + Ord + fmt::Display + fmt::Debug> groebner::Variable for Variable<P> {
    fn is_boolean_var(&self) -> bool {
        match *self {
            Variable::Key(..) => true,
            Variable::Hash(..) => true,
            Variable::Unique(_, b) => b,
        }
    }
}

impl<P: Clone + Ord + fmt::Display> fmt::Display for Variable<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Variable::Key(ref p) => write!(f, "key_{}", p),
            Variable::Hash(ref h) => write!(f, "hash_{}", h),
            Variable::Unique(n, false) => write!(f, "x_{}", n),
            Variable::Unique(n, true) => write!(f, "b_{}", n),
        }
    }
}

impl<P: Clone + Ord + fmt::Display> Variable<P> {
    pub fn unique(boolean: bool) -> Variable<P> {
        static COUNT: AtomicUsize = ATOMIC_USIZE_INIT;
        let inner = COUNT.fetch_add(1, atomic::Ordering::SeqCst);
        // Add one to 1-index things to make the display a bit nicer for mathematicians
        Variable::Unique(inner + 1, boolean)
    }
}

pub struct Ideal<P: Clone + Ord + fmt::Display + fmt::Debug> {
    inner: Vec<Polynomial<Variable<P>, Field31>>,
    output: Variable<P>,
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub struct EliminatedIdeal<P: Clone + Ord + fmt::Display + fmt::Debug> {
    inner: Vec<Polynomial<Variable<P>, Field31>>,
    output: Variable<P>,
}

impl<P: Clone + Ord + fmt::Display + fmt::Debug> Ideal<P> {
    pub fn from_key(key: &P) -> Ideal<P> {
        let var = Variable::Key(key.clone());
        Ideal {
            inner: vec![
                Polynomial::new(vec![
                    Monomial::new(Field31(1), vec![(var.clone(), 2)]),
                    Monomial::new(-Field31(1), vec![(var.clone(), 1)]),
                ])
            ],
            output: var,
        }
    }

    pub fn from_hash(hash: Sha256dHash) -> Ideal<P> {
        let var = Variable::Hash(hash);
        Ideal {
            inner: vec![
                Polynomial::new(vec![
                    Monomial::new(Field31(1), vec![(var.clone(), 2)]),
                    Monomial::new(-Field31(1), vec![(var.clone(), 1)]),
                ])
            ],
            output: var,
        }
    }

    pub fn and(left: Ideal<P>, right: Ideal<P>) -> Ideal<P> {
        let output = Variable::unique(true);
        let mut inner = Vec::with_capacity(1 + left.inner.len() + right.inner.len());
        inner.extend(left.inner);
        inner.extend(right.inner);
        inner.push(Polynomial::new(vec![
            Monomial::new(Field31(1), vec![(output.clone(), 1)]),
            Monomial::new(-Field31(1), vec![(left.output.clone(), 1), (right.output.clone(), 1)]),
        ]));
        Ideal {
            inner: inner,
            output: output,
        }
    }

    pub fn or(left: Ideal<P>, right: Ideal<P>) -> Ideal<P> {
        let output = Variable::unique(true);
        let mut inner = Vec::with_capacity(1 + left.inner.len() + right.inner.len());
        inner.extend(left.inner);
        inner.extend(right.inner);
        inner.push(Polynomial::new(vec![
            Monomial::new(Field31(1), vec![(output.clone(), 1)]),
            Monomial::new(-Field31(1), vec![(left.output.clone(), 1)]),
            Monomial::new(-Field31(1), vec![(right.output.clone(), 1)]),
            Monomial::new(Field31(1), vec![(left.output.clone(), 1), (right.output.clone(), 1)]),
        ]));
        Ideal {
            inner: inner,
            output: output,
        }
    }
}

impl<P: Clone + Ord + fmt::Display + fmt::Debug> Ideal<P> {
    pub fn threshold(k: usize, subs: Vec<Ideal<P>>) -> Ideal<P> {
        debug_assert!(k < subs.len());  // TODO we can do a n-of-n more efficiently
        let mut sum_monomials: Vec<Monomial<Variable<P>, Field31>> = subs
            .iter()
            .map(|s| Monomial::new(Field31(1), vec![(s.output.clone(), 1)]))
            .collect();

        let mut inner = Vec::with_capacity(1 + 3 * subs.len());

        // Sum
        assert!(!subs.is_empty());
        let sum_var;
        if subs.len() == 1 {
            sum_var = subs[0].output.clone();
        } else {
            let mut new = Variable::unique(false);
            inner.push(Polynomial::new(vec![
                Monomial::new(Field31(1), vec![(subs[0].output.clone(), 1)]),
                Monomial::new(Field31(1), vec![(subs[1].output.clone(), 1)]),
                Monomial::new(-Field31(1), vec![(new.clone(), 1)]),
            ]));
            for i in 2..subs.len() {
                let old_new = new.clone();
                new = Variable::unique(false);
                inner.push(Polynomial::new(vec![
                    Monomial::new(Field31(1), vec![(old_new, 1)]),
                    Monomial::new(Field31(1), vec![(subs[i].output.clone(), 1)]),
                    Monomial::new(-Field31(1), vec![(new.clone(), 1)]),
                ]));
            }
            sum_var = new;
        }
        // For i in `1` through `k-1`, define `alpha_i = alpha_{i-1}*(t - i)`
        // with `alpha_0 = sum_var`.
        let mut last_var: Option<Variable<P>> = None;
        println!("tpoly {} {} is {:?}", k, subs.len(),
        groebner::threshold_polynomial::<Field31>(k, subs.len()));
        for coeff in groebner::threshold_polynomial::<Field31>(k, subs.len()).0.into_iter().rev() {
            let new_var = Variable::unique(false);
            if let Some(last) = last_var {
                inner.push(Polynomial::new(vec![
                    Monomial::new(Field31(1), vec![
                        (last.clone(), 1), (sum_var.clone(), 1),
                    ]),
                    Monomial::new(coeff, vec![]),
                    Monomial::new(-Field31(1), vec![(new_var.clone(), 1)]),
                ]));
            } else {
                inner.push(Polynomial::new(vec![
                    Monomial::new(coeff, vec![]),
                    Monomial::new(-Field31(1), vec![(new_var.clone(), 1)]),
                ]));
            }
            last_var = Some(new_var);
        }

        // Add sub rules
        for sub in subs {
            inner.extend(sub.inner);
        }

        Ideal {
            inner: inner,
            output: last_var.unwrap(),
        }
    }

    pub fn add_success_requirement(&mut self) {
        self.inner.sort();
        self.inner.dedup();
        /*
        // Force output to be 1
        self.inner.push(Polynomial::new(vec![
            Monomial::new(Field31(1), vec![(self.output.clone(), 1)]),
            Monomial::new(-Field31(1), vec![]),
        ]));
        */
    }

    pub fn groebner_eliminate(self) -> EliminatedIdeal<P> {
        // Compute basis
        let mut inner = groebner_basis(self.inner);
        inner.retain(|poly| !poly.has_elimination_var());
        EliminatedIdeal {
            inner: inner,
            output: self.output,
        }
    }
}

impl<P: Clone + Ord + fmt::Display + fmt::Debug> Ideal<P> {
    pub fn print_ideal(&self) {
        println!("Len: {}; output: {}", self.inner.len(), self.output);
        println!("I = Ideal([");
        for elem in &self.inner {
            println!("    {},", elem);
        }
        println!("])");
    }
}

impl<P: Clone + Ord + fmt::Display + fmt::Debug> EliminatedIdeal<P> {
    pub fn output(&self) -> &Variable<P> {
        &self.output
    }

    pub fn reduce(&self, p: &mut Polynomial<Variable<P>, Field31>) {
        loop {
            let mut reduced = false;
            for elem in &self.inner {
                reduced |= p.reduce(elem);
            }
            if !reduced {
                break;
            }
        }
    }

    pub fn print_ideal(&self) {
        println!("Len: {};", self.inner.len());

        println!("I = Ideal([");
        for elem in &self.inner {
            println!("    {},", elem);
        }
        println!("])");
    }
}

