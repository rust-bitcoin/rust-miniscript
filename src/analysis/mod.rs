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

use std::fmt;
use std::sync::atomic::{self, AtomicUsize, ATOMIC_USIZE_INIT};

use bitcoin::util::hash::Sha256dHash; // TODO needs to be sha256, not sha256d
// TODO use QQ instead of Field31
use groebner::{self, Field31, Monomial, Polynomial, groebner_basis};

#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq)]
pub enum Variable<P: Clone + Ord + fmt::Display> {
    Unique(usize),
    Key(P),
    Hash(Sha256dHash),
}

impl<P: Clone + Ord + fmt::Display> groebner::Variable for Variable<P> {
    fn is_elimination_var(&self) -> bool {
        if let Variable::Unique(_) = *self {
            true
        } else {
            false
        }
    }
}

impl<P: Clone + Ord + fmt::Display> fmt::Display for Variable<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Variable::Key(ref p) => write!(f, "key_{}", p),
            Variable::Hash(ref h) => write!(f, "hash_{}", h),
            Variable::Unique(n) => write!(f, "x_{}", n),
        }
    }
}

impl<P: Clone + Ord + fmt::Display> Variable<P> {
    pub fn unique() -> Variable<P> {
        static COUNT: AtomicUsize = ATOMIC_USIZE_INIT;
        let inner = COUNT.fetch_add(1, atomic::Ordering::SeqCst);
        Variable::Unique(inner)
    }
}

pub struct Ideal<P: Clone + Ord + fmt::Display> {
    inner: Vec<Polynomial<Variable<P>, Field31>>,
    output: Variable<P>,
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub struct EliminatedIdeal<P: Clone + Ord + fmt::Display> {
    inner: Vec<Polynomial<Variable<P>, Field31>>,
}

impl<P: Clone + Ord + fmt::Display> Ideal<P> {
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
        let output = Variable::unique();
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
        let output = Variable::unique();
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

impl<P: Clone + Ord + fmt::Display> Ideal<P> {
    pub fn threshold(k: usize, subs: Vec<Ideal<P>>) -> Ideal<P> {
        let mut sum_monomials: Vec<Monomial<Variable<P>, Field31>> = subs
            .iter()
            .map(|s| Monomial::new(Field31(1), vec![(s.output.clone(), 1)]))
            .collect();

        let mut inner = Vec::with_capacity(3 + sum_monomials.len());

        // Sum
        let sum_var = Variable::unique();
        sum_monomials.push(Monomial::new(-Field31(1), vec![(sum_var.clone(), 1)]));
        inner.push(Polynomial::new(sum_monomials));
        // Allowable sum values
        let sum_adaptor = Variable::unique();
        let mut sum_restrict = Polynomial::new(vec![Monomial::new(Field31(1), vec![])]);
        for i in k..subs.len() + 1 {
            let term = Polynomial::new(vec![
                Monomial::new(Field31(1), vec![(sum_var.clone(), 1)]),
                Monomial::new(-Field31(i as u32), vec![]),
            ]);
            sum_restrict = &sum_restrict * &term;
        }
        sum_restrict += &Monomial::new(-Field31(1), vec![(sum_adaptor.clone(), 1)]);
        inner.push(sum_restrict);
        // The above function will evaluate to 0 for allowable sums, and the negatives of
        // various permutation numbers for non-allowable sums. Map 0 to 1 and the other
        // possibilities to 0.
        let output = Variable::unique();
        let mut kfact = Field31(1);
        let mut kfact_prod = Field31(1);
        for i in 0..k as u32 {
            kfact *= Field31(i + 1);
        }
        let mut output_restrict = Polynomial::new(vec![Monomial::new(Field31(1), vec![])]);
        for i in 0..subs.len() - k + 1 {
            kfact_prod *= kfact;

            let term = Polynomial::new(vec![
                Monomial::new(Field31(1), vec![(sum_adaptor.clone(), 1)]),
                Monomial::new(kfact, vec![]),
            ]);
            output_restrict = &output_restrict * &term;

            kfact *= Field31((k + i + 1) as u32);
            kfact /= Field31((i + 1) as u32);
        }
        output_restrict *= groebner::Field::invert(kfact_prod);
        output_restrict += &Monomial::new(-Field31(1), vec![(output.clone(), 1)]);
        inner.push(output_restrict);

        for sub in subs {
            inner.extend(sub.inner);
        }

        Ideal {
            inner: inner,
            output: output,
        }
    }

    pub fn groebner_eliminate(mut self) -> EliminatedIdeal<P> {
        // Force output to be 1
        self.inner.push(Polynomial::new(vec![
            Monomial::new(Field31(1), vec![(self.output, 1)]),
            Monomial::new(-Field31(1), vec![]),
        ]));

        // Compute basis
        let mut inner = groebner_basis(self.inner);
        inner.retain(|poly| !poly.has_elimination_var());
        EliminatedIdeal {
            inner: inner,
        }
    }
}

impl<P: Clone + Ord + fmt::Display> Ideal<P> {
    pub fn print_ideal(&self) {
        println!("Len: {}; output: {}", self.inner.len(), self.output);
        println!("I = Ideal([");
        for elem in &self.inner {
            println!("    {},", elem);
        }
        println!("])");
    }
}

impl<P: Clone + Ord + fmt::Display> EliminatedIdeal<P> {
    pub fn print_ideal(&self) {
        println!("Len: {};", self.inner.len());

        println!("I = Ideal([");
        for elem in &self.inner {
            println!("    {},", elem);
        }
        println!("])");
    }
}

