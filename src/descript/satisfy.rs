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

//! # Satisfaction and Dissatisfaction
//!
//! Traits and implementations to support producing witnesses for scriptpubkeys
//! described by script ASTs.
//!

use std::{isize, mem};
use std::rc::Rc;

use bitcoin::blockdata::transaction::SigHashType;
use bitcoin::util::hash::Sha256dHash; // TODO needs to be sha256, not sha256d
use secp256k1;

use Error;
use descript::astelem;

/// Trait describing an AST element which can be satisfied, given maps from the
/// public data to corresponding witness data.
pub trait Satisfiable<P> {
    /// Attempt to produce a witness that satisfies the AST element
    fn satisfy<F, H>(&self, keyfn: Option<&F>, hashfn: Option<&H>, age: u32)
        -> Result<Vec<Vec<u8>>, Error>
        where F: Fn(&P) -> Option<(secp256k1::Signature, Option<SigHashType>)>,
              H: Fn(Sha256dHash) -> Option<[u8; 32]>;
}

/// Trait describing an AST element which can be dissatisfied (without failing the
/// whole script). This only applies to `E` and `W`, since the other AST elements
/// are expected to fail the script on error.
pub trait Dissatisfiable<P> {
    /// Produce a witness that dissatisfies the AST element
    fn dissatisfy(&self) -> Vec<Vec<u8>>;
}

impl<P: ToString> Satisfiable<P> for astelem::E<P> {
    fn satisfy<F, H>(&self, keyfn: Option<&F>, hashfn: Option<&H>, age: u32)
        -> Result<Vec<Vec<u8>>, Error>
        where F: Fn(&P) -> Option<(secp256k1::Signature, Option<SigHashType>)>,
              H: Fn(Sha256dHash) -> Option<[u8; 32]>
    {
        match *self {
            astelem::E::CheckSig(ref pk) => satisfy_checksig(pk, keyfn),
            astelem::E::CheckMultiSig(k, ref keys) => satisfy_checkmultisig(k, keys, keyfn),
            astelem::E::Time(n) => satisfy_csv(n, age).map(|_| vec![vec![1]]),
            astelem::E::Threshold(k, ref sube, ref subw) => satisfy_threshold(k, sube, subw, keyfn, hashfn, age),
            astelem::E::ParallelAnd(ref left, ref right) => {
                let mut ret = right.satisfy(keyfn, hashfn, age)?;
                ret.extend(left.satisfy(keyfn, hashfn, age)?);
                Ok(ret)
            }
            astelem::E::CascadeAnd(ref left, ref right) => {
                let mut ret = right.satisfy(keyfn, hashfn, age)?;
                ret.extend(left.satisfy(keyfn, hashfn, age)?);
                Ok(ret)
            }
            astelem::E::ParallelOr(ref left, ref right) => satisfy_parallel_or(left, right, keyfn, hashfn, age),
            astelem::E::CascadeOr(ref left, ref right) => satisfy_cascade_or(left, right, keyfn, hashfn, age),
            astelem::E::SwitchOrLeft(ref left, ref right) => satisfy_switch_or(left, right, keyfn, hashfn, age),
            astelem::E::SwitchOrRight(ref left, ref right) => satisfy_switch_or(right, left, keyfn, hashfn, age),
            astelem::E::Likely(ref fexpr) => {
                let mut ret = fexpr.satisfy(keyfn, hashfn, age)?;
                ret.push(vec![]);
                Ok(ret)
            }
            astelem::E::Unlikely(ref fexpr) => {
                let mut ret = fexpr.satisfy(keyfn, hashfn, age)?;
                ret.push(vec![1]);
                Ok(ret)
            }
        }
    }
}

impl<P: Clone> astelem::E<P> {
    /// Return a list of all public keys which might contribute to satisfaction of the scriptpubkey
    pub fn required_keys(&self) -> Vec<P> {
        match *self {
            astelem::E::CheckSig(ref pk) => vec![pk.clone()],
            astelem::E::CheckMultiSig(_, ref keys) => keys.clone(),
            astelem::E::Time(..) => vec![],
            astelem::E::Threshold(_, ref sube, ref subw) => {
                let mut ret = sube.required_keys();
                for sub in subw {
                    ret.extend(sub.required_keys());
                }
                ret
            }
            astelem::E::ParallelAnd(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            astelem::E::CascadeAnd(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            astelem::E::ParallelOr(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            astelem::E::CascadeOr(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            astelem::E::SwitchOrLeft(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            astelem::E::SwitchOrRight(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            astelem::E::Likely(ref fexpr) | astelem::E::Unlikely(ref fexpr) => {
                fexpr.required_keys()
            }
        }
    }
}

impl<P: ToString> Dissatisfiable<P> for astelem::E<P> {
    fn dissatisfy(&self) -> Vec<Vec<u8>> {
        match *self {
            astelem::E::CheckSig(..) => vec![vec![]],
            astelem::E::CheckMultiSig(k, _) => vec![vec![]; k + 1],
            astelem::E::Time(..) => vec![vec![]],
            astelem::E::Threshold(_, ref sube, ref subw) => {
                let mut ret = vec![];
                for sub in subw.iter().rev() {
                    ret.extend(sub.dissatisfy());
                }
                ret.extend(sube.dissatisfy());
                ret
            }
            astelem::E::ParallelAnd(ref left, ref right) => {
                let mut ret = right.dissatisfy();
                ret.extend(left.dissatisfy());
                ret
            }
            astelem::E::CascadeAnd(ref left, _) => left.dissatisfy(),
            astelem::E::ParallelOr(ref left, ref right) => {
                let mut ret = right.dissatisfy();
                ret.extend(left.dissatisfy());
                ret
            }
            astelem::E::CascadeOr(ref left, ref right) => {
                let mut ret = right.dissatisfy();
                ret.extend(left.dissatisfy());
                ret
            }
            astelem::E::SwitchOrLeft(ref left, _) => {
                let mut ret = left.dissatisfy();
                ret.push(vec![1]);
                ret
            }
            astelem::E::SwitchOrRight(ref left, _) => {
                let mut ret = left.dissatisfy();
                ret.push(vec![]);
                ret
            }
            astelem::E::Likely(..) => vec![vec![1]],
            astelem::E::Unlikely(..) => vec![vec![]],
        }
    }
}

impl<P: ToString> Satisfiable<P> for astelem::W<P> {
    fn satisfy<F, H>(&self, keyfn: Option<&F>, hashfn: Option<&H>, age: u32)
        -> Result<Vec<Vec<u8>>, Error>
        where F: Fn(&P) -> Option<(secp256k1::Signature, Option<SigHashType>)>,
              H: Fn(Sha256dHash) -> Option<[u8; 32]>
    {
        match *self {
            astelem::W::CheckSig(ref pk) => satisfy_checksig(pk, keyfn),
            astelem::W::HashEqual(hash) => satisfy_hashequal(hash, hashfn),
            astelem::W::Time(n) => satisfy_csv(n, age).map(|_| vec![vec![1]]),
            astelem::W::CastE(ref e) => e.satisfy(keyfn, hashfn, age)
        }
    }
}

impl<P: Clone> astelem::W<P> {
    /// Return a list of all public keys which might contribute to satisfaction of the scriptpubkey
    pub fn required_keys(&self) -> Vec<P> {
        match *self {
            astelem::W::CheckSig(ref pk) => vec![pk.clone()],
            astelem::W::HashEqual(..) => vec![],
            astelem::W::Time(..) => vec![],
            astelem::W::CastE(ref e) => e.required_keys(),
        }
    }
}

impl<P: ToString> Dissatisfiable<P> for astelem::W<P> {
    fn dissatisfy(&self) -> Vec<Vec<u8>> {
        match *self {
            astelem::W::CheckSig(..) => vec![vec![]],
            astelem::W::HashEqual(..) => vec![vec![]],
            astelem::W::Time(..) => vec![vec![]],
            astelem::W::CastE(ref e) => e.dissatisfy()
        }
    }
}

impl<P: ToString> Satisfiable<P> for astelem::F<P> {
    fn satisfy<F, H>(&self, keyfn: Option<&F>, hashfn: Option<&H>, age: u32)
        -> Result<Vec<Vec<u8>>, Error>
        where F: Fn(&P) -> Option<(secp256k1::Signature, Option<SigHashType>)>,
              H: Fn(Sha256dHash) -> Option<[u8; 32]>
    {
        match *self {
            astelem::F::CheckSig(ref pk) => satisfy_checksig(pk, keyfn),
            astelem::F::CheckMultiSig(k, ref keys) => satisfy_checkmultisig(k, keys, keyfn),
            astelem::F::Time(n) => satisfy_csv(n, age),
            astelem::F::HashEqual(hash) => satisfy_hashequal(hash, hashfn),
            astelem::F::Threshold(k, ref sube, ref subw) => satisfy_threshold(k, sube, subw, keyfn, hashfn, age),
            astelem::F::And(ref left, ref right) => {
                let mut ret = right.satisfy(keyfn, hashfn, age)?;
                ret.extend(left.satisfy(keyfn, hashfn, age)?);
                Ok(ret)
            }
            astelem::F::CascadeOr(ref left, ref right) => satisfy_cascade_or(left, right, keyfn, hashfn, age),
            astelem::F::SwitchOr(ref left, ref right) => satisfy_switch_or(left, right, keyfn, hashfn, age),
            astelem::F::SwitchOrV(ref left, ref right) => satisfy_switch_or(left, right, keyfn, hashfn, age),
        }
    }
}

impl<P: Clone> astelem::F<P> {
    /// Return a list of all public keys which might contribute to satisfaction of the scriptpubkey
    pub fn required_keys(&self) -> Vec<P> {
        match *self {
            astelem::F::CheckSig(ref pk) => vec![pk.clone()],
            astelem::F::CheckMultiSig(_, ref keys) => keys.clone(),
            astelem::F::HashEqual(..) | astelem::F::Time(..) => vec![],
            astelem::F::Threshold(_, ref sube, ref subw) => {
                let mut ret = sube.required_keys();
                for sub in subw {
                    ret.extend(sub.required_keys());
                }
                ret
            }
            astelem::F::And(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            astelem::F::CascadeOr(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            astelem::F::SwitchOr(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            astelem::F::SwitchOrV(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
        }
    }

}

impl<P: ToString> Satisfiable<P> for astelem::V<P> {
    fn satisfy<F, H>(&self, keyfn: Option<&F>, hashfn: Option<&H>, age: u32)
        -> Result<Vec<Vec<u8>>, Error>
        where F: Fn(&P) -> Option<(secp256k1::Signature, Option<SigHashType>)>,
              H: Fn(Sha256dHash) -> Option<[u8; 32]>
    {
        match *self {
            astelem::V::CheckSig(ref pk) => satisfy_checksig(pk, keyfn),
            astelem::V::CheckMultiSig(k, ref keys) => satisfy_checkmultisig(k, keys, keyfn),
            astelem::V::Time(n) => satisfy_csv(n, age),
            astelem::V::HashEqual(hash) => satisfy_hashequal(hash, hashfn),
            astelem::V::Threshold(k, ref sube, ref subw) => satisfy_threshold(k, sube, subw, keyfn, hashfn, age),
            astelem::V::And(ref left, ref right) => {
                let mut ret = right.satisfy(keyfn, hashfn, age)?;
                ret.extend(left.satisfy(keyfn, hashfn, age)?);
                Ok(ret)
            }
            astelem::V::SwitchOr(ref left, ref right) => satisfy_switch_or(left, right, keyfn, hashfn, age),
            astelem::V::SwitchOrT(ref left, ref right) => satisfy_switch_or(left, right, keyfn, hashfn, age),
            astelem::V::CascadeOr(ref left, ref right) => satisfy_cascade_or(left, right, keyfn, hashfn, age),
        }
    }
}

impl<P: Clone> astelem::V<P> {
    /// Return a list of all public keys which might contribute to satisfaction of the scriptpubkey
    pub fn required_keys(&self) -> Vec<P> {
        match *self {
            astelem::V::CheckSig(ref pk) => vec![pk.clone()],
            astelem::V::CheckMultiSig(_, ref keys) => keys.clone(),
            astelem::V::HashEqual(..) | astelem::V::Time(..) => vec![],
            astelem::V::Threshold(_, ref sube, ref subw) => {
                let mut ret = sube.required_keys();
                for sub in subw {
                    ret.extend(sub.required_keys());
                }
                ret
            }
            astelem::V::And(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            astelem::V::SwitchOr(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            astelem::V::SwitchOrT(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            astelem::V::CascadeOr(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
        }
    }
}

impl<P: ToString> Satisfiable<P> for astelem::T<P> {
    fn satisfy<F, H>(&self, keyfn: Option<&F>, hashfn: Option<&H>, age: u32)
        -> Result<Vec<Vec<u8>>, Error>
        where F: Fn(&P) -> Option<(secp256k1::Signature, Option<SigHashType>)>,
              H: Fn(Sha256dHash) -> Option<[u8; 32]>
    {
        match *self {
            astelem::T::Time(..) => Ok(vec![]),
            astelem::T::HashEqual(hash) => satisfy_hashequal(hash, hashfn),
            astelem::T::And(ref left, ref right) => {
                let mut ret = right.satisfy(keyfn, hashfn, age)?;
                ret.extend(left.satisfy(keyfn, hashfn, age)?);
                Ok(ret)
            }
            astelem::T::ParallelOr(ref left, ref right) => satisfy_parallel_or(left, right, keyfn, hashfn, age),
            astelem::T::CascadeOr(ref left, ref right) => satisfy_cascade_or(left, right, keyfn, hashfn, age),
            astelem::T::CascadeOrV(ref left, ref right) => satisfy_cascade_or(left, right, keyfn, hashfn, age),
            astelem::T::SwitchOr(ref left, ref right) => satisfy_switch_or(left, right, keyfn, hashfn, age),
            astelem::T::SwitchOrV(ref left, ref right) => satisfy_switch_or(left, right, keyfn, hashfn, age),
            astelem::T::CastE(ref e) => e.satisfy(keyfn, hashfn, age),
        }
    }
}

impl<P: Clone> astelem::T<P> {
    /// Return a list of all public keys which might contribute to satisfaction of the scriptpubkey
    pub fn required_keys(&self) -> Vec<P> {
        match *self {
            astelem::T::Time(..) | astelem::T::HashEqual(..) => vec![],
            astelem::T::And(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            astelem::T::ParallelOr(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            astelem::T::CascadeOr(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            astelem::T::CascadeOrV(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            astelem::T::SwitchOr(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            astelem::T::SwitchOrV(ref left, ref right) => {
                let mut ret = left.required_keys();
                ret.extend(right.required_keys());
                ret
            }
            astelem::T::CastE(ref sub) => sub.required_keys(),
        }
    }
}

// Helper functions to produce satisfactions for the various AST element types,
// e.g. cascade OR, parallel AND, etc., which typically do not depend on the
// specific choice of E/W/F/V/T that is chosen.

/// Computes witness size, assuming individual pushes are less than 254 bytes
fn satisfy_cost(s: &[Vec<u8>]) -> usize {
    s.iter().map(|s| 1 + s.len()).sum()
}

/// Helper function that produces a checksig(verify) satisfaction
fn satisfy_checksig<P, F>(pk: &P, keyfn: Option<F>) -> Result<Vec<Vec<u8>>, Error>
    where F: Fn(&P) -> Option<(secp256k1::Signature, Option<SigHashType>)>,
          P: ToString,
{
    let ret = keyfn
        .and_then(|keyfn| keyfn(pk))
        .map(|(sig, hashtype)| {
            let secp = secp256k1::Secp256k1::without_caps();
            let mut ret = sig.serialize_der(&secp);
            if let Some(hashtype) = hashtype {
                ret.push(hashtype.as_u32() as u8);
            }
            vec![ret]
        });
        
    match ret {
        Some(ret) => Ok(ret),
        None => Err(Error::MissingSig(pk.to_string())),
    }
}

/// Helper function that produces a checkmultisig(verify) satisfaction
fn satisfy_checkmultisig<P, F>(k: usize, keys: &[P], keyfn: Option<&F>) -> Result<Vec<Vec<u8>>, Error>
    where F: Fn(&P) -> Option<(secp256k1::Signature, Option<SigHashType>)>,
          P: ToString,
{
    let mut ret = Vec::with_capacity(k + 1);

    ret.push(vec![]);
    for pk in keys {
        if let Ok(mut sig_vec) = satisfy_checksig(pk, keyfn) {
            ret.push(sig_vec.pop().expect("satisfied checksig has one witness element"));
            if ret.len() > k + 1 {
                let max_idx = ret
                    .iter()
                    .enumerate()
                    .max_by_key(|(_, ref sig)| sig.len())
                    .unwrap()
                    .0;
                ret.remove(max_idx);
            }
        }
    }

    if ret.len() == k + 1 {
        Ok(ret)
    } else {
        Err(Error::CouldNotSatisfy)
    }
}

fn satisfy_hashequal<H>(hash: Sha256dHash, hashfn: Option<&H>) -> Result<Vec<Vec<u8>>, Error>
    where H: Fn(Sha256dHash) -> Option<[u8; 32]>,
{
    match hashfn.and_then(|hashfn| hashfn(hash)).map(|preimage| vec![preimage[..].to_owned()]) {
        Some(ret) => Ok(ret),
        None => Err(Error::MissingHash(hash)),
    }
}

fn satisfy_csv(n: u32, age: u32) -> Result<Vec<Vec<u8>>, Error> {
    if age >= n {
        Ok(vec![])
    } else {
        Err(Error::LocktimeNotMet(n))
    }
}

fn satisfy_threshold<P, F, H>(
    k: usize,
    sube: &Rc<astelem::E<P>>,
    subw: &[Rc<astelem::W<P>>],
    keyfn: Option<&F>,
    hashfn: Option<&H>,
    age: u32,
    ) -> Result<Vec<Vec<u8>>, Error>
    where F: Fn(&P) -> Option<(secp256k1::Signature, Option<SigHashType>)>,
          H: Fn(Sha256dHash) -> Option<[u8; 32]>,
          P: ToString,
{
    fn flatten(v: Vec<Vec<Vec<u8>>>) -> Vec<Vec<u8>> {
        v.into_iter().fold(vec![], |mut acc, x| { acc.extend(x); acc })
    }

    if k == 0 {
        return Ok(vec![]);
    }

    let mut satisfied = 0;
    let mut ret = Vec::with_capacity(1 + subw.len());
    let mut ret_dis = Vec::with_capacity(1 + subw.len());

    for sub in subw.iter().rev() {
        let dissat = sub.dissatisfy();
        if let Ok(sat) = sub.satisfy(keyfn, hashfn, age) {
            ret.push(sat);
            satisfied += 1;
        } else {
            ret.push(dissat.clone());
        }
        ret_dis.push(dissat);
    }

    let dissat_e = sube.dissatisfy();
    if let Ok(sat) = sube.satisfy(keyfn, hashfn, age) {
        ret.push(sat);
        satisfied += 1;
    } else {
        ret.push(dissat_e.clone());
    }
    ret_dis.push(dissat_e);

    debug_assert_eq!(ret.len(), 1 + subw.len());
    debug_assert_eq!(ret_dis.len(), 1 + subw.len());

    if satisfied < k {
        return Err(Error::CouldNotSatisfy);
    }
    if satisfied == k {
        return Ok(flatten(ret));
    }

    // If we have more satisfactions than needed, throw away the extras, choosing
    // the ones that would yield the biggest savings.
    let mut indices: Vec<usize> = (0..1 + subw.len()).collect();
    indices.sort_by_key(|i| {
        satisfy_cost(&ret_dis[*i]) as isize - satisfy_cost(&ret[*i]) as isize
    });
    for i in indices.iter().take(satisfied - k) {
        mem::swap(&mut ret[*i], &mut ret_dis[*i]);
    }

    Ok(flatten(ret))
}

fn satisfy_parallel_or<P, F, H>(
    left: &Rc<astelem::E<P>>,
    right: &Rc<astelem::W<P>>,
    keyfn: Option<&F>,
    hashfn: Option<&H>,
    age: u32,
    ) -> Result<Vec<Vec<u8>>, Error>
    where F: Fn(&P) -> Option<(secp256k1::Signature, Option<SigHashType>)>,
          H: Fn(Sha256dHash) -> Option<[u8; 32]>,
          P: ToString,
{
    match (
        left.satisfy(keyfn, hashfn, age),
        right.satisfy(keyfn, hashfn, age),
    ) {
        (Ok(lsat), Err(..)) => {
            let mut rdissat = right.dissatisfy();
            rdissat.extend(lsat);
            Ok(rdissat)
        }
        (Err(..), Ok(mut rsat)) => {
            let ldissat = left.dissatisfy();
            rsat.extend(ldissat);
            Ok(rsat)
        }
        (Err(e), Err(..)) => {
            Err(e)
        }
        (Ok(lsat), Ok(mut rsat)) => {
            let ldissat = left.dissatisfy();
            let mut rdissat = right.dissatisfy();

            if satisfy_cost(&lsat) + satisfy_cost(&rdissat) <= satisfy_cost(&rsat) + satisfy_cost(&ldissat) {
                rdissat.extend(lsat);
                Ok(rdissat)
            } else {
                rsat.extend(ldissat);
                Ok(rsat)
            }
        }
    }
}

fn satisfy_switch_or<P, F, H, T, S>(
    left: &Rc<T>,
    right: &Rc<S>,
    keyfn: Option<&F>,
    hashfn: Option<&H>,
    age: u32,
    ) -> Result<Vec<Vec<u8>>, Error>
    where F: Fn(&P) -> Option<(secp256k1::Signature, Option<SigHashType>)>,
          H: Fn(Sha256dHash) -> Option<[u8; 32]>,
          T: Satisfiable<P>,
          S: Satisfiable<P>,
          P: ToString,
{
    match (
        left.satisfy(keyfn, hashfn, age),
        right.satisfy(keyfn, hashfn, age),
    ) {
        (Err(e), Err(..)) => Err(e),
        (Ok(mut lsat), Err(..)) => {
            lsat.push(vec![1]);
            Ok(lsat)
        }
        (Err(..), Ok(mut rsat)) => {
            rsat.push(vec![]);
            Ok(rsat)
        }
        (Ok(mut lsat), Ok(mut rsat)) => {
            if satisfy_cost(&lsat) + 2 <= satisfy_cost(&rsat) + 1 {
                lsat.push(vec![1]);
                Ok(lsat)
            } else {
                rsat.push(vec![]);
                Ok(rsat)
            }
        }
    }
}

fn satisfy_cascade_or<P, F, H, T>(
    left: &Rc<astelem::E<P>>,
    right: &Rc<T>,
    keyfn: Option<&F>,
    hashfn: Option<&H>,
    age: u32,
    ) -> Result<Vec<Vec<u8>>, Error>
    where F: Fn(&P) -> Option<(secp256k1::Signature, Option<SigHashType>)>,
          H: Fn(Sha256dHash) -> Option<[u8; 32]>,
          T: Satisfiable<P>,
          P: ToString,
{
    match (
        left.satisfy(keyfn, hashfn, age),
        right.satisfy(keyfn, hashfn, age),
    ) {
        (Err(e), Err(..)) => Err(e),
        (Ok(lsat), Err(..)) => Ok(lsat),
        (Err(..), Ok(mut rsat)) => {
            let ldissat = left.dissatisfy();
            rsat.extend(ldissat);
            Ok(rsat)
        }
        (Ok(lsat), Ok(mut rsat)) => {
            let ldissat = left.dissatisfy();

            if satisfy_cost(&lsat) <= satisfy_cost(&rsat) + satisfy_cost(&ldissat) {
                Ok(lsat)
            } else {
                rsat.extend(ldissat);
                Ok(rsat)
            }
        }
    }
}
