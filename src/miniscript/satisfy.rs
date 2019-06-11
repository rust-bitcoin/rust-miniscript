// Miniscript
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
//! Traits and implementations to support producing witnesses for Miniscript
//! scriptpubkeys.
//!

use std::{isize, mem};

use bitcoin::blockdata::transaction::SigHashType;
use bitcoin_hashes::sha256;
use secp256k1;

use Error;
use miniscript::astelem::AstElem;
use ToPublicKey;

/// Trait that lets us write `.rb()` to reborrow `Option<&mut T>` objects
trait Reborrow<T> {
    fn rb(&mut self) -> Option<&mut T>;
}
impl<'a, T> Reborrow<T> for Option<&'a mut T>
{
    fn rb(&mut self) -> Option<&mut T> {
        self.as_mut().map(|x| &mut **x)
    }
}


/// Trait describing an AST element which can be satisfied, given maps from the
/// public data to corresponding witness data.
pub trait Satisfiable<P> {
    /// Attempt to produce a witness that satisfies the AST element
    fn satisfy<F, H>(&self, keyfn: Option<&mut F>, hashfn: Option<&mut H>, age: u32)
        -> Result<Vec<Vec<u8>>, Error>
        where F: FnMut(&P) -> Option<(secp256k1::Signature, SigHashType)>,
              H: FnMut(sha256::Hash) -> Option<[u8; 32]>;
}

/// Trait describing an AST element which can be dissatisfied (without failing the
/// whole script). This only applies to `E` and `W`, since the other AST elements
/// are expected to fail the script on error.
pub trait Dissatisfiable<P> {
    /// For AST elements satisfying the "expression" and "wrapped" calling
    /// conventions, produce a dissatisfying witness. For other elements,
    /// panic.
    fn dissatisfy(&self) -> Vec<Vec<u8>>;
}

impl<P: ToPublicKey> Satisfiable<P> for AstElem<P> {
    fn satisfy<F, H>(&self, mut keyfn: Option<&mut F>, mut hashfn: Option<&mut H>, age: u32)
        -> Result<Vec<Vec<u8>>, Error>
        where F: FnMut(&P) -> Option<(secp256k1::Signature, SigHashType)>,
              H: FnMut(sha256::Hash) -> Option<[u8; 32]>
    {
        match *self {
            AstElem::Pk(ref p) |
            AstElem::PkV(ref p) |
            AstElem::PkQ(ref p) |
            AstElem::PkW(ref p) => satisfy_checksig(p, keyfn),
            AstElem::Multi(k, ref keys) |
            AstElem::MultiV(k, ref keys) => satisfy_checkmultisig(k, keys, keyfn),
            AstElem::TimeT(t) |
            AstElem::TimeV(t) |
            AstElem::TimeF(t) => satisfy_csv(t, age),
            AstElem::Time(t) |
            AstElem::TimeW(t) => satisfy_csv(t, age).map(|_| vec![vec![1]]),
            AstElem::HashT(h) |
            AstElem::HashV(h) |
            AstElem::HashW(h) => satisfy_hashequal(h, hashfn),
            AstElem::True(ref sub) |
            AstElem::Wrap(ref sub) => sub.satisfy(keyfn, hashfn, age),
            AstElem::Likely(ref sub) => {
                let mut ret = sub.satisfy(keyfn, hashfn, age)?;
                ret.push(vec![]);
                Ok(ret)
            },
            AstElem::Unlikely(ref sub) => {
                let mut ret = sub.satisfy(keyfn, hashfn, age)?;
                ret.push(vec![1]);
                Ok(ret)
            },
            AstElem::AndCat(ref left, ref right) |
            AstElem::AndBool(ref left, ref right) |
            AstElem::AndCasc(ref left, ref right) => {
                let mut ret = right.satisfy(keyfn.rb(), hashfn.rb(), age)?;
                ret.extend(left.satisfy(keyfn, hashfn, age)?);
                Ok(ret)
            },
            AstElem::OrBool(ref left, ref right) => satisfy_parallel_or(&*left, &*right, keyfn, hashfn, age),
            AstElem::OrCasc(ref left, ref right) |
            AstElem::OrCont(ref left, ref right) => satisfy_cascade_or(&*left, &*right, keyfn, hashfn, age),
            AstElem::OrKey(ref left, ref right) |
            AstElem::OrKeyV(ref left, ref right) |
            AstElem::OrIf(ref left, ref right) |
            AstElem::OrIfV(ref left, ref right) => satisfy_switch_or(&*left, &*right, keyfn, hashfn, age),
            AstElem::OrNotif(ref left, ref right) => satisfy_switch_or(&*right, &*left, keyfn, hashfn, age),
            AstElem::Thresh(k, ref subs) |
            AstElem::ThreshV(k, ref subs) => satisfy_threshold(k, subs, keyfn, hashfn, age),
        }
    }
}

impl<P: ToPublicKey> Dissatisfiable<P> for AstElem<P> {
    fn dissatisfy(&self) -> Vec<Vec<u8>> {
        match *self {
            AstElem::Pk(..) |
            AstElem::PkW(..) |
            AstElem::TimeW(..) |
            AstElem::HashW(..) => vec![vec![]],
            AstElem::Multi(k, _) => vec![vec![]; k + 1],
            AstElem::PkV(..) |
            AstElem::PkQ(..) |
            AstElem::MultiV(..) |
            AstElem::TimeT(..) |
            AstElem::TimeV(..) |
            AstElem::TimeF(..) |
            AstElem::Time(..) |
            AstElem::HashT(..) |
            AstElem::HashV(..) => unreachable!(),
            AstElem::True(ref sub) |
            AstElem::Wrap(ref sub) => sub.dissatisfy(),
            AstElem::Likely(..) => vec![vec![1]],
            AstElem::Unlikely(..) => vec![vec![]],
            AstElem::AndCat(..) => unreachable!(),
            AstElem::AndBool(ref left, ref right) => {
                let mut ret = right.dissatisfy();
                ret.extend(left.dissatisfy());
                ret
            },
            AstElem::AndCasc(ref left, _) => left.dissatisfy(),
            AstElem::OrBool(ref left, ref right) |
            AstElem::OrCasc(ref left, ref right) => {
                let mut ret = right.dissatisfy();
                ret.extend(left.dissatisfy());
                ret
            },
            AstElem::OrCont(..) |
            AstElem::OrKey(..) |
            AstElem::OrIfV(..) |
            AstElem::OrKeyV(..) => unreachable!(),
            AstElem::OrIf(_, ref right) => {
                let mut ret = right.dissatisfy();
                ret.push(vec![]);
                ret
            },
            AstElem::OrNotif(ref left, _) => {
                let mut ret = left.dissatisfy();
                ret.push(vec![]);
                ret
            },
            AstElem::Thresh(_, ref subs) => {
                let mut ret = vec![];
                for sub in subs.iter().rev() {
                    ret.extend(sub.dissatisfy());
                }
                ret
            },
            AstElem::ThreshV(..) => unreachable!(),
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
fn satisfy_checksig<P, F>(pk: &P, keyfn: Option<&mut F>) -> Result<Vec<Vec<u8>>, Error>
    where F: FnMut(&P) -> Option<(secp256k1::Signature, SigHashType)>,
          P: ToPublicKey,
{
    let ret = keyfn
        .and_then(|keyfn| keyfn(pk))
        .map(|(sig, hashtype)| {
            let mut ret = sig.serialize_der();
            ret.push(hashtype.as_u32() as u8);
            vec![ret]
        });
        
    match ret {
        Some(ret) => Ok(ret),
        None => Err(Error::MissingSig(pk.to_public_key())),
    }
}

/// Helper function that produces a checkmultisig(verify) satisfaction
fn satisfy_checkmultisig<P, F>(k: usize, keys: &[P], mut keyfn: Option<&mut F>) -> Result<Vec<Vec<u8>>, Error>
    where F: FnMut(&P) -> Option<(secp256k1::Signature, SigHashType)>,
          P: ToPublicKey,
{
    let mut ret = Vec::with_capacity(k + 1);

    ret.push(vec![]);
    for pk in keys {
        if let Ok(mut sig_vec) = satisfy_checksig(pk, keyfn.rb()) {
            ret.push(sig_vec.pop().expect("satisfied checksig has one witness element"));
            if ret.len() > k + 1 {
                let max_idx = ret
                    .iter()
                    .enumerate()
                    .max_by_key(|&(_, ref sig)| sig.len())
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

fn satisfy_hashequal<H>(hash: sha256::Hash, hashfn: Option<&mut H>) -> Result<Vec<Vec<u8>>, Error>
    where H: FnMut(sha256::Hash) -> Option<[u8; 32]>,
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
    subs: &[AstElem<P>],
    mut keyfn: Option<&mut F>,
    mut hashfn: Option<&mut H>,
    age: u32,
    ) -> Result<Vec<Vec<u8>>, Error>
    where F: FnMut(&P) -> Option<(secp256k1::Signature, SigHashType)>,
          H: FnMut(sha256::Hash) -> Option<[u8; 32]>,
          P: ToPublicKey,
{
    fn flatten(v: Vec<Vec<Vec<u8>>>) -> Vec<Vec<u8>> {
        v.into_iter().fold(vec![], |mut acc, x| { acc.extend(x); acc })
    }

    if k == 0 {
        return Ok(vec![]);
    }

    let mut satisfied = 0;
    let mut ret = Vec::with_capacity(subs.len());
    let mut ret_dis = Vec::with_capacity(subs.len());

    for sub in subs.iter().rev() {
        let dissat = sub.dissatisfy();
        if let Ok(sat) = sub.satisfy(keyfn.rb(), hashfn.rb(), age) {
            ret.push(sat);
            satisfied += 1;
        } else {
            ret.push(dissat.clone());
        }
        ret_dis.push(dissat);
    }

    debug_assert_eq!(ret.len(), subs.len());
    debug_assert_eq!(ret_dis.len(), subs.len());

    if satisfied < k {
        return Err(Error::CouldNotSatisfy);
    }
    if satisfied == k {
        return Ok(flatten(ret));
    }

    // If we have more satisfactions than needed, throw away the extras, choosing
    // the ones that would yield the biggest savings.
    let mut indices: Vec<usize> = (0..subs.len()).collect();
    indices.sort_by_key(|i| {
        satisfy_cost(&ret_dis[*i]) as isize - satisfy_cost(&ret[*i]) as isize
    });
    for i in indices.iter().take(satisfied - k) {
        mem::swap(&mut ret[*i], &mut ret_dis[*i]);
    }

    Ok(flatten(ret))
}

fn satisfy_parallel_or<P, F, H>(
    left: &AstElem<P>,
    right: &AstElem<P>,
    mut keyfn: Option<&mut F>,
    mut hashfn: Option<&mut H>,
    age: u32,
    ) -> Result<Vec<Vec<u8>>, Error>
    where F: FnMut(&P) -> Option<(secp256k1::Signature, SigHashType)>,
          H: FnMut(sha256::Hash) -> Option<[u8; 32]>,
          P: ToPublicKey,
{
    match (
        left.satisfy(keyfn.rb(), hashfn.rb(), age),
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

fn satisfy_switch_or<P, F, H>(
    left: &AstElem<P>,
    right: &AstElem<P>,
    mut keyfn: Option<&mut F>,
    mut hashfn: Option<&mut H>,
    age: u32,
    ) -> Result<Vec<Vec<u8>>, Error>
    where F: FnMut(&P) -> Option<(secp256k1::Signature, SigHashType)>,
          H: FnMut(sha256::Hash) -> Option<[u8; 32]>,
          P: ToPublicKey,
{
    match (
        left.satisfy(keyfn.rb(), hashfn.rb(), age),
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

fn satisfy_cascade_or<P, F, H>(
    left: &AstElem<P>,
    right: &AstElem<P>,
    mut keyfn: Option<&mut F>,
    mut hashfn: Option<&mut H>,
    age: u32,
    ) -> Result<Vec<Vec<u8>>, Error>
    where F: FnMut(&P) -> Option<(secp256k1::Signature, SigHashType)>,
          H: FnMut(sha256::Hash) -> Option<[u8; 32]>,
          P: ToPublicKey,
{
    match (
        left.satisfy(keyfn.rb(), hashfn.rb(), age),
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
