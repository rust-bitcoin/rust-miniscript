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

use bitcoin;
use bitcoin_hashes::{hash160, ripemd160, sha256, sha256d};
use secp256k1;

use miniscript::astelem::AstElem;

/// Type alias for a signature/hashtype pair
pub type BitcoinSig = (secp256k1::Signature, bitcoin::SigHashType);

/// Trait describing a lookup table for signatures, hash preimages, etc.
/// Every method has a default implementation that simply returns `None`
/// on every query. Users are expected to override the methods that they
/// have data for.
pub trait Satisfier<Pk, Pkh> {
    /// Given a public key, look up a signature with that key
    fn lookup_pk(&self, _: &Pk)-> Option<BitcoinSig> {
        None
    }

    /// Wrapper around `lookup_pk` that witness-serializes a signature
    fn lookup_pk_vec(&self, p: &Pk) -> Option<Vec<u8>> {
        self.lookup_pk(p)
            .map(|(sig, hashtype)| {
                let mut ret = sig.serialize_der();
                ret.push(hashtype.as_u32() as u8);
                ret
            })
    }

    /// Given a keyhash, look up the signature and the associated key
    fn lookup_pkh(&self, _: &Pkh) -> Option<(bitcoin::PublicKey, BitcoinSig)> {
        None
    }

    /// Wrapper around `lookup_pkh` that witness-serializes a signature
    fn lookup_pkh_wit(&self, p: &Pkh) -> Option<Vec<Vec<u8>>> {
        self.lookup_pkh(p)
            .map(|(pk, (sig, hashtype))| {
                let mut ret = sig.serialize_der();
                ret.push(hashtype.as_u32() as u8);
                vec![ret, pk.to_bytes()]
            })
    }

    /// Given a SHA256 hash, look up its preimage
    fn lookup_sha256(&self, _: sha256::Hash) -> Option<[u8; 32]> {
        None
    }

    /// Given a HASH256 hash, look up its preimage
    fn lookup_hash256(&self, _: sha256d::Hash) -> Option<[u8; 32]> {
        None
    }

    /// Given a RIPEMD160 hash, look up its preimage
    fn lookup_ripemd160(&self, _: ripemd160::Hash) -> Option<[u8; 32]> {
        None
    }

    /// Given a HASH160 hash, look up its preimage
    fn lookup_hash160(&self, _: hash160::Hash) -> Option<[u8; 32]> {
        None
    }
}

/// Trait describing an AST element which can be satisfied, given maps from the
/// public data to corresponding witness data.
pub trait Satisfiable<Pk, Pkh> {
    /// Attempt to produce a witness that satisfies the AST element
    fn satisfy<S: Satisfier<Pk, Pkh>>(
        &self,
        satisfier: &S,
        age: u32,
        height: u32,
    ) -> Option<Vec<Vec<u8>>>;
}

/// Trait describing an AST element which can be dissatisfied (without failing
/// the whole script). Specifically, elements of type `E`, `W` and `Ke` may be
/// dissatisfied.
pub trait Dissatisfiable<Pk, Pkh> {
    /// Produce a dissatisfying witness
    fn dissatisfy(&self) -> Option<Vec<Vec<u8>>>;
}

/// Computes witness size, assuming individual pushes are less than 254 bytes
fn satisfy_cost(s: &[Vec<u8>]) -> usize {
    s.iter().map(|s| 1 + s.len()).sum()
}

impl<Pk, Pkh> Satisfiable<Pk, Pkh> for AstElem<Pk, Pkh> {
    fn satisfy<S: Satisfier<Pk, Pkh>>(
        &self,
        satisfier: &S,
        age: u32,
        height: u32,
    ) -> Option<Vec<Vec<u8>>> {
        match *self {
            AstElem::Pk(ref pk) => satisfier
                .lookup_pk_vec(pk)
                .map(|sig| vec![sig]),
            AstElem::PkH(ref pkh) => satisfier.lookup_pkh_wit(pkh),
            AstElem::After(t) => if age >= t {
                Some(vec![])
            } else {
                None
            },
            AstElem::Older(t) => if height >= t {
                Some(vec![])
            } else {
                None
            },
            AstElem::Sha256(h) => satisfier
                .lookup_sha256(h)
                .map(|hash| vec![hash.to_vec()]),
            AstElem::Hash256(h) => satisfier
                .lookup_hash256(h)
                .map(|hash| vec![hash.to_vec()]),
            AstElem::Ripemd160(h) => satisfier
                .lookup_ripemd160(h)
                .map(|hash| vec![hash.to_vec()]),
            AstElem::Hash160(h) => satisfier
                .lookup_hash160(h)
                .map(|hash| vec![hash.to_vec()]),
            AstElem::True => Some(vec![]),
            AstElem::False => None,
            AstElem::Alt(ref s)
                | AstElem::Swap(ref s)
                | AstElem::Check(ref s)
                | AstElem::Verify(ref s)
                | AstElem::NonZero(ref s)
                | AstElem::ZeroNotEqual(ref s)
                => s.satisfy(satisfier, age, height),
            AstElem::DupIf(ref sub) => {
                let mut ret = sub.satisfy(satisfier, age, height)?;
                ret.push(vec![1]);
                Some(ret)
            },
            AstElem::AndV(ref left, ref right)
                | AstElem::AndB(ref left, ref right) => {
                    let mut ret = right.satisfy(satisfier, age, height)?;
                    ret.extend(left.satisfy(satisfier, age, height)?);
                    Some(ret)
                },
            AstElem::AndOr(ref a, ref b, ref c) => {
                if let Some(mut asat) = a.satisfy(satisfier, age, height) {
                    asat.extend(c.satisfy(satisfier, age, height)?);
                    Some(asat)
                } else {
                    b.satisfy(satisfier, age, height)
                }
            },
            AstElem::OrB(ref l, ref r) => {
                match (
                    l.satisfy(satisfier, age, height),
                    r.satisfy(satisfier, age, height),
                ) {
                    (Some(lsat), None) => {
                        let mut rdissat = r.dissatisfy().unwrap();
                        rdissat.extend(lsat);
                        Some(rdissat)
                    }
                    (None, Some(mut rsat)) => {
                        let ldissat = l.dissatisfy().unwrap();
                        rsat.extend(ldissat);
                        Some(rsat)
                    }
                    (None, None) => None,
                    (Some(lsat), Some(mut rsat)) => {
                        let ldissat = l.dissatisfy().unwrap();
                        let mut rdissat = r.dissatisfy().unwrap();

                        if satisfy_cost(&lsat) + satisfy_cost(&rdissat)
                            <= satisfy_cost(&rsat) + satisfy_cost(&ldissat)
                        {
                            rdissat.extend(lsat);
                            Some(rdissat)
                        } else {
                            rsat.extend(ldissat);
                            Some(rsat)
                        }
                    }
                }
            }
            AstElem::OrD(ref l, ref r) |
            AstElem::OrC(ref l, ref r) => {
                match (
                    l.satisfy(satisfier, age, height),
                    r.satisfy(satisfier, age, height),
                ) {
                    (None, None) => None,
                    (Some(lsat), None) => Some(lsat),
                    (None, Some(mut rsat)) => {
                        let ldissat = l.dissatisfy().unwrap();
                        rsat.extend(ldissat);
                        Some(rsat)
                    }
                    (Some(lsat), Some(mut rsat)) => {
                        let ldissat = l.dissatisfy().unwrap();

                        if satisfy_cost(&lsat)
                            <= satisfy_cost(&rsat) + satisfy_cost(&ldissat)
                        {
                            Some(lsat)
                        } else {
                            rsat.extend(ldissat);
                            Some(rsat)
                        }
                    }
                }
            },
            AstElem::OrI(ref l, ref r) => {
                match (
                    l.satisfy(satisfier, age, height),
                    r.satisfy(satisfier, age, height),
                ) {
                    (None, None) => None,
                    (Some(mut lsat), None) => {
                        lsat.push(vec![1]);
                        Some(lsat)
                    }
                    (None, Some(mut rsat)) => {
                        rsat.push(vec![]);
                        Some(rsat)
                    }
                    (Some(mut lsat), Some(mut rsat)) => {
                        if satisfy_cost(&lsat) + 2 <= satisfy_cost(&rsat) + 1 {
                            lsat.push(vec![1]);
                            Some(lsat)
                        } else {
                            rsat.push(vec![]);
                            Some(rsat)
                        }
                    }
                }
            },
            AstElem::Thresh(k, ref subs) => {
                fn flatten(v: Vec<Vec<Vec<u8>>>) -> Vec<Vec<u8>> {
                    v.into_iter().fold(
                        vec![],
                        |mut acc, x| { acc.extend(x); acc },
                    )
                }

                if k == 0 {
                    return Some(vec![]);
                }

                let mut satisfied = 0;
                let mut ret = Vec::with_capacity(subs.len());
                let mut ret_dis = Vec::with_capacity(subs.len());

                for sub in subs.iter().rev() {
                    let dissat = sub.dissatisfy().unwrap();
                    if let Some(sat) = sub.satisfy(satisfier, age, height) {
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
                    return None;
                }
                if satisfied == k {
                    return Some(flatten(ret));
                }

                // If we have more satisfactions than needed, throw away the
                // extras, choosing the ones that yield the biggest savings.
                let mut indices: Vec<usize> = (0..subs.len()).collect();
                indices.sort_by_key(|i| {
                    satisfy_cost(&ret_dis[*i]) as isize
                        - satisfy_cost(&ret[*i]) as isize
                });
                for i in indices.iter().take(satisfied - k) {
                    mem::swap(&mut ret[*i], &mut ret_dis[*i]);
                }

                Some(flatten(ret))
            },
            AstElem::ThreshM(k, ref keys) => {
                let mut ret = Vec::with_capacity(k + 1);

                ret.push(vec![]);
                for pk in keys {
                    if let Some(vec) = satisfier.lookup_pk_vec(pk) {
                        ret.push(vec);
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
                    Some(ret)
                } else {
                    None
                }
            }
        }
    }
}

impl<Pk, Pkh> Dissatisfiable<Pk, Pkh> for AstElem<Pk, Pkh> {
    fn dissatisfy(&self) -> Option<Vec<Vec<u8>>> {
        match *self {
            AstElem::Pk(..) => Some(vec![vec![]]),
            AstElem::False => Some(vec![]),
            AstElem::AndB(ref left, ref right) => {
                let mut ret = right.dissatisfy()?;
                ret.extend(left.dissatisfy()?);
                Some(ret)
            },
            AstElem::AndOr(ref a, _, ref c) => {
                let mut ret = c.dissatisfy()?;
                ret.extend(a.dissatisfy()?);
                Some(ret)
            },
            AstElem::OrB(ref left, ref right)
                | AstElem::OrD(ref left, ref right) => {
                let mut ret = right.dissatisfy()?;
                ret.extend(left.dissatisfy()?);
                Some(ret)
            },
            AstElem::OrI(ref left, ref right) => {
                match (left.dissatisfy(), right.dissatisfy()) {
                    (None, None) => None,
                    (Some(mut l), None) => {
                        l.push(vec![1]);
                        Some(l)
                    },
                    (None, Some(mut r)) => {
                        r.push(vec![1]);
                        Some(r)
                    },
                    _ => panic!("tried to dissatisfy or_i but both branches were dissatisfiable"),
                }
            },
            AstElem::Thresh(_, ref subs) => {
                let mut ret = vec![];
                for sub in subs.iter().rev() {
                    ret.extend(sub.dissatisfy()?);
                }
                Some(ret)
            },
            AstElem::ThreshM(k, _) => Some(vec![vec![]; k + 1]),
            AstElem::Alt(ref sub)
                | AstElem::Swap(ref sub)
                | AstElem::Check(ref sub) => sub.dissatisfy(),
            AstElem::DupIf(..)
                | AstElem::NonZero(..) => Some(vec![vec![]]),
            _ => None,
        }
    }
}

