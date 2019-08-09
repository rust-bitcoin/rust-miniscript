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

use std::collections::HashMap;
use std::{isize, mem};

use bitcoin_hashes::{hash160, ripemd160, sha256, sha256d};
use secp256k1;
use MiniscriptKey;
use {bitcoin, ToPublicKey};

use std::cmp::Ordering;
use Terminal;

/// Type alias for a signature/hashtype pair
pub type BitcoinSig = (secp256k1::Signature, bitcoin::SigHashType);

/// Trait describing a lookup table for signatures, hash preimages, etc.
/// Every method has a default implementation that simply returns `None`
/// on every query. Users are expected to override the methods that they
/// have data for.
pub trait Satisfier<Pk: MiniscriptKey + ToPublicKey> {
    /// Given a public key, look up a signature with that key
    fn lookup_pk(&self, _: &Pk) -> Option<BitcoinSig> {
        None
    }

    /// Wrapper around `lookup_pk` that witness-serializes a signature
    fn lookup_pk_vec(&self, p: &Pk) -> Option<Vec<u8>> {
        self.lookup_pk(p).map(|(sig, hashtype)| {
            let mut ret = sig.serialize_der();
            ret.push(hashtype.as_u32() as u8);
            ret
        })
    }

    /// Given a `Pkh`, lookup corresponding `Pk`
    fn lookup_pkh_pk(&self, _: &Pk::Hash) -> Option<Pk> {
        None
    }

    /// Wrapper around `lookup_pkh_pk` that witness-serializes a pk to bytes
    fn lookup_pkh_pk_wit(&self, p: &Pk::Hash) -> Option<Vec<Vec<u8>>> {
        self.lookup_pkh_pk(p)
            .and_then(|pk| Some(vec![pk.to_public_key().to_bytes()]))
    }

    /// Given a keyhash, look up the signature and the associated key
    /// Even if signatures for public key Hashes are not available, the users
    /// can use this map to provide pkh -> pk mapping which can use useful
    /// for dissatisfying pkh.
    fn lookup_pkh(&self, p: &Pk::Hash) -> Option<(bitcoin::PublicKey, BitcoinSig)> {
        self.lookup_pkh_pk(p)
            .and_then(|ref pk| Some((pk.to_public_key(), self.lookup_pk(pk)?)))
    }

    /// Wrapper around `lookup_pkh` that witness-serializes a signature
    fn lookup_pkh_wit(&self, p: &Pk::Hash) -> Option<Vec<Vec<u8>>> {
        self.lookup_pkh(p).map(|(pk, (sig, hashtype))| {
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

impl<Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk> for HashMap<Pk, BitcoinSig> {
    fn lookup_pk(&self, key: &Pk) -> Option<BitcoinSig> {
        self.get(key).map(|x| *x)
    }
}

impl<Pk> Satisfier<Pk> for HashMap<Pk::Hash, (bitcoin::PublicKey, BitcoinSig)>
where
    Pk: MiniscriptKey + ToPublicKey,
{
    fn lookup_pkh(&self, pk_hash: &Pk::Hash) -> Option<(bitcoin::PublicKey, BitcoinSig)> {
        self.get(pk_hash).map(|x| *x)
    }
}

macro_rules! impl_tuple_satisfier {
    ($(&$lt:tt $ty:ident,)*) => {
        #[allow(non_snake_case)]
        impl<$($lt,)* $($ty,)* Pk> Satisfier<Pk> for ($(&$lt $ty,)*)
        where
            Pk: MiniscriptKey + ToPublicKey,
            $($ty: Satisfier<Pk>,)*
        {
            fn lookup_pk(&self, key: &Pk) -> Option<BitcoinSig> {
                let ($($ty,)*) = *self;
                $(
                    if let Some(result) = $ty.lookup_pk(key) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_pkh(
                &self,
                key_hash: &Pk::Hash,
            ) -> Option<(bitcoin::PublicKey, BitcoinSig)> {
                let ($($ty,)*) = *self;
                $(
                    if let Some(result) = $ty.lookup_pkh(key_hash) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_pkh_pk(
                &self,
                key_hash: &Pk::Hash,
            ) -> Option<Pk> {
                let ($($ty,)*) = *self;
                $(
                    if let Some(result) = $ty.lookup_pkh_pk(key_hash) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_sha256(&self, h: sha256::Hash) -> Option<[u8; 32]> {
                let ($($ty,)*) = *self;
                $(
                    if let Some(result) = $ty.lookup_sha256(h) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_hash256(&self, h: sha256d::Hash) -> Option<[u8; 32]> {
                let ($($ty,)*) = *self;
                $(
                    if let Some(result) = $ty.lookup_hash256(h) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_ripemd160(&self, h: ripemd160::Hash) -> Option<[u8; 32]> {
                let ($($ty,)*) = *self;
                $(
                    if let Some(result) = $ty.lookup_ripemd160(h) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_hash160(&self, h: hash160::Hash) -> Option<[u8; 32]> {
                let ($($ty,)*) = *self;
                $(
                    if let Some(result) = $ty.lookup_hash160(h) {
                        return Some(result);
                    }
                )*
                None
            }
        }
    }
}

impl_tuple_satisfier!(&'a A,);
impl_tuple_satisfier!(&'a A, &'b B,);
impl_tuple_satisfier!(&'a A, &'b B, &'c C,);
impl_tuple_satisfier!(&'a A, &'b B, &'c C, &'d D,);
impl_tuple_satisfier!(&'a A, &'b B, &'c C, &'d D, &'e E,);
impl_tuple_satisfier!(&'a A, &'b B, &'c C, &'d D, &'e E, &'f F,);
impl_tuple_satisfier!(&'a A, &'b B, &'c C, &'d D, &'e E, &'f F, &'g G,);
impl_tuple_satisfier!(&'a A, &'b B, &'c C, &'d D, &'e E, &'f F, &'g G, &'h H,);

/// Trait describing an AST element which can be satisfied, given maps from the
/// public data to corresponding witness data.
pub trait Satisfiable<Pk: MiniscriptKey + ToPublicKey> {
    /// Attempt to produce a witness that satisfies the AST element
    fn satisfy<S: Satisfier<Pk>>(
        &self,
        satisfier: &S,
        age: u32,
        height: u32,
    ) -> Option<Vec<Vec<u8>>>;
}

/// Trait describing an AST element which can be dissatisfied (without failing
/// the whole script). Specifically, elements of type `E`, `W` and `Ke` may be
/// dissatisfied.
trait Dissatisfiable<Pk: MiniscriptKey + ToPublicKey> {
    /// Produce a dissatisfying witness
    fn dissatisfy<S: Satisfier<Pk>>(&self, satisfier: &S) -> Option<Vec<Vec<u8>>>;
}

/// Computes witness size, assuming individual pushes are less than 254 bytes
fn satisfy_cost(s: &[Vec<u8>]) -> usize {
    s.iter().map(|s| 1 + s.len()).sum()
}

impl<Pk: MiniscriptKey + ToPublicKey> Satisfiable<Pk> for Terminal<Pk> {
    fn satisfy<S: Satisfier<Pk>>(
        &self,
        satisfier: &S,
        age: u32,
        height: u32,
    ) -> Option<Vec<Vec<u8>>> {
        match *self {
            Terminal::Pk(ref pk) => satisfier.lookup_pk_vec(pk).map(|sig| vec![sig]),
            Terminal::PkH(ref pkh) => satisfier.lookup_pkh_wit(pkh),
            Terminal::After(t) => {
                if age >= t {
                    Some(vec![])
                } else {
                    None
                }
            }
            Terminal::Older(t) => {
                if height >= t {
                    Some(vec![])
                } else {
                    None
                }
            }
            Terminal::Sha256(h) => satisfier.lookup_sha256(h).map(|hash| vec![hash.to_vec()]),
            Terminal::Hash256(h) => satisfier.lookup_hash256(h).map(|hash| vec![hash.to_vec()]),
            Terminal::Ripemd160(h) => satisfier
                .lookup_ripemd160(h)
                .map(|hash| vec![hash.to_vec()]),
            Terminal::Hash160(h) => satisfier.lookup_hash160(h).map(|hash| vec![hash.to_vec()]),
            Terminal::True => Some(vec![]),
            Terminal::False => None,
            Terminal::Alt(ref s)
            | Terminal::Swap(ref s)
            | Terminal::Check(ref s)
            | Terminal::Verify(ref s)
            | Terminal::NonZero(ref s)
            | Terminal::ZeroNotEqual(ref s) => s.node.satisfy(satisfier, age, height),
            Terminal::DupIf(ref sub) => {
                let mut ret = sub.node.satisfy(satisfier, age, height)?;
                ret.push(vec![1]);
                Some(ret)
            }
            Terminal::AndV(ref left, ref right) | Terminal::AndB(ref left, ref right) => {
                let mut ret = right.node.satisfy(satisfier, age, height)?;
                ret.extend(left.node.satisfy(satisfier, age, height)?);
                Some(ret)
            }
            Terminal::AndOr(ref a, ref b, ref c) => {
                if let Some(mut asat) = a.node.satisfy(satisfier, age, height) {
                    asat.extend(c.node.satisfy(satisfier, age, height)?);
                    Some(asat)
                } else {
                    b.node.satisfy(satisfier, age, height)
                }
            }
            Terminal::OrB(ref l, ref r) => {
                match (
                    l.node.satisfy(satisfier, age, height),
                    r.node.satisfy(satisfier, age, height),
                ) {
                    (Some(lsat), None) => {
                        let mut rdissat = r.node.dissatisfy(satisfier)?;
                        rdissat.extend(lsat);
                        Some(rdissat)
                    }
                    (None, Some(mut rsat)) => {
                        let ldissat = l.node.dissatisfy(satisfier)?;
                        rsat.extend(ldissat);
                        Some(rsat)
                    }
                    (None, None) => None,
                    (Some(lsat), Some(mut rsat)) => {
                        let ldissat = l.node.dissatisfy(satisfier)?;
                        let mut rdissat = r.node.dissatisfy(satisfier)?;

                        if l.ty.mall.safe && !r.ty.mall.safe {
                            rsat.extend(ldissat);
                            Some(rsat)
                        } else if !l.ty.mall.safe && r.ty.mall.safe {
                            rdissat.extend(lsat);
                            Some(rdissat)
                        } else {
                            //if both branches are safe or unsafe pick the cheapest one
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
            }
            Terminal::OrD(ref l, ref r) | Terminal::OrC(ref l, ref r) => {
                match (
                    l.node.satisfy(satisfier, age, height),
                    r.node.satisfy(satisfier, age, height),
                ) {
                    (None, None) => None,
                    (Some(lsat), None) => Some(lsat),
                    (None, Some(mut rsat)) => {
                        let ldissat = l.node.dissatisfy(satisfier)?;
                        rsat.extend(ldissat);
                        Some(rsat)
                    }
                    (Some(lsat), Some(mut rsat)) => {
                        let ldissat = l.node.dissatisfy(satisfier)?;
                        if l.ty.mall.safe && !r.ty.mall.safe {
                            rsat.extend(ldissat);
                            Some(rsat)
                        } else if !l.ty.mall.safe && r.ty.mall.safe {
                            Some(lsat)
                        } else {
                            if satisfy_cost(&lsat) <= satisfy_cost(&rsat) + satisfy_cost(&ldissat) {
                                Some(lsat)
                            } else {
                                rsat.extend(ldissat);
                                Some(rsat)
                            }
                        }
                    }
                }
            }
            Terminal::OrI(ref l, ref r) => {
                match (
                    l.node.satisfy(satisfier, age, height),
                    r.node.satisfy(satisfier, age, height),
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
                        if l.ty.mall.safe && !r.ty.mall.safe {
                            rsat.push(vec![]);
                            Some(rsat)
                        } else if !l.ty.mall.safe && r.ty.mall.safe {
                            lsat.push(vec![1]);
                            Some(lsat)
                        } else {
                            if satisfy_cost(&lsat) + 2 <= satisfy_cost(&rsat) + 1 {
                                lsat.push(vec![1]);
                                Some(lsat)
                            } else {
                                rsat.push(vec![]);
                                Some(rsat)
                            }
                        }
                    }
                }
            }
            Terminal::Thresh(k, ref subs) => {
                fn flatten(v: Vec<Vec<Vec<u8>>>) -> Vec<Vec<u8>> {
                    v.into_iter().fold(vec![], |mut acc, x| {
                        acc.extend(x);
                        acc
                    })
                }

                if k == 0 {
                    return Some(vec![]);
                }

                let mut satisfied = 0;
                let mut ret = Vec::with_capacity(subs.len());
                let mut ret_dis = Vec::with_capacity(subs.len());

                for sub in subs.iter().rev() {
                    let dissat = sub.node.dissatisfy(satisfier)?;
                    if let Some(sat) = sub.node.satisfy(satisfier, age, height) {
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
                indices.sort_by(|a, b| {
                    if !subs[*a].ty.mall.safe && subs[*b].ty.mall.safe {
                        Ordering::Less
                    } else if subs[*a].ty.mall.safe && !subs[*b].ty.mall.safe {
                        Ordering::Greater
                    } else {
                        let a_cost =
                            satisfy_cost(&ret_dis[*a]) as isize - satisfy_cost(&ret[*a]) as isize;
                        let b_cost =
                            satisfy_cost(&ret_dis[*b]) as isize - satisfy_cost(&ret[*b]) as isize;
                        if a_cost < b_cost {
                            Ordering::Less
                        } else {
                            Ordering::Greater
                        }
                    }
                });
                for i in indices.iter().take(satisfied - k) {
                    mem::swap(&mut ret[*i], &mut ret_dis[*i]);
                }

                Some(flatten(ret))
            }
            Terminal::ThreshM(k, ref keys) => {
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

impl<Pk: MiniscriptKey> Dissatisfiable<Pk> for Terminal<Pk> {
    fn dissatisfy<S: Satisfier<Pk>>(&self, satisfier: &S) -> Option<Vec<Vec<u8>>> {
        match *self {
            Terminal::Pk(..) => Some(vec![vec![]]),
            Terminal::PkH(ref pkh) => {
                let pk1 = satisfier.lookup_pkh_pk_wit(pkh);
                let pk2 = satisfier
                    .lookup_pkh(pkh)
                    .and_then(|(pk, _sig)| Some(vec![pk.to_bytes()]));
                match (pk1, pk2) {
                    (Some(x), _) | (_, Some(x)) => Some(x),
                    _ => None,
                }
            }
            Terminal::False => Some(vec![]),
            Terminal::AndB(ref left, ref right) => {
                let mut ret = right.node.dissatisfy(satisfier)?;
                ret.extend(left.node.dissatisfy(satisfier)?);
                Some(ret)
            }
            Terminal::AndOr(ref a, _, ref c) => {
                let mut ret = c.node.dissatisfy(satisfier)?;
                ret.extend(a.node.dissatisfy(satisfier)?);
                Some(ret)
            }
            Terminal::OrB(ref left, ref right) | Terminal::OrD(ref left, ref right) => {
                let mut ret = right.node.dissatisfy(satisfier)?;
                ret.extend(left.node.dissatisfy(satisfier)?);
                Some(ret)
            }
            Terminal::OrI(ref left, ref right) => {
                match (
                    left.node.dissatisfy(satisfier),
                    right.node.dissatisfy(satisfier),
                ) {
                    (None, None) => None,
                    (Some(mut l), None) => {
                        l.push(vec![1]);
                        Some(l)
                    }
                    (None, Some(mut r)) => {
                        r.push(vec![1]);
                        Some(r)
                    }
                    _ => panic!("tried to dissatisfy or_i but both branches were dissatisfiable"),
                }
            }
            Terminal::Thresh(_, ref subs) => {
                let mut ret = vec![];
                for sub in subs.iter().rev() {
                    ret.extend(sub.node.dissatisfy(satisfier)?);
                }
                Some(ret)
            }
            Terminal::ThreshM(k, _) => Some(vec![vec![]; k + 1]),
            Terminal::Alt(ref sub) | Terminal::Swap(ref sub) | Terminal::Check(ref sub) => {
                sub.node.dissatisfy(satisfier)
            }
            Terminal::DupIf(..) | Terminal::NonZero(..) => Some(vec![vec![]]),
            _ => None,
        }
    }
}
