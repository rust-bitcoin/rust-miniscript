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
use std::{cmp, i64, mem};

use bitcoin::hashes::{hash160, ripemd160, sha256, sha256d};
use bitcoin::{self, secp256k1};
use {MiniscriptKey, ToPublicKey};

use ScriptContext;
use Terminal;

/// Type alias for a signature/hashtype pair
pub type BitcoinSig = (secp256k1::Signature, bitcoin::SigHashType);

/// Trait describing a lookup table for signatures, hash preimages, etc.
/// Every method has a default implementation that simply returns `None`
/// on every query. Users are expected to override the methods that they
/// have data for.
pub trait Satisfier<Pk: MiniscriptKey> {
    /// Given a public key, look up a signature with that key
    fn lookup_sig(&self, _: &Pk) -> Option<BitcoinSig> {
        None
    }

    /// Given a `Pkh`, lookup corresponding `Pk`
    fn lookup_pkh_pk(&self, _: &Pk::Hash) -> Option<Pk> {
        None
    }

    /// Given a keyhash, look up the signature and the associated key
    /// Even if signatures for public key Hashes are not available, the users
    /// can use this map to provide pkh -> pk mapping which can be useful
    /// for dissatisfying pkh.
    fn lookup_pkh_sig(&self, _: &Pk::Hash) -> Option<(bitcoin::PublicKey, BitcoinSig)> {
        None
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

    /// Assert whether an relative locktime is satisfied
    fn check_older(&self, _: u32) -> bool {
        false
    }

    /// Assert whether a absolute locktime is satisfied
    fn check_after(&self, _: u32) -> bool {
        false
    }
}

// Allow use of `()` as a "no conditions available" satisfier
impl<Pk: MiniscriptKey> Satisfier<Pk> for () {}

/// Newtype around `u32` which implements `Satisfier` using `n` as an
/// relative locktime
pub struct Older(pub u32);

impl<Pk: MiniscriptKey> Satisfier<Pk> for Older {
    fn check_older(&self, n: u32) -> bool {
        n <= self.0
    }
}

/// Newtype around `u32` which implements `Satisfier` using `n` as an
/// absolute locktime
pub struct After(pub u32);

impl<Pk: MiniscriptKey> Satisfier<Pk> for After {
    fn check_after(&self, n: u32) -> bool {
        n <= self.0
    }
}

impl<Pk: MiniscriptKey> Satisfier<Pk> for HashMap<Pk, BitcoinSig> {
    fn lookup_sig(&self, key: &Pk) -> Option<BitcoinSig> {
        self.get(key).map(|x| *x)
    }
}

impl<Pk> Satisfier<Pk> for HashMap<Pk::Hash, (Pk, BitcoinSig)>
where
    Pk: MiniscriptKey + ToPublicKey,
{
    fn lookup_sig(&self, key: &Pk) -> Option<BitcoinSig> {
        self.get(&key.to_pubkeyhash()).map(|x| x.1)
    }

    fn lookup_pkh_pk(&self, pk_hash: &Pk::Hash) -> Option<Pk> {
        self.get(pk_hash).map(|x| x.0.clone())
    }

    fn lookup_pkh_sig(&self, pk_hash: &Pk::Hash) -> Option<(bitcoin::PublicKey, BitcoinSig)> {
        self.get(pk_hash)
            .map(|&(ref pk, sig)| (pk.to_public_key(), sig))
    }
}

impl<'a, Pk: MiniscriptKey, S: Satisfier<Pk>> Satisfier<Pk> for &'a S {
    fn lookup_sig(&self, p: &Pk) -> Option<BitcoinSig> {
        (**self).lookup_sig(p)
    }

    fn lookup_pkh_pk(&self, pkh: &Pk::Hash) -> Option<Pk> {
        (**self).lookup_pkh_pk(pkh)
    }

    fn lookup_pkh_sig(&self, pkh: &Pk::Hash) -> Option<(bitcoin::PublicKey, BitcoinSig)> {
        (**self).lookup_pkh_sig(pkh)
    }

    fn lookup_sha256(&self, h: sha256::Hash) -> Option<[u8; 32]> {
        (**self).lookup_sha256(h)
    }

    fn lookup_hash256(&self, h: sha256d::Hash) -> Option<[u8; 32]> {
        (**self).lookup_hash256(h)
    }

    fn lookup_ripemd160(&self, h: ripemd160::Hash) -> Option<[u8; 32]> {
        (**self).lookup_ripemd160(h)
    }

    fn lookup_hash160(&self, h: hash160::Hash) -> Option<[u8; 32]> {
        (**self).lookup_hash160(h)
    }

    fn check_older(&self, t: u32) -> bool {
        (**self).check_older(t)
    }

    fn check_after(&self, t: u32) -> bool {
        (**self).check_after(t)
    }
}

impl<'a, Pk: MiniscriptKey, S: Satisfier<Pk>> Satisfier<Pk> for &'a mut S {
    fn lookup_sig(&self, p: &Pk) -> Option<BitcoinSig> {
        (**self).lookup_sig(p)
    }

    fn lookup_pkh_pk(&self, pkh: &Pk::Hash) -> Option<Pk> {
        (**self).lookup_pkh_pk(pkh)
    }

    fn lookup_pkh_sig(&self, pkh: &Pk::Hash) -> Option<(bitcoin::PublicKey, BitcoinSig)> {
        (**self).lookup_pkh_sig(pkh)
    }

    fn lookup_sha256(&self, h: sha256::Hash) -> Option<[u8; 32]> {
        (**self).lookup_sha256(h)
    }

    fn lookup_hash256(&self, h: sha256d::Hash) -> Option<[u8; 32]> {
        (**self).lookup_hash256(h)
    }

    fn lookup_ripemd160(&self, h: ripemd160::Hash) -> Option<[u8; 32]> {
        (**self).lookup_ripemd160(h)
    }

    fn lookup_hash160(&self, h: hash160::Hash) -> Option<[u8; 32]> {
        (**self).lookup_hash160(h)
    }

    fn check_older(&self, t: u32) -> bool {
        (**self).check_older(t)
    }

    fn check_after(&self, t: u32) -> bool {
        (**self).check_after(t)
    }
}

macro_rules! impl_tuple_satisfier {
    ($($ty:ident),*) => {
        #[allow(non_snake_case)]
        impl<$($ty,)* Pk> Satisfier<Pk> for ($($ty,)*)
        where
            Pk: MiniscriptKey,
            $($ty: Satisfier<Pk>,)*
        {
            fn lookup_sig(&self, key: &Pk) -> Option<BitcoinSig> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_sig(key) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_pkh_sig(
                &self,
                key_hash: &Pk::Hash,
            ) -> Option<(bitcoin::PublicKey, BitcoinSig)> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_pkh_sig(key_hash) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_pkh_pk(
                &self,
                key_hash: &Pk::Hash,
            ) -> Option<Pk> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_pkh_pk(key_hash) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_sha256(&self, h: sha256::Hash) -> Option<[u8; 32]> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_sha256(h) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_hash256(&self, h: sha256d::Hash) -> Option<[u8; 32]> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_hash256(h) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_ripemd160(&self, h: ripemd160::Hash) -> Option<[u8; 32]> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_ripemd160(h) {
                        return Some(result);
                    }
                )*
                None
            }

            fn lookup_hash160(&self, h: hash160::Hash) -> Option<[u8; 32]> {
                let &($(ref $ty,)*) = self;
                $(
                    if let Some(result) = $ty.lookup_hash160(h) {
                        return Some(result);
                    }
                )*
                None
            }

            fn check_older(&self, n: u32) -> bool {
                let &($(ref $ty,)*) = self;
                $(
                    if $ty.check_older(n) {
                        return true;
                    }
                )*
                false
            }

            fn check_after(&self, n: u32) -> bool {
                let &($(ref $ty,)*) = self;
                $(
                    if $ty.check_after(n) {
                        return true;
                    }
                )*
                false
            }
        }
    }
}

impl_tuple_satisfier!(A);
impl_tuple_satisfier!(A, B);
impl_tuple_satisfier!(A, B, C);
impl_tuple_satisfier!(A, B, C, D);
impl_tuple_satisfier!(A, B, C, D, E);
impl_tuple_satisfier!(A, B, C, D, E, F);
impl_tuple_satisfier!(A, B, C, D, E, F, G);
impl_tuple_satisfier!(A, B, C, D, E, F, G, H);

/// A witness, if available, for a Miniscript fragment
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Witness {
    Stack(Vec<Vec<u8>>),
    Unavailable,
}

impl PartialOrd for Witness {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Witness {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match (self, other) {
            (&Witness::Stack(_), &Witness::Unavailable) => cmp::Ordering::Less,
            (&Witness::Unavailable, &Witness::Stack(_)) => cmp::Ordering::Greater,
            (&Witness::Stack(ref v1), &Witness::Stack(ref v2)) => v1.len().cmp(&v2.len()),
            (&Witness::Unavailable, &Witness::Unavailable) => cmp::Ordering::Equal,
        }
    }
}

impl Witness {
    /// Turn a signature into (part of) a satisfaction
    fn signature<Pk: ToPublicKey, S: Satisfier<Pk>>(sat: S, pk: &Pk) -> Self {
        match sat.lookup_sig(pk) {
            Some((sig, hashtype)) => {
                let mut ret = sig.serialize_der().to_vec();
                ret.push(hashtype.as_u32() as u8);
                Witness::Stack(vec![ret])
            }
            None => Witness::Unavailable,
        }
    }

    /// Turn a public key related to a pkh into (part of) a satisfaction
    fn pkh_public_key<Pk, S>(sat: S, pkh: &Pk::Hash) -> Self
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        match sat.lookup_pkh_pk(pkh) {
            Some(pk) => Witness::Stack(vec![pk.to_public_key().to_bytes()]),
            None => Witness::Unavailable,
        }
    }

    /// Turn a key/signature pair related to a pkh into (part of) a satisfaction
    fn pkh_signature<Pk, S>(sat: S, pkh: &Pk::Hash) -> Self
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        match sat.lookup_pkh_sig(pkh) {
            Some((pk, (sig, hashtype))) => {
                let mut ret = sig.serialize_der().to_vec();
                ret.push(hashtype.as_u32() as u8);
                Witness::Stack(vec![ret.to_vec(), pk.to_public_key().to_bytes()])
            }
            None => Witness::Unavailable,
        }
    }

    /// Turn a hash preimage into (part of) a satisfaction
    fn ripemd160_preimage<Pk, S>(sat: S, h: ripemd160::Hash) -> Self
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        match sat.lookup_ripemd160(h) {
            Some(pre) => Witness::Stack(vec![pre.to_vec()]),
            None => Witness::Unavailable,
        }
    }

    /// Turn a hash preimage into (part of) a satisfaction
    fn hash160_preimage<Pk, S>(sat: S, h: hash160::Hash) -> Self
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        match sat.lookup_hash160(h) {
            Some(pre) => Witness::Stack(vec![pre.to_vec()]),
            None => Witness::Unavailable,
        }
    }

    /// Turn a hash preimage into (part of) a satisfaction
    fn sha256_preimage<Pk, S>(sat: S, h: sha256::Hash) -> Self
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        match sat.lookup_sha256(h) {
            Some(pre) => Witness::Stack(vec![pre.to_vec()]),
            None => Witness::Unavailable,
        }
    }

    /// Turn a hash preimage into (part of) a satisfaction
    fn hash256_preimage<Pk, S>(sat: S, h: sha256d::Hash) -> Self
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        match sat.lookup_hash256(h) {
            Some(pre) => Witness::Stack(vec![pre.to_vec()]),
            None => Witness::Unavailable,
        }
    }

    /// Produce something like a 32-byte 0 push
    fn hash_dissatisfaction() -> Self {
        Witness::Stack(vec![vec![0; 32]])
    }

    /// Construct a satisfaction equivalent to an empty stack
    fn empty() -> Self {
        Witness::Stack(vec![])
    }

    /// Construct a satisfaction equivalent to `OP_1`
    fn push_1() -> Self {
        Witness::Stack(vec![vec![1]])
    }

    /// Construct a satisfaction equivalent to a single empty push
    fn push_0() -> Self {
        Witness::Stack(vec![vec![]])
    }

    /// Concatenate, or otherwise combine, two satisfactions
    fn combine(one: Self, two: Self) -> Self {
        match (one, two) {
            (Witness::Unavailable, _) => Witness::Unavailable,
            (_, Witness::Unavailable) => Witness::Unavailable,
            (Witness::Stack(mut a), Witness::Stack(b)) => {
                a.extend(b);
                Witness::Stack(a)
            }
        }
    }
}

/// A (dis)satisfaction of a Miniscript fragment
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Satisfaction {
    /// The actual witness stack
    pub stack: Witness,
    /// Whether or not this (dis)satisfaction has a signature somewhere
    /// in it
    pub has_sig: bool,
}

impl Satisfaction {
    fn minimum(sat1: Self, sat2: Self) -> Self {
        match (sat1.has_sig, sat2.has_sig) {
            // If neither option has a signature, this is a malleability
            // vector, so choose neither one.
            (false, false) => Satisfaction {
                stack: Witness::Unavailable,
                has_sig: false,
            },
            // If only one has a signature, take the one that doesn't; a
            // third party could malleate by removing the signature, but
            // can't malleate if he'd have to add it
            (false, true) => Satisfaction {
                stack: sat1.stack,
                has_sig: false,
            },
            (true, false) => Satisfaction {
                stack: sat2.stack,
                has_sig: false,
            },
            // If both have a signature associated with them, choose the
            // cheaper one (where "cheaper" is defined such that available
            // things are cheaper than unavailable ones)
            (true, true) => Satisfaction {
                stack: cmp::min(sat1.stack, sat2.stack),
                has_sig: true,
            },
        }
    }

    /// Produce a satisfaction
    pub fn satisfy<Pk: MiniscriptKey + ToPublicKey, Ctx: ScriptContext, Sat: Satisfier<Pk>>(
        term: &Terminal<Pk, Ctx>,
        stfr: &Sat,
    ) -> Self {
        match *term {
            Terminal::PkK(ref pk) => Satisfaction {
                stack: Witness::signature(stfr, pk),
                has_sig: true,
            },
            Terminal::PkH(ref pkh) => Satisfaction {
                stack: Witness::pkh_signature(stfr, pkh),
                has_sig: true,
            },
            Terminal::After(t) => Satisfaction {
                stack: if stfr.check_after(t) {
                    Witness::empty()
                } else {
                    Witness::Unavailable
                },
                has_sig: false,
            },
            Terminal::Older(t) => Satisfaction {
                stack: if stfr.check_older(t) {
                    Witness::empty()
                } else {
                    Witness::Unavailable
                },
                has_sig: false,
            },
            Terminal::Ripemd160(h) => Satisfaction {
                stack: Witness::ripemd160_preimage(stfr, h),
                has_sig: false,
            },
            Terminal::Hash160(h) => Satisfaction {
                stack: Witness::hash160_preimage(stfr, h),
                has_sig: false,
            },
            Terminal::Sha256(h) => Satisfaction {
                stack: Witness::sha256_preimage(stfr, h),
                has_sig: false,
            },
            Terminal::Hash256(h) => Satisfaction {
                stack: Witness::hash256_preimage(stfr, h),
                has_sig: false,
            },
            Terminal::True => Satisfaction {
                stack: Witness::empty(),
                has_sig: false,
            },
            Terminal::False => Satisfaction {
                stack: Witness::Unavailable,
                has_sig: false,
            },
            Terminal::Alt(ref sub)
            | Terminal::Swap(ref sub)
            | Terminal::Check(ref sub)
            | Terminal::Verify(ref sub)
            | Terminal::NonZero(ref sub)
            | Terminal::ZeroNotEqual(ref sub) => Self::satisfy(&sub.node, stfr),
            Terminal::DupIf(ref sub) => {
                let sat = Self::satisfy(&sub.node, stfr);
                Satisfaction {
                    stack: Witness::combine(sat.stack, Witness::push_1()),
                    has_sig: sat.has_sig,
                }
            }
            Terminal::AndV(ref l, ref r) | Terminal::AndB(ref l, ref r) => {
                let l_sat = Self::satisfy(&l.node, stfr);
                let r_sat = Self::satisfy(&r.node, stfr);
                Satisfaction {
                    stack: Witness::combine(r_sat.stack, l_sat.stack),
                    has_sig: l_sat.has_sig || r_sat.has_sig,
                }
            }
            Terminal::AndOr(ref a, ref b, ref c) => {
                let a_sat = Self::satisfy(&a.node, stfr);
                let a_nsat = Self::dissatisfy(&a.node, stfr);
                let b_sat = Self::satisfy(&b.node, stfr);
                let c_sat = Self::satisfy(&c.node, stfr);

                Self::minimum(
                    Satisfaction {
                        stack: Witness::combine(b_sat.stack, a_sat.stack),
                        has_sig: a_sat.has_sig || b_sat.has_sig,
                    },
                    Satisfaction {
                        stack: Witness::combine(c_sat.stack, a_nsat.stack),
                        has_sig: a_nsat.has_sig || c_sat.has_sig,
                    },
                )
            }
            Terminal::OrB(ref l, ref r) => {
                let l_sat = Self::satisfy(&l.node, stfr);
                let r_sat = Self::satisfy(&r.node, stfr);
                let l_nsat = Self::dissatisfy(&l.node, stfr);
                let r_nsat = Self::dissatisfy(&r.node, stfr);

                assert!(!l_nsat.has_sig);
                assert!(!r_nsat.has_sig);

                Self::minimum(
                    Satisfaction {
                        stack: Witness::combine(r_sat.stack, l_nsat.stack),
                        has_sig: r_sat.has_sig,
                    },
                    Satisfaction {
                        stack: Witness::combine(r_nsat.stack, l_sat.stack),
                        has_sig: l_sat.has_sig,
                    },
                )
            }
            Terminal::OrD(ref l, ref r) | Terminal::OrC(ref l, ref r) => {
                let l_sat = Self::satisfy(&l.node, stfr);
                let r_sat = Self::satisfy(&r.node, stfr);
                let l_nsat = Self::dissatisfy(&l.node, stfr);

                assert!(!l_nsat.has_sig);

                Self::minimum(
                    l_sat,
                    Satisfaction {
                        stack: Witness::combine(r_sat.stack, l_nsat.stack),
                        has_sig: r_sat.has_sig,
                    },
                )
            }
            Terminal::OrI(ref l, ref r) => {
                let l_sat = Self::satisfy(&l.node, stfr);
                let r_sat = Self::satisfy(&r.node, stfr);
                Self::minimum(
                    Satisfaction {
                        stack: Witness::combine(l_sat.stack, Witness::push_1()),
                        has_sig: l_sat.has_sig,
                    },
                    Satisfaction {
                        stack: Witness::combine(r_sat.stack, Witness::push_0()),
                        has_sig: r_sat.has_sig,
                    },
                )
            }
            Terminal::Thresh(k, ref subs) => {
                let mut sats = subs
                    .iter()
                    .map(|s| Self::satisfy(&s.node, stfr))
                    .collect::<Vec<_>>();
                // Start with the to-return stack set to all dissatisfactions
                let mut ret_stack = subs
                    .iter()
                    .map(|s| Self::dissatisfy(&s.node, stfr))
                    .collect::<Vec<_>>();

                // Sort everything by (sat cost - dissat cost), except that
                // satisfactions without signatures beat satisfactions with
                // signatures
                let mut sat_indices = (0..subs.len()).collect::<Vec<_>>();
                sat_indices.sort_by_key(|&i| {
                    let stack_weight = match (&sats[i].stack, &ret_stack[i].stack) {
                        (&Witness::Unavailable, _) => i64::MAX,
                        (_, &Witness::Unavailable) => i64::MIN,
                        (&Witness::Stack(ref s), &Witness::Stack(ref d)) => {
                            s.iter().map(Vec::len).sum::<usize>() as i64
                                - d.iter().map(Vec::len).sum::<usize>() as i64
                        }
                    };
                    (sats[i].has_sig, stack_weight)
                });

                for i in 0..k {
                    mem::swap(&mut ret_stack[sat_indices[i]], &mut sats[sat_indices[i]]);
                }

                // The above loop should have taken everything without a sig
                // (since those were sorted higher than non-sigs). If there
                // are remaining non-sig satisfactions this indicates a
                // malleability vector
                if k < sats.len() && !sats[sat_indices[k]].has_sig {
                    // All arguments should be `d`, so dissatisfactions have no
                    // signatures; and in this branch we assume too many weak
                    // arguments, so none of the satisfactions should have
                    // signatures either.
                    for sat in &ret_stack {
                        assert!(!sat.has_sig);
                    }
                    Satisfaction {
                        stack: Witness::Unavailable,
                        has_sig: false,
                    }
                } else {
                    // Otherwise flatten everything out
                    Satisfaction {
                        has_sig: ret_stack.iter().any(|sat| sat.has_sig),
                        stack: ret_stack.into_iter().fold(Witness::empty(), |acc, next| {
                            Witness::combine(next.stack, acc)
                        }),
                    }
                }
            }
            Terminal::Multi(k, ref keys) => {
                // Collect all available signatures
                let mut sig_count = 0;
                let mut sigs = Vec::with_capacity(k);
                for pk in keys {
                    match Witness::signature(stfr, pk) {
                        Witness::Stack(sig) => {
                            sigs.push(sig);
                            sig_count += 1;
                        }
                        Witness::Unavailable => {}
                    }
                }

                if sig_count < k {
                    Satisfaction {
                        stack: Witness::Unavailable,
                        has_sig: true,
                    }
                } else {
                    // Throw away the most expensive ones
                    for _ in 0..sig_count - k {
                        let max_idx = sigs
                            .iter()
                            .enumerate()
                            .max_by_key(|&(_, ref v)| v.len())
                            .unwrap()
                            .0;
                        sigs[max_idx] = vec![];
                    }

                    Satisfaction {
                        stack: sigs.into_iter().fold(Witness::push_0(), |acc, sig| {
                            Witness::combine(acc, Witness::Stack(sig))
                        }),
                        has_sig: true,
                    }
                }
            }
        }
    }

    /// Produce a satisfaction
    fn dissatisfy<Pk: MiniscriptKey + ToPublicKey, Ctx: ScriptContext, Sat: Satisfier<Pk>>(
        term: &Terminal<Pk, Ctx>,
        stfr: &Sat,
    ) -> Self {
        match *term {
            Terminal::PkK(..) => Satisfaction {
                stack: Witness::push_0(),
                has_sig: false,
            },
            Terminal::PkH(ref pkh) => Satisfaction {
                stack: Witness::combine(Witness::push_0(), Witness::pkh_public_key(stfr, pkh)),
                has_sig: false,
            },
            Terminal::False => Satisfaction {
                stack: Witness::empty(),
                has_sig: false,
            },
            Terminal::True => Satisfaction {
                stack: Witness::Unavailable,
                has_sig: false,
            },
            Terminal::Older(_) => Satisfaction {
                stack: Witness::Unavailable,
                has_sig: false,
            },
            Terminal::After(_) => Satisfaction {
                stack: Witness::Unavailable,
                has_sig: false,
            },
            Terminal::Sha256(_)
            | Terminal::Hash256(_)
            | Terminal::Ripemd160(_)
            | Terminal::Hash160(_) => Satisfaction {
                stack: Witness::hash_dissatisfaction(),
                has_sig: false,
            },
            Terminal::Alt(ref sub)
            | Terminal::Swap(ref sub)
            | Terminal::Check(ref sub)
            | Terminal::ZeroNotEqual(ref sub) => Self::dissatisfy(&sub.node, stfr),
            Terminal::DupIf(_) | Terminal::NonZero(_) => Satisfaction {
                stack: Witness::push_0(),
                has_sig: false,
            },
            Terminal::Verify(_) => Satisfaction {
                stack: Witness::Unavailable,
                has_sig: false,
            },
            Terminal::AndV(ref v, ref other) => {
                let vsat = Self::satisfy(&v.node, stfr);
                let odissat = Self::dissatisfy(&other.node, stfr);
                Satisfaction {
                    stack: Witness::combine(odissat.stack, vsat.stack),
                    has_sig: vsat.has_sig || odissat.has_sig,
                }
            }
            Terminal::AndB(ref l, ref r)
            | Terminal::OrB(ref l, ref r)
            | Terminal::OrD(ref l, ref r)
            | Terminal::AndOr(ref l, _, ref r) => {
                let lnsat = Self::dissatisfy(&l.node, stfr);
                let rnsat = Self::dissatisfy(&r.node, stfr);
                Satisfaction {
                    stack: Witness::combine(rnsat.stack, lnsat.stack),
                    has_sig: rnsat.has_sig || lnsat.has_sig,
                }
            }
            Terminal::OrC(..) => Satisfaction {
                stack: Witness::Unavailable,
                has_sig: false,
            },
            Terminal::OrI(ref l, ref r) => {
                let lnsat = Self::dissatisfy(&l.node, stfr);
                let dissat_1 = Satisfaction {
                    stack: Witness::combine(lnsat.stack, Witness::push_1()),
                    has_sig: lnsat.has_sig,
                };

                let rnsat = Self::dissatisfy(&r.node, stfr);
                let dissat_2 = Satisfaction {
                    stack: Witness::combine(rnsat.stack, Witness::push_0()),
                    has_sig: rnsat.has_sig,
                };

                Self::minimum(dissat_1, dissat_2)
            }
            Terminal::Thresh(_, ref subs) => Satisfaction {
                stack: subs.iter().fold(Witness::empty(), |acc, sub| {
                    let nsat = Self::dissatisfy(&sub.node, stfr);
                    assert!(!nsat.has_sig);
                    Witness::combine(nsat.stack, acc)
                }),
                has_sig: false,
            },
            Terminal::Multi(k, _) => Satisfaction {
                stack: Witness::Stack(vec![vec![]; k + 1]),
                has_sig: false,
            },
        }
    }
}
