// Miniscript
// Written in 2019 by
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

//! Concrete Policies
//!

use core::{fmt, str};
#[cfg(feature = "std")]
use std::error;

use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::{hash160, ripemd160, sha256, sha256d};
#[cfg(feature = "compiler")]
use {
    crate::descriptor::TapTree,
    crate::miniscript::ScriptContext,
    crate::policy::compiler::CompilerError,
    crate::policy::compiler::OrdF64,
    crate::policy::{compiler, Concrete, Liftable, Semantic},
    crate::Descriptor,
    crate::Miniscript,
    crate::Tap,
    core::cmp::Reverse,
    sync::Arc,
};

use super::ENTAILMENT_MAX_TERMINALS;
use crate::expression::{self, FromTree};
use crate::miniscript::limits::{LOCKTIME_THRESHOLD, SEQUENCE_LOCKTIME_TYPE_FLAG};
use crate::miniscript::types::extra_props::TimelockInfo;
use crate::prelude::*;
use crate::{errstr, Error, ForEach, ForEachKey, MiniscriptKey};

/// Concrete policy which corresponds directly to a Miniscript structure,
/// and whose disjunctions are annotated with satisfaction probabilities
/// to assist the compiler
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Policy<Pk: MiniscriptKey> {
    /// Unsatisfiable
    Unsatisfiable,
    /// Trivially satisfiable
    Trivial,
    /// A public key which must sign to satisfy the descriptor
    Key(Pk),
    /// An absolute locktime restriction
    After(u32),
    /// A relative locktime restriction
    Older(u32),
    /// A SHA256 whose preimage must be provided to satisfy the descriptor
    Sha256(sha256::Hash),
    /// A SHA256d whose preimage must be provided to satisfy the descriptor
    Hash256(sha256d::Hash),
    /// A RIPEMD160 whose preimage must be provided to satisfy the descriptor
    Ripemd160(ripemd160::Hash),
    /// A HASH160 whose preimage must be provided to satisfy the descriptor
    Hash160(hash160::Hash),
    /// A list of sub-policies, all of which must be satisfied
    And(Vec<Policy<Pk>>),
    /// A list of sub-policies, one of which must be satisfied, along with
    /// relative probabilities for each one
    Or(Vec<(usize, Policy<Pk>)>),
    /// A set of descriptors, satisfactions must be provided for `k` of them
    Threshold(usize, Vec<Policy<Pk>>),
}

/// Detailed Error type for Policies
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum PolicyError {
    /// `And` fragments only support two args
    NonBinaryArgAnd,
    /// `Or` fragments only support two args
    NonBinaryArgOr,
    /// `Thresh` fragment can only have `1<=k<=n`
    IncorrectThresh,
    /// `older` or `after` fragment can only have `n = 0`
    ZeroTime,
    /// `after` fragment can only have ` n < 2^31`
    TimeTooFar,
    /// Semantic Policy Error: `And` `Or` fragments must take args: k > 1
    InsufficientArgsforAnd,
    /// Semantic Policy Error: `And` `Or` fragments must take args: k > 1
    InsufficientArgsforOr,
    /// Entailment max terminals exceeded
    EntailmentMaxTerminals,
    /// lifting error: Cannot lift policies that have
    /// a combination of height and timelocks.
    HeightTimelockCombination,
    /// Duplicate Public Keys
    DuplicatePubKeys,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PolicyError::NonBinaryArgAnd => {
                f.write_str("And policy fragment must take 2 arguments")
            }
            PolicyError::NonBinaryArgOr => f.write_str("Or policy fragment must take 2 arguments"),
            PolicyError::IncorrectThresh => {
                f.write_str("Threshold k must be greater than 0 and less than or equal to n 0<k<=n")
            }
            PolicyError::TimeTooFar => {
                f.write_str("Relative/Absolute time must be less than 2^31; n < 2^31")
            }
            PolicyError::ZeroTime => f.write_str("Time must be greater than 0; n > 0"),
            PolicyError::InsufficientArgsforAnd => {
                f.write_str("Semantic Policy 'And' fragment must have at least 2 args ")
            }
            PolicyError::InsufficientArgsforOr => {
                f.write_str("Semantic Policy 'Or' fragment must have at least 2 args ")
            }
            PolicyError::EntailmentMaxTerminals => write!(
                f,
                "Policy entailment only supports {} terminals",
                ENTAILMENT_MAX_TERMINALS
            ),
            PolicyError::HeightTimelockCombination => {
                f.write_str("Cannot lift policies that have a heightlock and timelock combination")
            }
            PolicyError::DuplicatePubKeys => f.write_str("Policy contains duplicate keys"),
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for PolicyError {
    fn cause(&self) -> Option<&dyn error::Error> {
        use self::PolicyError::*;

        match self {
            NonBinaryArgAnd
            | NonBinaryArgOr
            | IncorrectThresh
            | ZeroTime
            | TimeTooFar
            | InsufficientArgsforAnd
            | InsufficientArgsforOr
            | EntailmentMaxTerminals
            | HeightTimelockCombination
            | DuplicatePubKeys => None,
        }
    }
}

impl<Pk: MiniscriptKey> Policy<Pk> {
    /// Flatten the [`Policy`] tree structure into a Vector of tuple `(leaf script, leaf probability)`
    /// with leaf probabilities corresponding to odds for sub-branch in the policy.
    /// We calculate the probability of selecting the sub-branch at every level and calculate the
    /// leaf probabilities as the probability of traversing through required branches to reach the
    /// leaf node, i.e. multiplication of the respective probabilities.
    ///
    /// For example, the policy tree:       OR
    ///                                   /   \
    ///                                  2     1            odds
    ///                                /        \
    ///                               A         OR
    ///                                        /  \
    ///                                       3    1        odds
    ///                                     /       \
    ///                                    B         C
    ///
    /// gives the vector [(2/3, A), (1/3 * 3/4, B), (1/3 * 1/4, C)].
    #[cfg(feature = "compiler")]
    fn to_tapleaf_prob_vec(&self, prob: f64) -> Vec<(f64, Policy<Pk>)> {
        match *self {
            Policy::Or(ref subs) => {
                let total_odds: usize = subs.iter().map(|(ref k, _)| k).sum();
                subs.iter()
                    .map(|(k, ref policy)| {
                        policy.to_tapleaf_prob_vec(prob * *k as f64 / total_odds as f64)
                    })
                    .flatten()
                    .collect::<Vec<_>>()
            }
            Policy::Threshold(k, ref subs) if k == 1 => {
                let total_odds = subs.len();
                subs.iter()
                    .map(|policy| policy.to_tapleaf_prob_vec(prob / total_odds as f64))
                    .flatten()
                    .collect::<Vec<_>>()
            }
            ref x => vec![(prob, x.clone())],
        }
    }

    /// Compile [`Policy::Or`] and [`Policy::Threshold`] according to odds
    #[cfg(feature = "compiler")]
    fn compile_tr_policy(&self) -> Result<TapTree<Pk>, Error> {
        let leaf_compilations: Vec<_> = self
            .to_tapleaf_prob_vec(1.0)
            .into_iter()
            .filter(|x| x.1 != Policy::Unsatisfiable)
            .map(|(prob, ref policy)| (OrdF64(prob), compiler::best_compilation(policy).unwrap()))
            .collect();
        let taptree = with_huffman_tree::<Pk>(leaf_compilations).unwrap();
        Ok(taptree)
    }

    /// Extract the internal_key from policy tree.
    #[cfg(feature = "compiler")]
    fn extract_key(self, unspendable_key: Option<Pk>) -> Result<(Pk, Policy<Pk>), Error> {
        let mut internal_key: Option<Pk> = None;
        {
            let mut prob = 0.;
            let semantic_policy = self.lift()?;
            let concrete_keys = self.keys();
            let key_prob_map: HashMap<_, _> = self
                .to_tapleaf_prob_vec(1.0)
                .into_iter()
                .filter(|(_, ref pol)| match *pol {
                    Concrete::Key(..) => true,
                    _ => false,
                })
                .map(|(prob, key)| (key, prob))
                .collect();

            for key in concrete_keys.into_iter() {
                if semantic_policy
                    .clone()
                    .satisfy_constraint(&Semantic::KeyHash(key.to_pubkeyhash()), true)
                    == Semantic::Trivial
                {
                    match key_prob_map.get(&Concrete::Key(key.clone())) {
                        Some(val) => {
                            if *val > prob {
                                prob = *val;
                                internal_key = Some(key.clone());
                            }
                        }
                        None => return Err(errstr("Key should have existed in the HashMap!")),
                    }
                }
            }
        }
        match (internal_key, unspendable_key) {
            (Some(ref key), _) => Ok((key.clone(), self.translate_unsatisfiable_pk(&key))),
            (_, Some(key)) => Ok((key, self)),
            _ => Err(errstr("No viable internal key found.")),
        }
    }

    /// Compile the [`Policy`] into a [`Tr`][`Descriptor::Tr`] Descriptor.
    ///
    /// ### TapTree compilation
    ///
    /// The policy tree constructed by root-level disjunctions over [`Or`][`Policy::Or`] and
    /// [`Thresh`][`Policy::Threshold`](1, ..) which is flattened into a vector (with respective
    /// probabilities derived from odds) of policies.
    /// For example, the policy `thresh(1,or(pk(A),pk(B)),and(or(pk(C),pk(D)),pk(E)))` gives the vector
    /// `[pk(A),pk(B),and(or(pk(C),pk(D)),pk(E)))]`. Each policy in the vector is compiled into
    /// the respective miniscripts. A Huffman Tree is created from this vector which optimizes over
    /// the probabilitity of satisfaction for the respective branch in the TapTree.
    // TODO: We might require other compile errors for Taproot.
    #[cfg(feature = "compiler")]
    pub fn compile_tr(&self, unspendable_key: Option<Pk>) -> Result<Descriptor<Pk>, Error> {
        self.is_valid()?; // Check for validity
        match self.is_safe_nonmalleable() {
            (false, _) => Err(Error::from(CompilerError::TopLevelNonSafe)),
            (_, false) => Err(Error::from(
                CompilerError::ImpossibleNonMalleableCompilation,
            )),
            _ => {
                let (internal_key, policy) = self.clone().extract_key(unspendable_key)?;
                let tree = Descriptor::new_tr(
                    internal_key,
                    match policy {
                        Policy::Trivial => None,
                        policy => Some(policy.compile_tr_policy()?),
                    },
                )?;
                Ok(tree)
            }
        }
    }

    /// Compile the descriptor into an optimized `Miniscript` representation
    #[cfg(feature = "compiler")]
    pub fn compile<Ctx: ScriptContext>(&self) -> Result<Miniscript<Pk, Ctx>, CompilerError> {
        self.is_valid()?;
        match self.is_safe_nonmalleable() {
            (false, _) => Err(CompilerError::TopLevelNonSafe),
            (_, false) => Err(CompilerError::ImpossibleNonMalleableCompilation),
            _ => compiler::best_compilation(self),
        }
    }
}

impl<Pk: MiniscriptKey> ForEachKey<Pk> for Policy<Pk> {
    fn for_each_key<'a, F: FnMut(ForEach<'a, Pk>) -> bool>(&'a self, mut pred: F) -> bool
    where
        Pk: 'a,
        Pk::Hash: 'a,
    {
        match *self {
            Policy::Unsatisfiable | Policy::Trivial => true,
            Policy::Key(ref pk) => pred(ForEach::Key(pk)),
            Policy::Sha256(..)
            | Policy::Hash256(..)
            | Policy::Ripemd160(..)
            | Policy::Hash160(..)
            | Policy::After(..)
            | Policy::Older(..) => true,
            Policy::Threshold(_, ref subs) | Policy::And(ref subs) => {
                subs.iter().all(|sub| sub.for_each_key(&mut pred))
            }
            Policy::Or(ref subs) => subs.iter().all(|(_, sub)| sub.for_each_key(&mut pred)),
        }
    }
}

impl<Pk: MiniscriptKey> Policy<Pk> {
    /// Convert a policy using one kind of public key to another
    /// type of public key
    ///
    /// # Example
    ///
    /// ```
    /// use miniscript::{bitcoin::PublicKey, policy::concrete::Policy};
    /// use std::str::FromStr;
    /// let alice_key = "0270cf3c71f65a3d93d285d9149fddeeb638f87a2d4d8cf16c525f71c417439777";
    /// let bob_key = "02f43b15c50a436f5335dbea8a64dd3b4e63e34c3b50c42598acb5f4f336b5d2fb";
    /// let placeholder_policy = Policy::<String>::from_str("and(pk(alice_key),pk(bob_key))").unwrap();
    ///
    /// let real_policy = placeholder_policy.translate_pk(|placeholder: &String| match placeholder.as_str() {
    ///     "alice_key" => PublicKey::from_str(alice_key),
    ///     "bob_key"   => PublicKey::from_str(bob_key),
    ///     _ => panic!("unknown key!")
    /// }).unwrap();
    ///
    /// let expected_policy = Policy::from_str(&format!("and(pk({}),pk({}))", alice_key, bob_key)).unwrap();
    /// assert_eq!(real_policy, expected_policy);
    /// ```
    pub fn translate_pk<Fpk, Q, E>(&self, mut fpk: Fpk) -> Result<Policy<Q>, E>
    where
        Fpk: FnMut(&Pk) -> Result<Q, E>,
        Q: MiniscriptKey,
    {
        self._translate_pk(&mut fpk)
    }

    fn _translate_pk<Fpk, Q, E>(&self, fpk: &mut Fpk) -> Result<Policy<Q>, E>
    where
        Fpk: FnMut(&Pk) -> Result<Q, E>,
        Q: MiniscriptKey,
    {
        match *self {
            Policy::Unsatisfiable => Ok(Policy::Unsatisfiable),
            Policy::Trivial => Ok(Policy::Trivial),
            Policy::Key(ref pk) => fpk(pk).map(Policy::Key),
            Policy::Sha256(ref h) => Ok(Policy::Sha256(*h)),
            Policy::Hash256(ref h) => Ok(Policy::Hash256(*h)),
            Policy::Ripemd160(ref h) => Ok(Policy::Ripemd160(*h)),
            Policy::Hash160(ref h) => Ok(Policy::Hash160(*h)),
            Policy::After(n) => Ok(Policy::After(n)),
            Policy::Older(n) => Ok(Policy::Older(n)),
            Policy::Threshold(k, ref subs) => {
                let new_subs: Result<Vec<Policy<Q>>, _> =
                    subs.iter().map(|sub| sub._translate_pk(fpk)).collect();
                new_subs.map(|ok| Policy::Threshold(k, ok))
            }
            Policy::And(ref subs) => Ok(Policy::And(
                subs.iter()
                    .map(|sub| sub._translate_pk(fpk))
                    .collect::<Result<Vec<Policy<Q>>, E>>()?,
            )),
            Policy::Or(ref subs) => Ok(Policy::Or(
                subs.iter()
                    .map(|&(ref prob, ref sub)| Ok((*prob, sub._translate_pk(fpk)?)))
                    .collect::<Result<Vec<(usize, Policy<Q>)>, E>>()?,
            )),
        }
    }

    /// Translate `Concrete::Key(key)` to `Concrete::Unsatisfiable` when extracting TapKey
    pub fn translate_unsatisfiable_pk(self, key: &Pk) -> Policy<Pk> {
        match self {
            Policy::Key(ref k) if k.clone() == *key => Policy::Unsatisfiable,
            Policy::And(subs) => Policy::And(
                subs.into_iter()
                    .map(|sub| sub.translate_unsatisfiable_pk(key))
                    .collect::<Vec<_>>(),
            ),
            Policy::Or(subs) => Policy::Or(
                subs.into_iter()
                    .map(|(k, sub)| (k, sub.translate_unsatisfiable_pk(key)))
                    .collect::<Vec<_>>(),
            ),
            Policy::Threshold(k, subs) => Policy::Threshold(
                k,
                subs.into_iter()
                    .map(|sub| sub.translate_unsatisfiable_pk(key))
                    .collect::<Vec<_>>(),
            ),
            x => x,
        }
    }

    /// Get all keys in the policy
    pub fn keys(&self) -> Vec<&Pk> {
        match *self {
            Policy::Key(ref pk) => vec![pk],
            Policy::Threshold(_k, ref subs) => {
                subs.iter().flat_map(|sub| sub.keys()).collect::<Vec<_>>()
            }
            Policy::And(ref subs) => subs.iter().flat_map(|sub| sub.keys()).collect::<Vec<_>>(),
            Policy::Or(ref subs) => subs
                .iter()
                .flat_map(|(ref _k, ref sub)| sub.keys())
                .collect::<Vec<_>>(),
            // map all hashes and time
            _ => vec![],
        }
    }

    /// Check whether the policy contains duplicate public keys
    pub fn check_duplicate_keys(&self) -> Result<(), PolicyError> {
        let pks = self.keys();
        let pks_len = pks.len();
        let unique_pks_len = pks.into_iter().collect::<HashSet<_>>().len();

        if pks_len > unique_pks_len {
            Err(PolicyError::DuplicatePubKeys)
        } else {
            Ok(())
        }
    }

    /// Checks whether the given concrete policy contains a combination of
    /// timelocks and heightlocks.
    /// Returns an error if there is at least one satisfaction that contains
    /// a combination of hieghtlock and timelock.
    pub fn check_timelocks(&self) -> Result<(), PolicyError> {
        let timelocks = self.check_timelocks_helper();
        if timelocks.contains_combination {
            Err(PolicyError::HeightTimelockCombination)
        } else {
            Ok(())
        }
    }

    // Checks whether the given concrete policy contains a combination of
    // timelocks and heightlocks
    fn check_timelocks_helper(&self) -> TimelockInfo {
        // timelocks[csv_h, csv_t, cltv_h, cltv_t, combination]
        match *self {
            Policy::Unsatisfiable
            | Policy::Trivial
            | Policy::Key(_)
            | Policy::Sha256(_)
            | Policy::Hash256(_)
            | Policy::Ripemd160(_)
            | Policy::Hash160(_) => TimelockInfo::default(),
            Policy::After(t) => TimelockInfo {
                csv_with_height: false,
                csv_with_time: false,
                cltv_with_height: t < LOCKTIME_THRESHOLD,
                cltv_with_time: t >= LOCKTIME_THRESHOLD,
                contains_combination: false,
            },
            Policy::Older(t) => TimelockInfo {
                csv_with_height: (t & SEQUENCE_LOCKTIME_TYPE_FLAG) == 0,
                csv_with_time: (t & SEQUENCE_LOCKTIME_TYPE_FLAG) != 0,
                cltv_with_height: false,
                cltv_with_time: false,
                contains_combination: false,
            },
            Policy::Threshold(k, ref subs) => {
                let iter = subs.iter().map(|sub| sub.check_timelocks_helper());
                TimelockInfo::combine_threshold(k, iter)
            }
            Policy::And(ref subs) => {
                let iter = subs.iter().map(|sub| sub.check_timelocks_helper());
                TimelockInfo::combine_threshold(subs.len(), iter)
            }
            Policy::Or(ref subs) => {
                let iter = subs
                    .iter()
                    .map(|&(ref _p, ref sub)| sub.check_timelocks_helper());
                TimelockInfo::combine_threshold(1, iter)
            }
        }
    }

    /// This returns whether the given policy is valid or not. It maybe possible that the policy
    /// contains Non-two argument `and`, `or` or a `0` arg thresh.
    /// Validity condition also checks whether there is a possible satisfaction
    /// combination of timelocks and heightlocks
    pub fn is_valid(&self) -> Result<(), PolicyError> {
        self.check_timelocks()?;
        self.check_duplicate_keys()?;
        match *self {
            Policy::And(ref subs) => {
                if subs.len() != 2 {
                    Err(PolicyError::NonBinaryArgAnd)
                } else {
                    subs.iter()
                        .map(|sub| sub.is_valid())
                        .collect::<Result<Vec<()>, PolicyError>>()?;
                    Ok(())
                }
            }
            Policy::Or(ref subs) => {
                if subs.len() != 2 {
                    Err(PolicyError::NonBinaryArgOr)
                } else {
                    subs.iter()
                        .map(|&(ref _prob, ref sub)| sub.is_valid())
                        .collect::<Result<Vec<()>, PolicyError>>()?;
                    Ok(())
                }
            }
            Policy::Threshold(k, ref subs) => {
                if k == 0 || k > subs.len() {
                    Err(PolicyError::IncorrectThresh)
                } else {
                    subs.iter()
                        .map(|sub| sub.is_valid())
                        .collect::<Result<Vec<()>, PolicyError>>()?;
                    Ok(())
                }
            }
            Policy::After(n) | Policy::Older(n) => {
                if n == 0 {
                    Err(PolicyError::ZeroTime)
                } else if n > 2u32.pow(31) {
                    Err(PolicyError::TimeTooFar)
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
        }
    }
    /// This returns whether any possible compilation of the policy could be
    /// compiled as non-malleable and safe. Note that this returns a tuple
    /// (safe, non-malleable) to avoid because the non-malleability depends on
    /// safety and we would like to cache results.
    ///
    pub fn is_safe_nonmalleable(&self) -> (bool, bool) {
        match *self {
            Policy::Unsatisfiable | Policy::Trivial => (true, true),
            Policy::Key(_) => (true, true),
            Policy::Sha256(_)
            | Policy::Hash256(_)
            | Policy::Ripemd160(_)
            | Policy::Hash160(_)
            | Policy::After(_)
            | Policy::Older(_) => (false, true),
            Policy::Threshold(k, ref subs) => {
                let (safe_count, non_mall_count) = subs
                    .iter()
                    .map(|sub| sub.is_safe_nonmalleable())
                    .fold((0, 0), |(safe_count, non_mall_count), (safe, non_mall)| {
                        (
                            safe_count + safe as usize,
                            non_mall_count + non_mall as usize,
                        )
                    });
                (
                    safe_count >= (subs.len() - k + 1),
                    non_mall_count == subs.len() && safe_count >= (subs.len() - k),
                )
            }
            Policy::And(ref subs) => {
                let (atleast_one_safe, all_non_mall) = subs
                    .iter()
                    .map(|sub| sub.is_safe_nonmalleable())
                    .fold((false, true), |acc, x| (acc.0 || x.0, acc.1 && x.1));
                (atleast_one_safe, all_non_mall)
            }

            Policy::Or(ref subs) => {
                let (all_safe, atleast_one_safe, all_non_mall) = subs
                    .iter()
                    .map(|&(_, ref sub)| sub.is_safe_nonmalleable())
                    .fold((true, false, true), |acc, x| {
                        (acc.0 && x.0, acc.1 || x.0, acc.2 && x.1)
                    });
                (all_safe, atleast_one_safe && all_non_mall)
            }
        }
    }
}

impl<Pk: MiniscriptKey> fmt::Debug for Policy<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Policy::Unsatisfiable => f.write_str("UNSATISFIABLE()"),
            Policy::Trivial => f.write_str("TRIVIAL()"),
            Policy::Key(ref pk) => write!(f, "pk({:?})", pk),
            Policy::After(n) => write!(f, "after({})", n),
            Policy::Older(n) => write!(f, "older({})", n),
            Policy::Sha256(h) => write!(f, "sha256({})", h),
            Policy::Hash256(h) => write!(f, "hash256({})", h),
            Policy::Ripemd160(h) => write!(f, "ripemd160({})", h),
            Policy::Hash160(h) => write!(f, "hash160({})", h),
            Policy::And(ref subs) => {
                f.write_str("and(")?;
                if !subs.is_empty() {
                    write!(f, "{:?}", subs[0])?;
                    for sub in &subs[1..] {
                        write!(f, ",{:?}", sub)?;
                    }
                }
                f.write_str(")")
            }
            Policy::Or(ref subs) => {
                f.write_str("or(")?;
                if !subs.is_empty() {
                    write!(f, "{}@{:?}", subs[0].0, subs[0].1)?;
                    for sub in &subs[1..] {
                        write!(f, ",{}@{:?}", sub.0, sub.1)?;
                    }
                }
                f.write_str(")")
            }
            Policy::Threshold(k, ref subs) => {
                write!(f, "thresh({}", k)?;
                for sub in subs {
                    write!(f, ",{:?}", sub)?;
                }
                f.write_str(")")
            }
        }
    }
}

impl<Pk: MiniscriptKey> fmt::Display for Policy<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Policy::Unsatisfiable => f.write_str("UNSATISFIABLE"),
            Policy::Trivial => f.write_str("TRIVIAL"),
            Policy::Key(ref pk) => write!(f, "pk({})", pk),
            Policy::After(n) => write!(f, "after({})", n),
            Policy::Older(n) => write!(f, "older({})", n),
            Policy::Sha256(h) => write!(f, "sha256({})", h),
            Policy::Hash256(h) => write!(f, "hash256({})", h),
            Policy::Ripemd160(h) => write!(f, "ripemd160({})", h),
            Policy::Hash160(h) => write!(f, "hash160({})", h),
            Policy::And(ref subs) => {
                f.write_str("and(")?;
                if !subs.is_empty() {
                    write!(f, "{}", subs[0])?;
                    for sub in &subs[1..] {
                        write!(f, ",{}", sub)?;
                    }
                }
                f.write_str(")")
            }
            Policy::Or(ref subs) => {
                f.write_str("or(")?;
                if !subs.is_empty() {
                    write!(f, "{}@{}", subs[0].0, subs[0].1)?;
                    for sub in &subs[1..] {
                        write!(f, ",{}@{}", sub.0, sub.1)?;
                    }
                }
                f.write_str(")")
            }
            Policy::Threshold(k, ref subs) => {
                write!(f, "thresh({}", k)?;
                for sub in subs {
                    write!(f, ",{}", sub)?;
                }
                f.write_str(")")
            }
        }
    }
}

impl_from_str!(
    Policy<Pk>,
    type Err = Error;,
    fn from_str(s: &str) -> Result<Policy<Pk>, Error> {
        for ch in s.as_bytes() {
            if *ch < 20 || *ch > 127 {
                return Err(Error::Unprintable(*ch));
            }
        }

        let tree = expression::Tree::from_str(s)?;
        let policy: Policy<Pk> = FromTree::from_tree(&tree)?;
        policy.check_timelocks()?;
        Ok(policy)
    }
);

serde_string_impl_pk!(Policy, "a miniscript concrete policy");

#[rustfmt::skip]
impl_block_str!(
    Policy<Pk>,
    /// Helper function for `from_tree` to parse subexpressions with
    /// names of the form x@y
    fn from_tree_prob(top: &expression::Tree, allow_prob: bool,)
        -> Result<(usize, Policy<Pk>), Error>
    {
        let frag_prob;
        let frag_name;
        let mut name_split = top.name.split('@');
        match (name_split.next(), name_split.next(), name_split.next()) {
            (None, _, _) => {
                frag_prob = 1;
                frag_name = "";
            }
            (Some(name), None, _) => {
                frag_prob = 1;
                frag_name = name;
            }
            (Some(prob), Some(name), None) => {
                if !allow_prob {
                    return Err(Error::AtOutsideOr(top.name.to_owned()));
                }
                frag_prob = expression::parse_num(prob)? as usize;
                frag_name = name;
            }
            (Some(_), Some(_), Some(_)) => {
                return Err(Error::MultiColon(top.name.to_owned()));
            }
        }
        match (frag_name, top.args.len() as u32) {
            ("UNSATISFIABLE", 0) => Ok(Policy::Unsatisfiable),
            ("TRIVIAL", 0) => Ok(Policy::Trivial),
            ("pk", 1) => expression::terminal(&top.args[0], |pk| Pk::from_str(pk).map(Policy::Key)),
            ("after", 1) => {
                let num = expression::terminal(&top.args[0], expression::parse_num)?;
                if num > 2u32.pow(31) {
                    return Err(Error::PolicyError(PolicyError::TimeTooFar));
                } else if num == 0 {
                    return Err(Error::PolicyError(PolicyError::ZeroTime));
                }
                Ok(Policy::After(num))
            }
            ("older", 1) => {
                let num = expression::terminal(&top.args[0], expression::parse_num)?;
                if num > 2u32.pow(31) {
                    return Err(Error::PolicyError(PolicyError::TimeTooFar));
                } else if num == 0 {
                    return Err(Error::PolicyError(PolicyError::ZeroTime));
                }
                Ok(Policy::Older(num))
            }
            ("sha256", 1) => expression::terminal(&top.args[0], |x| {
                sha256::Hash::from_hex(x).map(Policy::Sha256)
            }),
            ("hash256", 1) => expression::terminal(&top.args[0], |x| {
                sha256d::Hash::from_hex(x).map(Policy::Hash256)
            }),
            ("ripemd160", 1) => expression::terminal(&top.args[0], |x| {
                ripemd160::Hash::from_hex(x).map(Policy::Ripemd160)
            }),
            ("hash160", 1) => expression::terminal(&top.args[0], |x| {
                hash160::Hash::from_hex(x).map(Policy::Hash160)
            }),
            ("and", _) => {
                if top.args.len() != 2 {
                    return Err(Error::PolicyError(PolicyError::NonBinaryArgAnd));
                }
                let mut subs = Vec::with_capacity(top.args.len());
                for arg in &top.args {
                    subs.push(Policy::from_tree(arg)?);
                }
                Ok(Policy::And(subs))
            }
            ("or", _) => {
                if top.args.len() != 2 {
                    return Err(Error::PolicyError(PolicyError::NonBinaryArgOr));
                }
                let mut subs = Vec::with_capacity(top.args.len());
                for arg in &top.args {
                    subs.push(Policy::from_tree_prob(arg, true)?);
                }
                Ok(Policy::Or(subs))
            }
            ("thresh", nsubs) => {
                if top.args.is_empty() || !top.args[0].args.is_empty() {
                    return Err(Error::PolicyError(PolicyError::IncorrectThresh));
                }

                let thresh = expression::parse_num(top.args[0].name)?;
                if thresh >= nsubs || thresh == 0 {
                    return Err(Error::PolicyError(PolicyError::IncorrectThresh));
                }

                let mut subs = Vec::with_capacity(top.args.len() - 1);
                for arg in &top.args[1..] {
                    subs.push(Policy::from_tree(arg)?);
                }
                Ok(Policy::Threshold(thresh as usize, subs))
            }
            _ => Err(errstr(top.name)),
        }
        .map(|res| (frag_prob, res))
    }
);

impl_from_tree!(
    Policy<Pk>,
    fn from_tree(top: &expression::Tree) -> Result<Policy<Pk>, Error> {
        Policy::from_tree_prob(top, false).map(|(_, result)| result)
    }
);

/// Create a Huffman Tree from compiled [Miniscript] nodes
#[cfg(feature = "compiler")]
fn with_huffman_tree<Pk: MiniscriptKey>(
    ms: Vec<(OrdF64, Miniscript<Pk, Tap>)>,
) -> Result<TapTree<Pk>, Error> {
    let mut node_weights = BinaryHeap::<(Reverse<OrdF64>, TapTree<Pk>)>::new();
    for (prob, script) in ms {
        node_weights.push((Reverse(prob), TapTree::Leaf(Arc::new(script))));
    }
    if node_weights.is_empty() {
        return Err(errstr("Empty Miniscript compilation"));
    }
    while node_weights.len() > 1 {
        let (p1, s1) = node_weights.pop().expect("len must atleast be two");
        let (p2, s2) = node_weights.pop().expect("len must atleast be two");

        let p = (p1.0).0 + (p2.0).0;
        node_weights.push((
            Reverse(OrdF64(p)),
            TapTree::Tree(Arc::from(s1), Arc::from(s2)),
        ));
    }

    debug_assert!(node_weights.len() == 1);
    let node = node_weights
        .pop()
        .expect("huffman tree algorithm is broken")
        .1;
    Ok(node)
}
