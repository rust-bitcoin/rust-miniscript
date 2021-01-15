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

use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::{hash160, ripemd160, sha256, sha256d};
use std::collections::HashSet;
use std::{error, fmt, str};

use super::ENTAILMENT_MAX_TERMINALS;
use errstr;
use expression::{self, FromTree};
use miniscript::limits::{HEIGHT_TIME_THRESHOLD, SEQUENCE_LOCKTIME_TYPE_FLAG};
use miniscript::types::extra_props::TimeLockInfo;
#[cfg(feature = "compiler")]
use miniscript::ScriptContext;
#[cfg(feature = "compiler")]
use policy::compiler;
#[cfg(feature = "compiler")]
use policy::compiler::CompilerError;
#[cfg(feature = "compiler")]
use Miniscript;
use {Error, ForEach, ForEachKey, MiniscriptKey};
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
    /// A SHA256 whose must match the tx template
    TxTemplate(sha256::Hash),
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
    HeightTimeLockCombination,
    /// Duplicate Public Keys
    DuplicatePubKeys,
}

impl error::Error for PolicyError {}

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
            PolicyError::HeightTimeLockCombination => {
                f.write_str("Cannot lift policies that have a heightlock and timelock combination")
            }
            PolicyError::DuplicatePubKeys => f.write_str("Policy contains duplicate keys"),
        }
    }
}

impl<Pk: MiniscriptKey> Policy<Pk> {
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
            | Policy::Older(..)
            | Policy::TxTemplate(..) => true,
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
    pub fn translate_pk<Fpk, Q, E>(&self, mut translatefpk: Fpk) -> Result<Policy<Q>, E>
    where
        Fpk: FnMut(&Pk) -> Result<Q, E>,
        Q: MiniscriptKey,
    {
        self._translate_pk(&mut translatefpk)
    }

    fn _translate_pk<Fpk, Q, E>(&self, translatefpk: &mut Fpk) -> Result<Policy<Q>, E>
    where
        Fpk: FnMut(&Pk) -> Result<Q, E>,
        Q: MiniscriptKey,
    {
        match *self {
            Policy::Unsatisfiable => Ok(Policy::Unsatisfiable),
            Policy::Trivial => Ok(Policy::Trivial),
            Policy::Key(ref pk) => translatefpk(pk).map(Policy::Key),
            Policy::Sha256(ref h) => Ok(Policy::Sha256(h.clone())),
            Policy::Hash256(ref h) => Ok(Policy::Hash256(h.clone())),
            Policy::Ripemd160(ref h) => Ok(Policy::Ripemd160(h.clone())),
            Policy::Hash160(ref h) => Ok(Policy::Hash160(h.clone())),
            Policy::After(n) => Ok(Policy::After(n)),
            Policy::Older(n) => Ok(Policy::Older(n)),
            Policy::Threshold(k, ref subs) => {
                let new_subs: Result<Vec<Policy<Q>>, _> = subs
                    .iter()
                    .map(|sub| sub._translate_pk(translatefpk))
                    .collect();
                new_subs.map(|ok| Policy::Threshold(k, ok))
            }
            Policy::And(ref subs) => Ok(Policy::And(
                subs.iter()
                    .map(|sub| sub._translate_pk(translatefpk))
                    .collect::<Result<Vec<Policy<Q>>, E>>()?,
            )),
            Policy::Or(ref subs) => Ok(Policy::Or(
                subs.iter()
                    .map(|&(ref prob, ref sub)| Ok((*prob, sub._translate_pk(translatefpk)?)))
                    .collect::<Result<Vec<(usize, Policy<Q>)>, E>>()?,
            )),
            Policy::TxTemplate(ref h) => Ok(Policy::TxTemplate(h.clone())),
        }
    }

    /// Get all keys in the policy
    pub fn keys(&self) -> Vec<&Pk> {
        match *self {
            Policy::Key(ref pk) => vec![pk],
            Policy::Threshold(_k, ref subs) => subs
                .iter()
                .map(|sub| sub.keys())
                .flatten()
                .collect::<Vec<_>>(),
            Policy::And(ref subs) => subs
                .iter()
                .map(|sub| sub.keys())
                .flatten()
                .collect::<Vec<_>>(),
            Policy::Or(ref subs) => subs
                .iter()
                .map(|(ref _k, ref sub)| sub.keys())
                .flatten()
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
            Err(PolicyError::HeightTimeLockCombination)
        } else {
            Ok(())
        }
    }

    // Checks whether the given concrete policy contains a combination of
    // timelocks and heightlocks
    fn check_timelocks_helper(&self) -> TimeLockInfo {
        // timelocks[csv_h, csv_t, cltv_h, cltv_t, combination]
        match *self {
            Policy::Unsatisfiable
            | Policy::Trivial
            | Policy::Key(_)
            | Policy::Sha256(_)
            | Policy::Hash256(_)
            | Policy::Ripemd160(_)
            // TODO: Correct this to be accurate
            | Policy::TxTemplate(_)
            | Policy::Hash160(_) => TimeLockInfo::default(),
            Policy::After(t) => TimeLockInfo {
                csv_with_height: false,
                csv_with_time: false,
                cltv_with_height: t < HEIGHT_TIME_THRESHOLD,
                cltv_with_time: t >= HEIGHT_TIME_THRESHOLD,
                contains_combination: false,
            },
            Policy::Older(t) => TimeLockInfo {
                csv_with_height: (t & SEQUENCE_LOCKTIME_TYPE_FLAG) == 0,
                csv_with_time: (t & SEQUENCE_LOCKTIME_TYPE_FLAG) != 0,
                cltv_with_height: false,
                cltv_with_time: false,
                contains_combination: false,
            },
            Policy::Threshold(k, ref subs) => {
                let iter = subs.iter().map(|sub| sub.check_timelocks_helper());
                TimeLockInfo::combine_thresh_timelocks(k, iter)
            }
            Policy::And(ref subs) => {
                let iter = subs.iter().map(|sub| sub.check_timelocks_helper());
                TimeLockInfo::combine_thresh_timelocks(subs.len(), iter)
            }
            Policy::Or(ref subs) => {
                let iter = subs
                    .iter()
                    .map(|&(ref _p, ref sub)| sub.check_timelocks_helper());
                TimeLockInfo::combine_thresh_timelocks(1, iter)
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
                if k <= 0 || k > subs.len() {
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
            Policy::TxTemplate(_) => (true, true),
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
            Policy::TxTemplate(h) => write!(f, "txtmpl({})", h),
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
            Policy::TxTemplate(h) => write!(f, "txtmpl({})", h),
        }
    }
}

impl<Pk> str::FromStr for Policy<Pk>
where
    Pk: MiniscriptKey + str::FromStr,
    Pk::Hash: str::FromStr,
    <Pk as str::FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as str::FromStr>::Err: ToString,
{
    type Err = Error;

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
}

serde_string_impl_pk!(Policy, "a miniscript concrete policy");

impl<Pk> Policy<Pk>
where
    Pk: MiniscriptKey + str::FromStr,
    Pk::Hash: str::FromStr,
    <Pk as str::FromStr>::Err: ToString,
{
    /// Helper function for `from_tree` to parse subexpressions with
    /// names of the form x@y
    fn from_tree_prob(
        top: &expression::Tree,
        allow_prob: bool,
    ) -> Result<(usize, Policy<Pk>), Error> {
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
                let num = expression::terminal(&top.args[0], |x| expression::parse_num(x))?;
                if num > 2u32.pow(31) {
                    return Err(Error::PolicyError(PolicyError::TimeTooFar));
                } else if num == 0 {
                    return Err(Error::PolicyError(PolicyError::ZeroTime));
                }
                Ok(Policy::After(num))
            }
            ("older", 1) => {
                let num = expression::terminal(&top.args[0], |x| expression::parse_num(x))?;
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
                if thresh >= nsubs || thresh <= 0 {
                    return Err(Error::PolicyError(PolicyError::IncorrectThresh));
                }

                let mut subs = Vec::with_capacity(top.args.len() - 1);
                for arg in &top.args[1..] {
                    subs.push(Policy::from_tree(arg)?);
                }
                Ok(Policy::Threshold(thresh as usize, subs))
            }
            ("txtmpl", 1) => expression::terminal(&top.args[0], |x| {
                sha256::Hash::from_hex(x).map(Policy::TxTemplate)
            }),
            _ => Err(errstr(top.name)),
        }
        .map(|res| (frag_prob, res))
    }
}

impl<Pk> FromTree for Policy<Pk>
where
    Pk: MiniscriptKey + str::FromStr,
    Pk::Hash: str::FromStr,
    <Pk as str::FromStr>::Err: ToString,
{
    fn from_tree(top: &expression::Tree) -> Result<Policy<Pk>, Error> {
        Policy::from_tree_prob(top, false).map(|(_, result)| result)
    }
}
