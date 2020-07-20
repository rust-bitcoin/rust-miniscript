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

//! Abstract Policies

use std::str::FromStr;
use std::{fmt, str};

use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::{hash160, ripemd160, sha256, sha256d};

use super::concrete::PolicyError;
use errstr;
use Error;
use {expression, MiniscriptKey};

/// Abstract policy which corresponds to the semantics of a Miniscript
/// and which allows complex forms of analysis, e.g. filtering and
/// normalization.
/// Semantic policies store only hashes of keys to ensure that objects
/// representing the same policy are lifted to the same `Semantic`,
/// regardless of their choice of `pk` or `pk_h` nodes.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Policy<Pk: MiniscriptKey> {
    /// Unsatisfiable
    Unsatisfiable,
    /// Trivially satisfiable
    Trivial,
    /// Signature and public key matching a given hash is required
    KeyHash(Pk::Hash),
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
    /// A list of sub-policies, one of which must be satisfied
    Or(Vec<Policy<Pk>>),
    /// A set of descriptors, satisfactions must be provided for `k` of them
    Threshold(usize, Vec<Policy<Pk>>),
}

impl<Pk: MiniscriptKey> Policy<Pk> {
    /// Convert a policy using one kind of public key to another
    /// type of public key
    pub fn translate_pkh<Fpkh, Q, E>(&self, mut translatefpkh: Fpkh) -> Result<Policy<Q>, E>
    where
        Fpkh: FnMut(&Pk::Hash) -> Result<Q::Hash, E>,
        Q: MiniscriptKey,
    {
        match *self {
            Policy::Unsatisfiable => Ok(Policy::Unsatisfiable),
            Policy::Trivial => Ok(Policy::Trivial),
            Policy::KeyHash(ref pkh) => translatefpkh(pkh).map(Policy::KeyHash),
            Policy::Sha256(ref h) => Ok(Policy::Sha256(h.clone())),
            Policy::Hash256(ref h) => Ok(Policy::Hash256(h.clone())),
            Policy::Ripemd160(ref h) => Ok(Policy::Ripemd160(h.clone())),
            Policy::Hash160(ref h) => Ok(Policy::Hash160(h.clone())),
            Policy::After(n) => Ok(Policy::After(n)),
            Policy::Older(n) => Ok(Policy::Older(n)),
            Policy::Threshold(k, ref subs) => {
                let new_subs: Result<Vec<Policy<Q>>, _> = subs
                    .iter()
                    .map(|sub| sub.translate_pkh(&mut translatefpkh))
                    .collect();
                new_subs.map(|ok| Policy::Threshold(k, ok))
            }
            Policy::And(ref subs) => Ok(Policy::And(
                subs.iter()
                    .map(|sub| sub.translate_pkh(&mut translatefpkh))
                    .collect::<Result<Vec<Policy<Q>>, E>>()?,
            )),
            Policy::Or(ref subs) => Ok(Policy::Or(
                subs.iter()
                    .map(|sub| sub.translate_pkh(&mut translatefpkh))
                    .collect::<Result<Vec<Policy<Q>>, E>>()?,
            )),
        }
    }
}

impl<Pk: MiniscriptKey> fmt::Debug for Policy<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Policy::Unsatisfiable => f.write_str("UNSATISFIABLE()"),
            Policy::Trivial => f.write_str("TRIVIAL()"),
            Policy::KeyHash(ref pkh) => write!(f, "pkh({:?})", pkh),
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
                    write!(f, "{:?}", subs[0])?;
                    for sub in &subs[1..] {
                        write!(f, ",{:?}", sub)?;
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
            Policy::KeyHash(ref pkh) => write!(f, "pkh({})", pkh),
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
                    write!(f, "{}", subs[0])?;
                    for sub in &subs[1..] {
                        write!(f, ",{}", sub)?;
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

impl<Pk> str::FromStr for Policy<Pk>
where
    Pk: MiniscriptKey,
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
        expression::FromTree::from_tree(&tree)
    }
}

serde_string_impl_pk!(Policy, "a miniscript semantic policy");

impl<Pk> expression::FromTree for Policy<Pk>
where
    Pk: MiniscriptKey,
    <Pk as str::FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as str::FromStr>::Err: ToString,
{
    fn from_tree(top: &expression::Tree) -> Result<Policy<Pk>, Error> {
        match (top.name, top.args.len() as u32) {
            ("UNSATISFIABLE", 0) => Ok(Policy::Unsatisfiable),
            ("TRIVIAL", 0) => Ok(Policy::Trivial),
            ("pkh", 1) => expression::terminal(&top.args[0], |pk| {
                Pk::Hash::from_str(pk).map(Policy::KeyHash)
            }),
            ("after", 1) => expression::terminal(&top.args[0], |x| {
                expression::parse_num(x).map(Policy::After)
            }),
            ("older", 1) => expression::terminal(&top.args[0], |x| {
                expression::parse_num(x).map(Policy::Older)
            }),
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
                    subs.push(Policy::from_tree(arg)?);
                }
                Ok(Policy::Or(subs))
            }
            ("thresh", nsubs) => {
                if nsubs == 0 {
                    return Err(errstr("thresh without args"));
                }
                if !top.args[0].args.is_empty() {
                    return Err(errstr(top.args[0].args[0].name));
                }

                let thresh = expression::parse_num(top.args[0].name)?;
                if thresh >= nsubs {
                    return Err(errstr(top.args[0].name));
                }

                let mut subs = Vec::with_capacity(top.args.len() - 1);
                for arg in &top.args[1..] {
                    subs.push(Policy::from_tree(arg)?);
                }
                Ok(Policy::Threshold(thresh as usize, subs))
            }
            _ => Err(errstr(top.name)),
        }
    }
}

impl<Pk: MiniscriptKey> Policy<Pk> {
    /// Flatten out trees of `And`s and `Or`s; eliminate `Trivial` and
    /// `Unsatisfiable`s. Does not reorder any branches; use `.sort`.
    pub fn normalized(self) -> Policy<Pk> {
        match self {
            Policy::And(subs) => {
                let mut ret_subs = Vec::with_capacity(subs.len());
                for sub in subs {
                    match sub.normalized() {
                        Policy::Trivial => {}
                        Policy::Unsatisfiable => return Policy::Unsatisfiable,
                        Policy::And(and_subs) => ret_subs.extend(and_subs),
                        x => ret_subs.push(x),
                    }
                }
                match ret_subs.len() {
                    0 => Policy::Trivial,
                    1 => ret_subs.pop().unwrap(),
                    _ => Policy::And(ret_subs),
                }
            }
            Policy::Or(subs) => {
                let mut ret_subs = Vec::with_capacity(subs.len());
                for sub in subs {
                    match sub {
                        Policy::Trivial => return Policy::Trivial,
                        Policy::Unsatisfiable => {}
                        Policy::Or(or_subs) => ret_subs.extend(or_subs),
                        x => ret_subs.push(x),
                    }
                }
                match ret_subs.len() {
                    0 => Policy::Trivial,
                    1 => ret_subs.pop().unwrap(),
                    _ => Policy::Or(ret_subs),
                }
            }
            x => x,
        }
    }

    /// Helper function to detect a true/trivial policy
    pub fn is_trivial(&self) -> bool {
        match *self {
            Policy::Trivial => true,
            _ => false,
        }
    }

    /// Helper function to detect a false/unsatisfiable policy
    pub fn is_unsatisfiable(&self) -> bool {
        match *self {
            Policy::Unsatisfiable => true,
            _ => false,
        }
    }

    /// Helper function to do the recursion in `timelocks`.
    fn real_relative_timelocks(&self) -> Vec<u32> {
        match *self {
            Policy::Unsatisfiable
            | Policy::Trivial
            | Policy::KeyHash(..)
            | Policy::Sha256(..)
            | Policy::Hash256(..)
            | Policy::Ripemd160(..)
            | Policy::Hash160(..) => vec![],
            Policy::After(..) => vec![],
            Policy::Older(t) => vec![t],
            Policy::And(ref subs) | Policy::Threshold(_, ref subs) => {
                subs.iter().fold(vec![], |mut acc, x| {
                    acc.extend(x.real_relative_timelocks());
                    acc
                })
            }
            Policy::Or(ref subs) => subs.iter().fold(vec![], |mut acc, x| {
                acc.extend(x.real_relative_timelocks());
                acc
            }),
        }
    }

    /// Returns a list of all relative timelocks, not including 0,
    /// which appear in the policy
    pub fn relative_timelocks(&self) -> Vec<u32> {
        let mut ret = self.real_relative_timelocks();
        ret.sort();
        ret.dedup();
        ret
    }

    /// Filter a policy by eliminating relative timelock constraints
    /// that are not satisfied at the given age.
    pub fn at_age(mut self, time: u32) -> Policy<Pk> {
        self = match self {
            Policy::Older(t) => {
                if t > time {
                    Policy::Unsatisfiable
                } else {
                    Policy::Older(t)
                }
            }
            Policy::And(subs) => {
                Policy::And(subs.into_iter().map(|sub| sub.at_age(time)).collect())
            }
            Policy::Or(subs) => Policy::Or(subs.into_iter().map(|sub| sub.at_age(time)).collect()),
            Policy::Threshold(k, subs) => {
                Policy::Threshold(k, subs.into_iter().map(|sub| sub.at_age(time)).collect())
            }
            x => x,
        };
        self.normalized()
    }

    /// Count the number of public keys and keyhashes referenced in a policy.
    /// Duplicate keys will be double-counted.
    pub fn n_keys(&self) -> usize {
        match *self {
            Policy::Unsatisfiable | Policy::Trivial => 0,
            Policy::KeyHash(..) => 1,
            Policy::After(..)
            | Policy::Older(..)
            | Policy::Sha256(..)
            | Policy::Hash256(..)
            | Policy::Ripemd160(..)
            | Policy::Hash160(..) => 0,
            Policy::And(ref subs) | Policy::Threshold(_, ref subs) => {
                subs.iter().map(|sub| sub.n_keys()).sum::<usize>()
            }
            Policy::Or(ref subs) => subs.iter().map(|sub| sub.n_keys()).sum::<usize>(),
        }
    }

    /// Count the minimum number of public keys for which signatures
    /// could be used to satisfy the policy.
    pub fn minimum_n_keys(&self) -> usize {
        match *self {
            Policy::Unsatisfiable | Policy::Trivial => 0,
            Policy::KeyHash(..) => 1,
            Policy::After(..)
            | Policy::Older(..)
            | Policy::Sha256(..)
            | Policy::Hash256(..)
            | Policy::Ripemd160(..)
            | Policy::Hash160(..) => 0,
            Policy::And(ref subs) => subs.iter().map(Policy::minimum_n_keys).sum(),
            Policy::Or(ref subs) => subs.iter().map(Policy::minimum_n_keys).min().unwrap_or(0),
            Policy::Threshold(k, ref subs) => {
                let mut sublens: Vec<usize> = subs.iter().map(Policy::minimum_n_keys).collect();
                sublens.sort();
                sublens[0..k].iter().cloned().sum::<usize>()
            }
        }
    }
}

impl<Pk: MiniscriptKey> Policy<Pk> {
    /// "Sort" a policy to bring it into a canonical form to allow comparisons.
    /// Does **not** allow policies to be compared for functional equivalence;
    /// in general this appears to require Gröbner basis techniques that are not
    /// implemented.
    pub fn sorted(self) -> Policy<Pk> {
        match self {
            Policy::And(subs) => {
                let mut new_subs: Vec<_> = subs.into_iter().map(Policy::sorted).collect();
                new_subs.sort();
                Policy::And(new_subs)
            }
            Policy::Or(subs) => {
                let mut new_subs: Vec<_> = subs.into_iter().map(Policy::sorted).collect();
                new_subs.sort();
                Policy::Or(new_subs)
            }
            Policy::Threshold(k, subs) => {
                let mut new_subs: Vec<_> = subs.into_iter().map(Policy::sorted).collect();
                new_subs.sort();
                Policy::Threshold(k, new_subs)
            }
            x => x,
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::PublicKey;
    use std::str::FromStr;

    use super::*;

    type StringPolicy = Policy<String>;

    #[test]
    fn parse_policy_err() {
        assert!(StringPolicy::from_str("(").is_err());
        assert!(StringPolicy::from_str("(x()").is_err());
        assert!(StringPolicy::from_str("(\u{7f}()3").is_err());
        assert!(StringPolicy::from_str("pkh()").is_ok());

        assert!(StringPolicy::from_str("or(or)").is_err());

        assert!(Policy::<PublicKey>::from_str("pkh()").is_err());
        assert!(Policy::<PublicKey>::from_str(
            "pkh(\
             0200000000000000000000000000000000000002\
             )"
        )
        .is_ok());
    }

    #[test]
    fn semantic_analysis() {
        let policy = StringPolicy::from_str("pkh()").unwrap();
        assert_eq!(policy, Policy::KeyHash("".to_owned()));
        assert_eq!(policy.relative_timelocks(), vec![]);
        assert_eq!(policy.clone().at_age(0), policy.clone());
        assert_eq!(policy.clone().at_age(10000), policy.clone());
        assert_eq!(policy.n_keys(), 1);
        assert_eq!(policy.minimum_n_keys(), 1);

        let policy = StringPolicy::from_str("older(1000)").unwrap();
        assert_eq!(policy, Policy::Older(1000));
        assert_eq!(policy.relative_timelocks(), vec![1000]);
        assert_eq!(policy.clone().at_age(0), Policy::Unsatisfiable);
        assert_eq!(policy.clone().at_age(999), Policy::Unsatisfiable);
        assert_eq!(policy.clone().at_age(1000), policy.clone());
        assert_eq!(policy.clone().at_age(10000), policy.clone());
        assert_eq!(policy.n_keys(), 0);
        assert_eq!(policy.minimum_n_keys(), 0);

        let policy = StringPolicy::from_str("or(pkh(),older(1000))").unwrap();
        assert_eq!(
            policy,
            Policy::Or(vec![Policy::KeyHash("".to_owned()), Policy::Older(1000),])
        );
        assert_eq!(policy.relative_timelocks(), vec![1000]);
        assert_eq!(policy.clone().at_age(0), Policy::KeyHash("".to_owned()));
        assert_eq!(policy.clone().at_age(999), Policy::KeyHash("".to_owned()));
        assert_eq!(policy.clone().at_age(1000), policy.clone());
        assert_eq!(policy.clone().at_age(10000), policy.clone());
        assert_eq!(policy.n_keys(), 1);
        assert_eq!(policy.minimum_n_keys(), 0);

        let policy = StringPolicy::from_str(
            "thresh(\
             2,older(1000),older(10000),older(1000),older(2000),older(2000)\
             )",
        )
        .unwrap();
        assert_eq!(
            policy,
            Policy::Threshold(
                2,
                vec![
                    Policy::Older(1000),
                    Policy::Older(10000),
                    Policy::Older(1000),
                    Policy::Older(2000),
                    Policy::Older(2000),
                ]
            )
        );
        assert_eq!(
            policy.relative_timelocks(),
            vec![1000, 2000, 10000] //sorted and dedup'd
        );
    }
}
