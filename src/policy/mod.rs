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

//! # Script Policies
//!
//! Tools for representing Bitcoin scriptpubkeys as abstract spending policies.
//! These may be compiled to Miniscript, which contains extra information to
//! describe the exact representation as Bitcoin script.
//!
//! The format represents EC public keys abstractly to allow wallets to replace
//! these with BIP32 paths, pay-to-contract instructions, etc.
//!

pub mod compiler;

use std::{cmp, fmt, mem};
use std::str::FromStr;

use bitcoin_hashes::hex::FromHex;
use bitcoin_hashes::sha256;

use miniscript::Miniscript;
use Error;
use errstr;
use expression;

/// Script descriptor
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Policy<P> {
    /// A public key which must sign to satisfy the descriptor
    Key(P),
    /// A set of keys, signatures must be provided for `k` of them
    Multi(usize, Vec<P>),
    /// A SHA256 whose preimage must be provided to satisfy the descriptor
    Hash(sha256::Hash),
    /// A locktime restriction
    Time(u32),
    /// A set of descriptors, satisfactions must be provided for `k` of them
    Threshold(usize, Vec<Policy<P>>),
    /// A list of descriptors, all of which must be satisfied
    And(Box<Policy<P>>, Box<Policy<P>>),
    /// A pair of descriptors, one of which must be satisfied
    Or(Box<Policy<P>>, Box<Policy<P>>),
    /// Same as `Or`, but the second option is assumed to never be taken for costing purposes
    AsymmetricOr(Box<Policy<P>>, Box<Policy<P>>),
}

impl<P: Clone + fmt::Debug> Policy<P> {
    /// Compile the descriptor into an optimized `Miniscript` representation
    pub fn compile(&self) -> Miniscript<P> {
        let t = {
            let node = compiler::CompiledNode::from_policy(self);
            node.best_t(1.0, 0.0)
        };
        println!("offending {:?}", t.ast);
        Miniscript::from(t.ast)
    }

    /// Abstract the policy into an "abstract policy" which can be filtered and analyzed
    pub fn abstract_policy(&self) -> AbstractPolicy<P> {
        match *self {
            Policy::Key(ref p) => AbstractPolicy::Key(p.clone()),
            Policy::Multi(k, ref keys) => {
                AbstractPolicy::Threshold(
                    k,
                    keys
                        .iter()
                        .map(|key| AbstractPolicy::Key(key.clone()))
                        .collect(),
                )
            }
            Policy::Hash(hash) => AbstractPolicy::Hash(hash),
            Policy::Time(k) => AbstractPolicy::Time(k),
            Policy::Threshold(k, ref subs) => AbstractPolicy::Threshold(
                k,
                subs
                    .iter()
                    .map(|sub| sub.abstract_policy())
                    .collect(),
            ),
            Policy::And(ref left, ref right) => AbstractPolicy::And(
                Box::new(left.abstract_policy()),
                Box::new(right.abstract_policy()),
            ),
            Policy::Or(ref left, ref right) |
            Policy::AsymmetricOr(ref left, ref right) => AbstractPolicy::Or(
                Box::new(left.abstract_policy()),
                Box::new(right.abstract_policy()),
            ),
        }
    }
}

impl<P> Policy<P> {
    /// Convert a policy using abstract keys to one using specific keys
    pub fn translate<F, Q, E>(&self, translatefn: &F) -> Result<Policy<Q>, E>
        where F: Fn(&P) -> Result<Q, E>
    {
        match *self {
            Policy::Key(ref pk) => translatefn(pk).map(Policy::Key),
            Policy::Multi(k, ref pks) => {
                let new_pks: Result<Vec<Q>, _> = pks.iter().map(translatefn).collect();
                new_pks.map(|ok| Policy::Multi(k, ok))
            }
            Policy::Hash(ref h) => Ok(Policy::Hash(h.clone())),
            Policy::Time(n) => Ok(Policy::Time(n)),
            Policy::Threshold(k, ref subs) => {
                let new_subs: Result<Vec<Policy<Q>>, _> = subs.iter().map(
                    |sub| sub.translate(translatefn)
                ).collect();
                new_subs.map(|ok| Policy::Threshold(k, ok))
            }
            Policy::And(ref left, ref right) => {
                Ok(Policy::And(
                    Box::new(left.translate(translatefn)?),
                    Box::new(right.translate(translatefn)?),
                ))
            }
            Policy::Or(ref left, ref right) => {
                Ok(Policy::Or(
                    Box::new(left.translate(translatefn)?),
                    Box::new(right.translate(translatefn)?),
                ))
            }
            Policy::AsymmetricOr(ref left, ref right) => {
                Ok(Policy::AsymmetricOr(
                    Box::new(left.translate(translatefn)?),
                    Box::new(right.translate(translatefn)?),
                ))
            }
        }
    }
}

impl<P: fmt::Debug> fmt::Debug for Policy<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Policy::Key(ref pk) => write!(f, "pk({:?})", pk),
            Policy::Multi(k, ref pks) => {
                write!(f, "multi({}", k)?;
                for pk in pks {
                    write!(f, ",{:?},", pk)?;
                }
                f.write_str(")")
            }
            Policy::Hash(ref h) => write!(f, "hash({:x})", h),
            Policy::Time(n) => write!(f, "time({})", n),
            Policy::Threshold(k, ref subs) => {
                write!(f, "thres({}", k)?;
                for sub in subs {
                    write!(f, ",{:?}", sub)?;
                }
                f.write_str(")")
            }
            Policy::And(ref left, ref right) => write!(f, "and({:?},{:?})", left, right),
            Policy::Or(ref left, ref right) => write!(f, "or({:?},{:?})", left, right),
            Policy::AsymmetricOr(ref left, ref right) => write!(f, "aor({:?} {:?})", left, right),
        }
    }
}

impl<P: fmt::Display> fmt::Display for Policy<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Policy::Key(ref pk) => write!(f, "pk({})", pk),
            Policy::Multi(k, ref pks) => {
                write!(f, "multi({}", k)?;
                for pk in pks {
                    write!(f, ",{},", pk)?;
                }
                f.write_str(")")
            }
            Policy::Hash(ref h) => write!(f, "hash({:x})", h),
            Policy::Time(n) => write!(f, "time({})", n),
            Policy::Threshold(k, ref subs) => {
                write!(f, "thres({}", k)?;
                for sub in subs {
                    write!(f, ",{}", sub)?;
                }
                f.write_str(")")
            }
            Policy::And(ref left, ref right) => write!(f, "and({},{})", left, right),
            Policy::Or(ref left, ref right) => write!(f, "or({},{})", left, right),
            Policy::AsymmetricOr(ref left, ref right) => write!(f, "aor({},{})", left, right),
        }
    }
}

impl<P: FromStr> FromStr for Policy<P>
    where P::Err: ToString + fmt::Debug
{
    type Err = Error;
    fn from_str(s: &str) -> Result<Policy<P>, Error> {
        let tree = expression::Tree::from_str(s)?;
        expression::FromTree::from_tree(&tree)
    }
}

impl<P: FromStr> expression::FromTree for Policy<P>
    where P::Err: ToString + fmt::Debug
{
    fn from_tree(top: &expression::Tree) -> Result<Policy<P>, Error> {
        match (top.name, top.args.len() as u32) {
            ("pk", 1) => expression::terminal(
                &top.args[0],
                |pk| P::from_str(pk).map(Policy::Key)
            ),
            ("multi", nkeys) => {
                for arg in &top.args {
                    if !arg.args.is_empty() {
                        return Err(errstr(arg.args[0].name));
                    }
                }

                let thresh = expression::parse_num(top.args[0].name)?;
                if thresh >= nkeys {
                    return Err(errstr("higher threshold than there were keys in multi"));
                }

                let mut keys = Vec::with_capacity(top.args.len() - 1);
                for arg in &top.args[1..] {
                    match P::from_str(arg.name) {
                        Ok(pk) => keys.push(pk),
                        Err(e) => return Err(Error::Unexpected(e.to_string())),
                    }
                }
                Ok(Policy::Multi(thresh as usize, keys))
            }
            ("hash", 1) => {
                expression::terminal(
                    &top.args[0],
                    |x| sha256::Hash::from_hex(x).map(Policy::Hash)
                )
            }
            ("time", 1) => {
                expression::terminal(
                    &top.args[0],
                    |x| expression::parse_num(x).map(Policy::Time)
                )
            }
            ("thres", nsubs) => {
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
            ("and", 2) => {
                Ok(Policy::And(
                    Box::new(Policy::from_tree(&top.args[0])?),
                    Box::new(Policy::from_tree(&top.args[1])?),
                ))
            }
            ("or", 2) => {
                Ok(Policy::Or(
                    Box::new(Policy::from_tree(&top.args[0])?),
                    Box::new(Policy::from_tree(&top.args[1])?),
                ))
            }
            ("aor", 2) => {
                Ok(Policy::AsymmetricOr(
                    Box::new(Policy::from_tree(&top.args[0])?),
                    Box::new(Policy::from_tree(&top.args[1])?),
                ))
            }
            _ => Err(errstr(top.name))
        }
    }
}


/// An "abstract" script policy that does not distinguish between functionally
/// equivalent things. Designed to be filterable and analyzable, and to be
/// created from either concrete `Policy`s or even-concreter `Miniscript`s.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum AbstractPolicy<P> {
    /// A public key which must sign to satisfy the descriptor
    Key(P),
    /// A SHA256 whose preimage must be provided to satisfy the descriptor
    Hash(sha256::Hash),
    /// A locktime restriction
    Time(u32),
    /// A set of descriptors, satisfactions must be provided for `k` of them
    Threshold(usize, Vec<AbstractPolicy<P>>),
    /// A list of descriptors, all of which must be satisfied
    And(Box<AbstractPolicy<P>>, Box<AbstractPolicy<P>>),
    /// A pair of descriptors, one of which must be satisfied
    Or(Box<AbstractPolicy<P>>, Box<AbstractPolicy<P>>),
}

impl<P> AbstractPolicy<P> {
    /// Filter an abstract policy by eliminating any timelock constraints.
    /// If, after filtering, the policy cannot be satisfied, this function
    /// returns `None`.
    pub fn before_time(mut self, time: u32) -> Option<AbstractPolicy<P>> {
        self = match self {
            AbstractPolicy::Time(t) => {
                if t > time {
                    return None;
                }
                AbstractPolicy::Time(t)
            }
            AbstractPolicy::Threshold(k, subs) => {
                let subs: Vec<_> = subs
                    .into_iter()
                    .filter_map(|sub| sub.before_time(time))
                    .collect();
                if k > subs.len() {
                    return None;
                }
                AbstractPolicy::Threshold(k, subs)
            },
            AbstractPolicy::And(x, y) => {
                match (x.before_time(time), y.before_time(time)) {
                    (Some(x), Some(y)) => AbstractPolicy::And(Box::new(x), Box::new(y)),
                    _ => return None,
                }
            }
            AbstractPolicy::Or(x, y) => {
                match (x.before_time(time), y.before_time(time)) {
                    (None, None) => return None,
                    (Some(x), None) | (None, Some(x)) => x,
                    (Some(x), Some(y)) => AbstractPolicy::Or(Box::new(x), Box::new(y)),
                }
            }
            x => x,
        };
        Some(self)
    }

    /// Count the number of public keys referenced in a policy. Note that duplicate keys
    /// will be double-counted.
    pub fn n_keys(&self) -> usize {
        match *self {
            AbstractPolicy::Key(..) => 1,
            AbstractPolicy::Hash(..) | AbstractPolicy::Time(..) => 0,
            AbstractPolicy::Threshold(_, ref subs) => {
                subs.iter().map(|sub| sub.n_keys()).sum::<usize>()
            }
            AbstractPolicy::And(ref x, ref y) | AbstractPolicy::Or(ref x, ref y) => {
                x.n_keys() + y.n_keys()
            }
        }
    }

    /// Count the minimum number of public keys for which signatures could be used
    /// to satisfy the policy.
    pub fn minimum_n_keys(&self) -> usize {
        match *self {
            AbstractPolicy::Key(..) => 1,
            AbstractPolicy::Hash(..) | AbstractPolicy::Time(..) => 0,
            AbstractPolicy::Threshold(k, ref subs) => {
                let mut sublens: Vec<usize> = subs.iter().map(|sub| sub.minimum_n_keys()).collect();
                sublens.sort();
                sublens[0..k].iter().cloned().sum::<usize>()
            }
            AbstractPolicy::And(ref x, ref y) => {
                x.minimum_n_keys() + y.minimum_n_keys()
            }
            AbstractPolicy::Or(ref x, ref y) => {
                cmp::min(x.minimum_n_keys(), y.minimum_n_keys())
            }
        }
    }
}

impl<P: Ord> AbstractPolicy<P> {
    /// "Sort" a policy to bring it into a canonical form to allow comparisons.
    /// This does **not** allow policies to be compared for functional equivalence;
    /// in general this appears to require Gröbner basis techniques that are not
    /// implemented.
    pub fn sort(self) -> AbstractPolicy<P> {
        match self {
            AbstractPolicy::And(mut x, mut y) => {
                if x > y {
                    mem::swap(&mut x, &mut y);
                }
                AbstractPolicy::Or(x, y)
            }
            AbstractPolicy::Or(mut x, mut y) => {
                if x > y {
                    mem::swap(&mut x, &mut y);
                }
                AbstractPolicy::Or(x, y)
            }
            AbstractPolicy::Threshold(k, mut subs) => {
                subs.sort();
                AbstractPolicy::Threshold(k, subs)
            }
            x => x,
        }
    }
}

#[cfg(test)]
mod tests {
    use secp256k1;
    use std::str::FromStr;

    use bitcoin::blockdata::{opcodes, script};
    use bitcoin::{PublicKey, Script, SigHashType};
    use super::*;
    use NO_HASHES;

    fn pubkeys_and_a_sig(n: usize) -> (Vec<PublicKey>, secp256k1::Signature) {
        let mut ret = Vec::with_capacity(n);
        let secp = secp256k1::Secp256k1::new();
        let mut sk = [0; 32];
        for i in 1..n+1 {
            sk[0] = i as u8;
            sk[1] = (i >> 8) as u8;
            sk[2] = (i >> 16) as u8;

            let pk = PublicKey {
                key: secp256k1::PublicKey::from_secret_key(
                    &secp,
                    &secp256k1::SecretKey::from_slice(&sk[..]).expect("secret key"),
                ),
                compressed: true,
            };
            ret.push(pk);
        }
        let sig = secp.sign(
            &secp256k1::Message::from_slice(&sk[..]).expect("secret key"),
            &secp256k1::SecretKey::from_slice(&sk[..]).expect("secret key"),
        );
        (ret, sig)
    }

    #[test]
    fn compile() {
        let (keys, sig) = pubkeys_and_a_sig(10);
        let policy: Policy<PublicKey> = Policy::Time(100);
        let desc = policy.compile();
        assert_eq!(desc.serialize(), Script::from(vec![0x01, 0x64, 0xb2]));

        let policy = Policy::Key(keys[0].clone());
        let desc = policy.compile();
        assert_eq!(
            desc.serialize(),
            script::Builder::new()
                .push_key(&keys[0])
                .push_opcode(opcodes::all::OP_CHECKSIG)
                .into_script()
        );

        // CSV reordering trick
        let policy = Policy::And(
            // nb the compiler will reorder this because it can avoid the DROP if it ends with the CSV
            Box::new(Policy::Time(10000)),
            Box::new(Policy::Multi(2, keys[5..8].to_owned())),
        );
        let desc = policy.compile();
        assert_eq!(
            desc.serialize(),
            script::Builder::new()
                .push_opcode(opcodes::all::OP_PUSHNUM_2)
                .push_key(&keys[5])
                .push_key(&keys[6])
                .push_key(&keys[7])
                .push_opcode(opcodes::all::OP_PUSHNUM_3)
                .push_opcode(opcodes::all::OP_CHECKMULTISIGVERIFY)
                .push_int(10000)
                .push_opcode(opcodes::OP_CSV)
                .into_script()
        );

        // Liquid policy
        let policy = Policy::AsymmetricOr(
            Box::new(Policy::Multi(3, keys[0..5].to_owned())),
            Box::new(Policy::And(
                Box::new(Policy::Time(10000)),
                Box::new(Policy::Multi(2, keys[5..8].to_owned())),
            )),
        );
        let desc = policy.compile();
        assert_eq!(
            desc.serialize(),
            script::Builder::new()
                .push_opcode(opcodes::all::OP_PUSHNUM_3)
                .push_key(&keys[0])
                .push_key(&keys[1])
                .push_key(&keys[2])
                .push_key(&keys[3])
                .push_key(&keys[4])
                .push_opcode(opcodes::all::OP_PUSHNUM_5)
                .push_opcode(opcodes::all::OP_CHECKMULTISIG)
                .push_opcode(opcodes::all::OP_IFDUP)
                .push_opcode(opcodes::all::OP_NOTIF)
                    .push_opcode(opcodes::all::OP_PUSHNUM_2)
                    .push_key(&keys[5])
                    .push_key(&keys[6])
                    .push_key(&keys[7])
                    .push_opcode(opcodes::all::OP_PUSHNUM_3)
                    .push_opcode(opcodes::all::OP_CHECKMULTISIGVERIFY)
                    .push_int(10000)
                    .push_opcode(opcodes::OP_CSV)
                .push_opcode(opcodes::all::OP_ENDIF)
                .into_script()
        );
        println!("desc: {}", desc);

        let mut abs = policy.abstract_policy();
        assert_eq!(abs.n_keys(), 8);
        assert_eq!(abs.minimum_n_keys(), 2);
        abs = abs.before_time(10000).unwrap();
        assert_eq!(abs.n_keys(), 8);
        assert_eq!(abs.minimum_n_keys(), 2);
        abs = abs.before_time(9999).unwrap();
        assert_eq!(abs.n_keys(), 5);
        assert_eq!(abs.minimum_n_keys(), 3);
        abs = abs.before_time(0).unwrap();
        assert_eq!(abs.n_keys(), 5);
        assert_eq!(abs.minimum_n_keys(), 3);

        assert_eq!(
            &desc.public_keys()[..],
            &keys[0..8]
        );

        let mut sigvec = sig.serialize_der();
        sigvec.push(1); // sighash all

        let badfn = |_: &PublicKey| None;
        let keyfn = |_: &PublicKey| Some((sig.clone(), Some(SigHashType::All)));

        let leftfn = |pk: &PublicKey| {
            for (n, target) in keys.iter().enumerate() {
                if pk == target && n < 5 {
                    return Some((sig.clone(), Some(SigHashType::All)));
                }
            }
            None
        };

        assert!(desc.satisfy(Some(&badfn), NO_HASHES, 0).is_err());
        assert!(desc.satisfy(Some(&keyfn), NO_HASHES, 0).is_ok());
        assert!(desc.satisfy(Some(&leftfn), NO_HASHES, 0).is_ok());

        assert_eq!(
            desc.satisfy(Some(&leftfn), NO_HASHES, 0).unwrap(),
            vec![
                // sat for left branch
                vec![],
                sigvec.clone(),
                sigvec.clone(),
                sigvec.clone(),
            ]
        );

        assert_eq!(
            desc.satisfy(Some(&keyfn), NO_HASHES, 10000).unwrap(),
            vec![
                // sat for right branch
                vec![],
                sigvec.clone(),
                sigvec.clone(),
                // dissat for left branch
                vec![],
                vec![],
                vec![],
                vec![],
            ]
        );
    }

    #[test]
    fn parse_descriptor() {
        assert!(Policy::<PublicKey>::from_str("(").is_err());
        assert!(Policy::<PublicKey>::from_str("(x()").is_err());
        assert!(Policy::<PublicKey>::from_str("(\u{7f}()3").is_err());
        assert!(Policy::<PublicKey>::from_str("pk()").is_err());

        assert!(Policy::<PublicKey>::from_str("pk(020000000000000000000000000000000000000000000000000000000000000002)").is_ok());
    }
}


