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

//! # Script Policies
//!
//! Tools for representing Bitcoin scriptpubkeys as abstract spending policies, known
//! as "script descriptors".
//!
//! The format represents EC public keys abstractly to allow wallets to replace these with
//! BIP32 paths, pay-to-contract instructions, etc.
//!

pub mod compiler;

use std::fmt;
use std::rc::Rc;
use std::str::FromStr;

use bitcoin::util::hash::Sha256dHash; // TODO needs to be sha256, not sha256d

use descript::Descript;
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
    Hash(Sha256dHash),
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
    /// Compile the descriptor into an optimized `Descript` representation
    pub fn compile(&self) -> Descript<P> {
        let t = {
            let node = compiler::CompiledNode::from_policy(self);
            node.best_t(1.0, 0.0)
        };
        Descript::from(Rc::try_unwrap(t.ast).ok().unwrap())
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

// TODO ** special case empty multis
                let thresh = match expression::parse_num(top.args[0].name) {
                    Ok(n) => n,
                    Err(_) => {
                        return Ok(Policy::Multi(2, vec![
                            P::from_str("").unwrap(),
                            P::from_str("").unwrap(),
                            P::from_str("").unwrap(),
                        ]));
                    }
                };
// end TODO ** special case empty multis
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
// TODO ** special case empty strings
if top.args[0].args.is_empty() && top.args[0].name == "" {
    return Ok(Policy::Hash(Sha256dHash::from_data(&[0;32][..])));
}
// TODO ** special case empty strings
                expression::terminal(
                    &top.args[0],
                    |x| Sha256dHash::from_hex(x).map(Policy::Hash)
                )
            }
            ("time", 1) => {
// TODO ** special case empty strings
if top.args[0].args.is_empty() && top.args[0].name == "" {
    return Ok(Policy::Time(0x10000000))
}
// TODO ** special case empty strings
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

#[cfg(test)]
mod tests {
    use secp256k1;
    use std::str::FromStr;

    use bitcoin::blockdata::opcodes;
    use bitcoin::blockdata::script::{self, Script};
    use bitcoin::blockdata::transaction::SigHashType;
    use super::*;
    use NO_HASHES;

    fn pubkeys_and_a_sig(n: usize) -> (Vec<secp256k1::PublicKey>, secp256k1::Signature) {
        let mut ret = Vec::with_capacity(n);
        let secp = secp256k1::Secp256k1::new();
        let mut sk = [0; 32];
        for i in 1..n+1 {
            sk[0] = i as u8;
            sk[1] = (i >> 8) as u8;
            sk[2] = (i >> 16) as u8;

            let pk = secp256k1::PublicKey::from_secret_key(
                &secp,
                &secp256k1::SecretKey::from_slice(&secp, &sk[..]).expect("secret key"),
            );
            ret.push(pk);
        }
        let sig = secp.sign(
            &secp256k1::Message::from_slice(&sk[..]).expect("secret key"),
            &secp256k1::SecretKey::from_slice(&secp, &sk[..]).expect("secret key"),
        );
        (ret, sig)
    }

    #[test]
    fn compile() {
        let (keys, sig) = pubkeys_and_a_sig(10);
        let policy: Policy<secp256k1::PublicKey> = Policy::Time(100);
        let desc = policy.compile();
        assert_eq!(desc.serialize(), Script::from(vec![0x01, 0x64, 0xb2]));

        let policy = Policy::Key(keys[0].clone());
        let desc = policy.compile();
        assert_eq!(
            desc.serialize(),
            script::Builder::new()
                .push_slice(&keys[0].serialize()[..])
                .push_opcode(opcodes::All::OP_CHECKSIG)
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
                .push_opcode(opcodes::All::OP_PUSHNUM_2)
                .push_slice(&keys[5].serialize()[..])
                .push_slice(&keys[6].serialize()[..])
                .push_slice(&keys[7].serialize()[..])
                .push_opcode(opcodes::All::OP_PUSHNUM_3)
                .push_opcode(opcodes::All::OP_CHECKMULTISIGVERIFY)
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
                .push_opcode(opcodes::All::OP_PUSHNUM_3)
                .push_slice(&keys[0].serialize()[..])
                .push_slice(&keys[1].serialize()[..])
                .push_slice(&keys[2].serialize()[..])
                .push_slice(&keys[3].serialize()[..])
                .push_slice(&keys[4].serialize()[..])
                .push_opcode(opcodes::All::OP_PUSHNUM_5)
                .push_opcode(opcodes::All::OP_CHECKMULTISIG)
                .push_opcode(opcodes::All::OP_IFDUP)
                .push_opcode(opcodes::All::OP_NOTIF)
                    .push_opcode(opcodes::All::OP_PUSHNUM_2)
                    .push_slice(&keys[5].serialize()[..])
                    .push_slice(&keys[6].serialize()[..])
                    .push_slice(&keys[7].serialize()[..])
                    .push_opcode(opcodes::All::OP_PUSHNUM_3)
                    .push_opcode(opcodes::All::OP_CHECKMULTISIGVERIFY)
                    .push_int(10000)
                    .push_opcode(opcodes::OP_CSV)
                .push_opcode(opcodes::All::OP_ENDIF)
                .into_script()
        );

        assert_eq!(
            &desc.public_keys()[..],
            &keys[0..8]
        );

        let mut sigvec = sig.serialize_der(&secp256k1::Secp256k1::without_caps());
        sigvec.push(1); // sighash all

        let badfn = |_: &secp256k1::PublicKey| None;
        let keyfn = |_: &secp256k1::PublicKey| Some((sig.clone(), Some(SigHashType::All)));

        let leftfn = |pk: &secp256k1::PublicKey| {
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
            desc.satisfy(Some(&keyfn), NO_HASHES, 0).unwrap(),
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
        assert!(Policy::<secp256k1::PublicKey>::from_str("(").is_err());
        assert!(Policy::<secp256k1::PublicKey>::from_str("(x()").is_err());
        assert!(Policy::<secp256k1::PublicKey>::from_str("(\u{7f}()3").is_err());
        assert!(Policy::<secp256k1::PublicKey>::from_str("pk()").is_err());

        assert!(Policy::<secp256k1::PublicKey>::from_str("pk(020000000000000000000000000000000000000000000000000000000000000002)").is_ok());
    }
}


