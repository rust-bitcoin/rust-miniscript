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

//! # Script Descriptors
//!
//! Tools for representing Bitcoin scriptpubkeys as abstract spending policies, known
//! as "script descriptors".
//!
//! The format represents EC public keys abstractly to allow wallets to replace these with
//! BIP32 paths, pay-to-contract instructions, etc.
//!

use std::fmt;
use std::str::{self, FromStr};

use expression;
use descript::Descript;
use Error;
use PublicKey;

/// Script descriptor
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Descriptor<P> {
    /// A raw scriptpubkey
    Bare(Descript<P>),
    /// Pay-to-PubKey-Hash
    Pkh(P),
    /// Pay-to-Witness-PubKey-Hash
    Wpkh(P),
    /// Pay-to-ScriptHash
    Sh(Descript<P>),
    /// Pay-to-Witness-ScriptHash
    Wsh(Descript<P>),
    /// P2SH-P2WSH
    ShWsh(Descript<P>),
}

impl<P: PublicKey> Descriptor<P> {
    /// Convert a descriptor using abstract keys to one using specific keys
    pub fn translate<F, Q, E>(&self, translatefn: &F) -> Result<Descriptor<Q>, E>
        where F: Fn(&P) -> Result<Q, E>
    {
        match *self {
            Descriptor::Bare(ref descript) => {
                Ok(Descriptor::Bare(descript.translate(translatefn)?))
            }
            Descriptor::Pkh(ref pk) => {
                translatefn(pk).map(Descriptor::Pkh)
            }
            Descriptor::Wpkh(ref pk) => {
                translatefn(pk).map(Descriptor::Wpkh)
            }
            Descriptor::Sh(ref descript) => {
                Ok(Descriptor::Bare(descript.translate(translatefn)?))
            }
            Descriptor::Wsh(ref descript) => {
                Ok(Descriptor::Bare(descript.translate(translatefn)?))
            }
            Descriptor::ShWsh(ref descript) => {
                Ok(Descriptor::Bare(descript.translate(translatefn)?))
            }
        }
    }
}

impl<P: PublicKey> expression::FromTree for Descriptor<P>
    where <P as FromStr>::Err: ToString,
{
    /// Parse an expression tree into a descriptor
    fn from_tree(top: &expression::Tree) -> Result<Descriptor<P>, Error> {
        match (top.name, top.args.len() as u32) {
            ("pkh", 1) => expression::terminal(
                &top.args[0],
                |pk| P::from_str(pk).map(Descriptor::Pkh)
            ),
            ("wpkh", 1) => expression::terminal(
                &top.args[0],
                |pk| P::from_str(pk).map(Descriptor::Wpkh)
            ),
            ("sh", 1) => {
                let newtop = &top.args[0];
                match (newtop.name, newtop.args.len()) {
                    ("wsh", 1) => {
                        let sub = Descript::from_tree(&newtop.args[0])?;
                        Ok(Descriptor::ShWsh(sub))
                    }
                    _ => {
                        let sub = Descript::from_tree(&top.args[0])?;
                        Ok(Descriptor::Sh(sub))
                    }
                }
            }
            ("wsh", 1) => expression::unary(top, Descriptor::Wsh),
            _ => {
                let sub = expression::FromTree::from_tree(&top)?;
                Ok(Descriptor::Bare(sub))
            }
        }
    }
}

impl<P: PublicKey> FromStr for Descriptor<P>
    where <P as FromStr>::Err: ToString,
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Descriptor<P>, Error> {
        for ch in s.as_bytes() {
            if *ch < 20 || *ch > 127 {
                return Err(Error::Unprintable(*ch));
            }
        }

        let top = expression::Tree::from_str(s)?;
        expression::FromTree::from_tree(&top)
    }
}

impl <P: fmt::Debug> fmt::Debug for Descriptor<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Descriptor::Bare(ref sub) => write!(f, "{:?}", sub),
            Descriptor::Pkh(ref p) => write!(f, "pkh({:?})", p),
            Descriptor::Wpkh(ref p) => write!(f, "wpkh({:?})", p),
            Descriptor::Sh(ref sub) => write!(f, "sh({:?})", sub),
            Descriptor::Wsh(ref sub) => write!(f, "wsh({:?})", sub),
            Descriptor::ShWsh(ref sub) => write!(f, "sh(wsh({:?}))", sub),
        }
    }
}

impl <P: fmt::Display> fmt::Display for Descriptor<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Descriptor::Bare(ref sub) => write!(f, "{}", sub),
            Descriptor::Pkh(ref p) => write!(f, "pkh({})", p),
            Descriptor::Wpkh(ref p) => write!(f, "wpkh({})", p),
            Descriptor::Sh(ref sub) => write!(f, "sh({})", sub),
            Descriptor::Wsh(ref sub) => write!(f, "wsh({})", sub),
            Descriptor::ShWsh(ref sub) => write!(f, "sh(wsh({}))", sub),
        }
    }
}

#[cfg(test)]
mod tests {
    use secp256k1;
    use std::collections::HashMap;
    use std::str::FromStr;

    use bitcoin::blockdata::opcodes;
    use bitcoin::blockdata::script::{self, Script};
    use bitcoin::blockdata::transaction::SigHashType;
    use Descriptor;
    use ParseTree;

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
        let desc: Descriptor<secp256k1::PublicKey> = Descriptor::Time(100);
        let pt = ParseTree::compile(&desc);
        assert_eq!(pt.serialize(), Script::from(vec![0x01, 0x64, 0xb2]));

        let desc = Descriptor::Key(keys[0].clone());
        let pt = ParseTree::compile(&desc);
        assert_eq!(
            pt.serialize(),
            script::Builder::new()
                .push_slice(&keys[0].serialize()[..])
                .push_opcode(opcodes::All::OP_CHECKSIG)
                .into_script()
        );

        // CSV reordering trick
        let desc = Descriptor::And(
            // nb the compiler will reorder this because it can avoid the DROP if it ends with the CSV
            Box::new(Descriptor::Time(10000)),
            Box::new(Descriptor::Multi(2, keys[5..8].to_owned())),
        );
        let pt = ParseTree::compile(&desc);
        assert_eq!(
            pt.serialize(),
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
        let desc = Descriptor::AsymmetricOr(
            Box::new(Descriptor::Multi(3, keys[0..5].to_owned())),
            Box::new(Descriptor::And(
                Box::new(Descriptor::Time(10000)),
                Box::new(Descriptor::Multi(2, keys[5..8].to_owned())),
            )),
        );
        let pt = ParseTree::compile(&desc);
        assert_eq!(
            pt.serialize(),
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
            &pt.required_keys()[..],
            &keys[0..8]
        );

        let mut sigvec = sig.serialize_der(&secp256k1::Secp256k1::without_caps());
        sigvec.push(1); // sighash all

        let mut map = HashMap::new();
        assert!(pt.satisfy(&map, &HashMap::new(), &HashMap::new(), 0).is_err());

        map.insert(keys[0].clone(), (sig.clone(), SigHashType::All));
        map.insert(keys[1].clone(), (sig.clone(), SigHashType::All));
        assert!(pt.satisfy(&map, &HashMap::new(), &HashMap::new(), 0).is_err());

        map.insert(keys[2].clone(), (sig.clone(), SigHashType::All));
        assert_eq!(
            pt.satisfy(&map, &HashMap::new(), &HashMap::new(), 0).unwrap(),
            vec![
                sigvec.clone(),
                sigvec.clone(),
                sigvec.clone(),
                vec![],
            ]
        );

        map.insert(keys[5].clone(), (sig.clone(), SigHashType::All));
        assert_eq!(
            pt.satisfy(&map, &HashMap::new(), &HashMap::new(), 0).unwrap(),
            vec![
                sigvec.clone(),
                sigvec.clone(),
                sigvec.clone(),
                vec![],
            ]
        );

        map.insert(keys[6].clone(), (sig.clone(), SigHashType::All));
        assert_eq!(
            pt.satisfy(&map, &HashMap::new(), &HashMap::new(), 10000).unwrap(),
            vec![
                // sat for right branch
                sigvec.clone(),
                sigvec.clone(),
                vec![],
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
        assert!(Descriptor::<secp256k1::PublicKey>::from_str("(").is_err());
        assert!(Descriptor::<secp256k1::PublicKey>::from_str("(x()").is_err());
        assert!(Descriptor::<secp256k1::PublicKey>::from_str("(\u{7f}()3").is_err());
        assert!(Descriptor::<secp256k1::PublicKey>::from_str("pk()").is_err());

        assert!(Descriptor::<secp256k1::PublicKey>::from_str("pk(020000000000000000000000000000000000000000000000000000000000000002)").is_ok());
    }
}

