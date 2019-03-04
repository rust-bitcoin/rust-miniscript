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

//! # AST Tree
//!
//! Defines a variety of data structures for describing Miniscript, a subset of
//! Bitcoin Script which can be efficiently parsed and serialized from Script,
//! and from which it is easy to extract data needed to construct witnesses.
//!
//! Users of the library in general will only need to use the structures exposed
//! from the top level of this module; however for people wanting to do advanced
//! things, the submodules are public as well which provide visibility into the
//! components of the AST trees.
//!

use std::{fmt, str};
use std::rc::Rc;
use secp256k1;

use bitcoin;
use bitcoin::blockdata::script;
use bitcoin::blockdata::transaction::SigHashType;
use bitcoin_hashes::sha256;

pub mod astelem;
pub mod lex;
pub mod satisfy;

use Error;
use expression;
use self::astelem::{AstElem, parse_subexpression};
use self::lex::{lex, TokenIter};
use self::satisfy::Satisfiable;

/// Top-level script AST type
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Miniscript<P>(astelem::T<P>);

impl<P> From<astelem::T<P>> for Miniscript<P> {
    fn from(t: astelem::T<P>) -> Miniscript<P> {
        Miniscript(t)
    }
}

impl<P: fmt::Debug> fmt::Debug for Miniscript<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<P: fmt::Display> fmt::Display for Miniscript<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Miniscript<bitcoin::util::key::PublicKey> {
    /// Attempt to parse a script into a Miniscript representation
    pub fn parse(script: &script::Script) -> Result<Miniscript<bitcoin::util::key::PublicKey>, Error> {
        let tokens = lex(script)?;
        let mut iter = TokenIter::new(tokens);

        let top = parse_subexpression(&mut iter)?;
        let top = if top.is_t() {
            top.into_t()
        } else {
            return Err(Error::Unexpected(top.to_string()))
        };
        if let Some(leading) = iter.next() {
            Err(Error::Unexpected(leading.to_string()))
        } else {
            Ok(Miniscript(Rc::try_unwrap(top).unwrap()))
        }
    }

    /// Serialize back into script form
    pub fn serialize(&self) -> script::Script {
        self.0.serialize(script::Builder::new()).into_script()
    }
}

impl<P> Miniscript<P> {
    pub fn translate<F, Q, E>(&self, translatefn: &F) -> Result<Miniscript<Q>, E>
        where F: Fn(&P) -> Result<Q, E> {
        let inner = self.0.translate(translatefn)?;
        Ok(Miniscript(inner))
    }
}

impl<P: ToString> Miniscript<P> {
    /// Attempt to produce a satisfying witness for the scriptpubkey represented by the parse tree
    pub fn satisfy<F, H>(&self, keyfn: Option<&F>, hashfn: Option<&H>, age: u32)
        -> Result<Vec<Vec<u8>>, Error>
        where F: Fn(&P) -> Option<(secp256k1::Signature, Option<SigHashType>)>,
              H: Fn(sha256::Hash) -> Option<[u8; 32]>
    {
        self.0.satisfy(keyfn, hashfn, age)
    }
}

impl<P: Clone> Miniscript<P> {
    /// Return a list of all public keys which might contribute to satisfaction of the scriptpubkey
    pub fn public_keys(&self) -> Vec<P> {
        self.0.public_keys()
    }
}

impl<P: str::FromStr> expression::FromTree for Miniscript<P>
    where <P as str::FromStr>::Err: ToString,
{
    /// Parse an expression tree into a Miniscript. As a general rule this should
    /// not be called directly; rather go through the output descriptor API.
    fn from_tree(top: &expression::Tree) -> Result<Miniscript<P>, Error> {
        let inner: Rc<astelem::T<P>> = expression::FromTree::from_tree(top)?;
        Ok(Miniscript(Rc::try_unwrap(inner).ok().unwrap()))
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use super::Miniscript;
    use miniscript::astelem::{E, W, V, T};

    use bitcoin::blockdata::script;
    use bitcoin::util::key::PublicKey;
    use bitcoin_hashes::{Hash, sha256};

    use secp256k1;

    fn pubkeys(n: usize) -> Vec<PublicKey> {
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
        ret
    }

    fn roundtrip(tree: &Miniscript<PublicKey>, s: &str) {
        let ser = tree.serialize();
        assert_eq!(ser.to_string(), s);
        let deser = Miniscript::parse(&ser).expect("deserialize result of serialize");
        assert_eq!(tree, &deser);
    }

    #[test]
    fn serialize() {
        let keys = pubkeys(5);

        roundtrip(
            &Miniscript(T::CastE(E::CheckSig(keys[0].clone()))),
            "Script(OP_PUSHBYTES_33 028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa OP_CHECKSIG)"
        );
        roundtrip(
            &Miniscript(T::CastE(E::CheckMultiSig(3, keys.clone()))),
            "Script(OP_PUSHNUM_3 OP_PUSHBYTES_33 028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa OP_PUSHBYTES_33 03ab1ac1872a38a2f196bed5a6047f0da2c8130fe8de49fc4d5dfb201f7611d8e2 OP_PUSHBYTES_33 039729247032c0dfcf45b4841fcd72f6e9a2422631fc3466cf863e87154754dd40 OP_PUSHBYTES_33 032564fe9b5beef82d3703a607253f31ef8ea1b365772df434226aee642651b3fa OP_PUSHBYTES_33 0289637f97580a796e050791ad5a2f27af1803645d95df021a3c2d82eb8c2ca7ff OP_PUSHNUM_5 OP_CHECKMULTISIG)"
        );

        // Liquid policy
        roundtrip(
            &Miniscript(T::CascadeOr(
                Rc::new(E::CheckMultiSig(2, keys[0..2].to_owned())),
                Rc::new(T::And(
                     Rc::new(V::CheckMultiSig(2, keys[3..5].to_owned())),
                     Rc::new(T::Time(10000)),
                 ),
             ))),
             "Script(OP_PUSHNUM_2 OP_PUSHBYTES_33 028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa \
                                  OP_PUSHBYTES_33 03ab1ac1872a38a2f196bed5a6047f0da2c8130fe8de49fc4d5dfb201f7611d8e2 \
                                  OP_PUSHNUM_2 OP_CHECKMULTISIG \
                     OP_IFDUP OP_NOTIF \
                         OP_PUSHNUM_2 OP_PUSHBYTES_33 032564fe9b5beef82d3703a607253f31ef8ea1b365772df434226aee642651b3fa \
                                      OP_PUSHBYTES_33 0289637f97580a796e050791ad5a2f27af1803645d95df021a3c2d82eb8c2ca7ff \
                                      OP_PUSHNUM_2 OP_CHECKMULTISIGVERIFY \
                         OP_PUSHBYTES_2 1027 OP_NOP3 \
                     OP_ENDIF)"
         );

        roundtrip(
            &Miniscript(T::Time(921)),
            "Script(OP_PUSHBYTES_2 9903 OP_NOP3)"
        );

        roundtrip(
            &Miniscript(T::HashEqual(sha256::Hash::hash(&[]))),
            "Script(OP_SIZE OP_PUSHBYTES_1 20 OP_EQUALVERIFY OP_SHA256 OP_PUSHBYTES_32 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 OP_EQUAL)"
        );

        roundtrip(
            &Miniscript(T::CastE(E::CheckMultiSig(3, keys[0..5].to_owned()))),
            "Script(OP_PUSHNUM_3 \
                    OP_PUSHBYTES_33 028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa \
                    OP_PUSHBYTES_33 03ab1ac1872a38a2f196bed5a6047f0da2c8130fe8de49fc4d5dfb201f7611d8e2 \
                    OP_PUSHBYTES_33 039729247032c0dfcf45b4841fcd72f6e9a2422631fc3466cf863e87154754dd40 \
                    OP_PUSHBYTES_33 032564fe9b5beef82d3703a607253f31ef8ea1b365772df434226aee642651b3fa \
                    OP_PUSHBYTES_33 0289637f97580a796e050791ad5a2f27af1803645d95df021a3c2d82eb8c2ca7ff \
                    OP_PUSHNUM_5 OP_CHECKMULTISIG)"
        );

        roundtrip(
            &Miniscript(T::HashEqual(sha256::Hash::hash(&[]))),
            "Script(OP_SIZE OP_PUSHBYTES_1 20 OP_EQUALVERIFY OP_SHA256 OP_PUSHBYTES_32 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 OP_EQUAL)"
        );

        roundtrip(
            &Miniscript(T::SwitchOrV(
                Rc::new(V::CheckSig(keys[0].clone())),
                Rc::new(V::And(
                    Rc::new(V::CheckSig(keys[1].clone())),
                    Rc::new(V::CheckSig(keys[2].clone())),
                )),
            )),
            "Script(OP_IF \
                OP_PUSHBYTES_33 028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa OP_CHECKSIGVERIFY \
                OP_ELSE \
                OP_PUSHBYTES_33 03ab1ac1872a38a2f196bed5a6047f0da2c8130fe8de49fc4d5dfb201f7611d8e2 OP_CHECKSIGVERIFY \
                OP_PUSHBYTES_33 039729247032c0dfcf45b4841fcd72f6e9a2422631fc3466cf863e87154754dd40 OP_CHECKSIGVERIFY \
                OP_ENDIF OP_PUSHNUM_1)"
        );

        // fuzzer
        roundtrip(
            &Miniscript(T::SwitchOr(
                Rc::new(T::Time(9)),
                Rc::new(T::Time(7)),
            )),
            "Script(OP_IF OP_PUSHNUM_9 OP_NOP3 OP_ELSE OP_PUSHNUM_7 OP_NOP3 OP_ENDIF)"
        );

        roundtrip(
            &Miniscript(T::And(
                Rc::new(V::SwitchOrT(
                    Rc::new(T::Time(9)),
                    Rc::new(T::Time(7)),
                )),
                Rc::new(T::Time(7))
            )),
            "Script(OP_IF OP_PUSHNUM_9 OP_NOP3 OP_ELSE OP_PUSHNUM_7 OP_NOP3 OP_ENDIF OP_VERIFY OP_PUSHNUM_7 OP_NOP3)"
        );

        roundtrip(
            &Miniscript(T::ParallelOr(
                Rc::new(E::CheckMultiSig(0, vec![])),
                Rc::new(W::CheckSig(keys[0].clone())),
            )),
            "Script(OP_0 OP_0 OP_CHECKMULTISIG OP_SWAP OP_PUSHBYTES_33 028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa OP_CHECKSIG OP_BOOLOR)"
        );
    }

    #[test]
    fn deserialize() {
        // Most of these came from fuzzing, hence the increasing lengths
        assert!(Miniscript::parse(&script::Script::new()).is_err()); // empty script
        assert!(Miniscript::parse(&script::Script::from(vec![0])).is_err()); // FALSE and nothing else
        assert!(Miniscript::parse(&script::Script::from(vec![0x50])).is_err()); // TRUE and nothing else
        assert!(Miniscript::parse(&script::Script::from(vec![0x69])).is_err()); // VERIFY and nothing else
        assert!(Miniscript::parse(&script::Script::from(vec![0x10, 1])).is_err()); // incomplete push and nothing else
        assert!(Miniscript::parse(&script::Script::from(vec![0x03, 0x99, 0x03, 0x00, 0xb2])).is_err()); // non-minimal #
        assert!(Miniscript::parse(&script::Script::from(vec![0x85, 0x59, 0xb2])).is_err()); // leading bytes
        assert!(Miniscript::parse(&script::Script::from(vec![0x4c, 0x01, 0x69, 0xb2])).is_err()); // nonminimal push
        assert!(Miniscript::parse(&script::Script::from(vec![0x00, 0x00, 0xaf, 0x01, 0x01, 0xb2])).is_err()); // nonminimal number

        assert!(Miniscript::parse(&script::Script::from(vec![0x00, 0x00, 0xaf, 0x00, 0x00, 0xae, 0x85])).is_err()); // OR not BOOLOR
        assert!(Miniscript::parse(&script::Script::from(vec![0x00, 0x00, 0xaf, 0x00, 0x00, 0xae, 0x9b])).is_err()); // parallel OR without wrapping
    }
}

