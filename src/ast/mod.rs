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

//! # AST Tree
//!
//! Defines a variety of data structures for describing a subset of Bitcoin Script
//! which can be efficiently parsed and serialized from Script, and from which it
//! is easy to extract data needed to construct witnesses.
//!
//! Users of the library in general will only need to use the structures exposed
//! from the top level of this module; however for people wanting to do advanced
//! things, the submodules are public as well which provide visibility into the
//! components of the AST trees.
//!

use std::fmt;
use std::collections::HashMap;
use secp256k1;

use bitcoin::blockdata::script;
use bitcoin::util::hash::Hash160;
use bitcoin::util::hash::Sha256dHash; // TODO needs to be sha256, not sha256d

pub mod astelem;
pub mod compiler;
pub mod lex;
pub mod satisfy;

use Error;
use Descriptor;
use self::astelem::{AstElem, parse_subexpression};
use self::compiler::Compileable;
use self::lex::{lex, TokenIter};
use self::satisfy::Satisfiable;

/// Top-level script AST type
#[derive(Clone, PartialEq, Eq)]
pub struct ParseTree(Box<astelem::T>);

impl fmt::Debug for ParseTree {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl fmt::Display for ParseTree {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl ParseTree {
    /// Attempt to parse a script into an AST
    pub fn parse(script: &script::Script) -> Result<ParseTree, Error> {
        let tokens = lex(script)?;
        let mut iter = TokenIter::new(tokens);

        let top = parse_subexpression(&mut iter)?.into_t()?;
        if let Some(leading) = iter.next() {
            Err(Error::Unexpected(leading.to_string()))
        } else {
            Ok(ParseTree(top))
        }
    }

    /// Serialize an AST into script form
    pub fn serialize(&self) -> script::Script {
        self.0.serialize(script::Builder::new()).into_script()
    }

    /// Compile an instantiated descriptor into a parse tree
    pub fn compile(desc: &Descriptor<secp256k1::PublicKey>) -> ParseTree {
        let t = astelem::T::from_descriptor(desc, 1.0, 0.0);
        ParseTree(Box::new(t.ast))
    }

    /// Attempt to produce a satisfying witness for the scriptpubkey represented by the parse tree
    pub fn satisfy(
        &self,
        key_map: &HashMap<secp256k1::PublicKey, secp256k1::Signature>,
        pkh_map: &HashMap<Hash160, secp256k1::PublicKey>,
        hash_map: &HashMap<Sha256dHash, [u8; 32]>,
        age: u32,
    ) -> Result<Vec<Vec<u8>>, Error> {
        self.0.satisfy(key_map, pkh_map, hash_map, age)
    }

    /// Return a list of all public keys which might contribute to satisfaction of the scriptpubkey
    pub fn required_keys(&self) -> Vec<secp256k1::PublicKey> {
        self.0.required_keys()
    }
}

#[cfg(test)]
mod tests {
    use ast::ParseTree;
    use ast::astelem::{E, W, F, V, T};

    use bitcoin::blockdata::script;
    use bitcoin::util::hash::Hash160;
    use bitcoin::util::hash::Sha256dHash; // TODO needs to be sha256, not sha256d

    use secp256k1;

    fn pubkeys(n: usize) -> Vec<secp256k1::PublicKey> {
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
        ret
    }

    fn roundtrip(tree: &ParseTree, s: &str) {
        let ser = tree.serialize();
        assert_eq!(ser.to_string(), s);
        let deser = ParseTree::parse(&ser).expect("deserialize result of serialize");
        assert_eq!(tree, &deser);
    }

    #[test]
    fn serialize() {
        let keys = pubkeys(5);

        roundtrip(
            &ParseTree(Box::new(T::CastE(E::CheckSig(keys[0].clone())))),
            "Script(OP_PUSHBYTES_33 028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa OP_CHECKSIG)"
        );
        roundtrip(
            &ParseTree(Box::new(T::CastE(E::CheckMultiSig(3, keys.clone())))),
            "Script(OP_PUSHNUM_3 OP_PUSHBYTES_33 028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa OP_PUSHBYTES_33 03ab1ac1872a38a2f196bed5a6047f0da2c8130fe8de49fc4d5dfb201f7611d8e2 OP_PUSHBYTES_33 039729247032c0dfcf45b4841fcd72f6e9a2422631fc3466cf863e87154754dd40 OP_PUSHBYTES_33 032564fe9b5beef82d3703a607253f31ef8ea1b365772df434226aee642651b3fa OP_PUSHBYTES_33 0289637f97580a796e050791ad5a2f27af1803645d95df021a3c2d82eb8c2ca7ff OP_PUSHNUM_5 OP_CHECKMULTISIG)"
        );

        let hash = Hash160::from_data(&keys[0].serialize());
        roundtrip(
            &ParseTree(Box::new(T::CastE(E::CheckSigHash(hash)))),
            "Script(OP_DUP OP_HASH160 OP_PUSHBYTES_20 60afcdec519698a263417ddfe7cea936737a0ee7 OP_EQUALVERIFY OP_CHECKSIG)"
        );

        // Liquid policy
        roundtrip(
            &ParseTree(Box::new(T::CascadeOr(
                Box::new(E::CheckMultiSig(2, keys[0..2].to_owned())),
                Box::new(T::And(
                     Box::new(V::CheckMultiSig(2, keys[3..5].to_owned())),
                     Box::new(T::Csv(10000)),
                 )),
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
            &ParseTree(Box::new(T::Csv(921))),
            "Script(OP_PUSHBYTES_2 9903 OP_NOP3)"
        );

        roundtrip(
            &ParseTree(Box::new(T::HashEqual(Sha256dHash::from_data(&[])))),
            "Script(OP_SIZE OP_PUSHBYTES_1 20 OP_EQUALVERIFY OP_SHA256 OP_PUSHBYTES_32 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456 OP_EQUAL)"
        );

        roundtrip(
            &ParseTree(Box::new(T::CastE(E::CheckMultiSig(3, keys[0..5].to_owned())))),
            "Script(OP_PUSHNUM_3 \
                    OP_PUSHBYTES_33 028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa \
                    OP_PUSHBYTES_33 03ab1ac1872a38a2f196bed5a6047f0da2c8130fe8de49fc4d5dfb201f7611d8e2 \
                    OP_PUSHBYTES_33 039729247032c0dfcf45b4841fcd72f6e9a2422631fc3466cf863e87154754dd40 \
                    OP_PUSHBYTES_33 032564fe9b5beef82d3703a607253f31ef8ea1b365772df434226aee642651b3fa \
                    OP_PUSHBYTES_33 0289637f97580a796e050791ad5a2f27af1803645d95df021a3c2d82eb8c2ca7ff \
                    OP_PUSHNUM_5 OP_CHECKMULTISIG)"
        );

        roundtrip(
            &ParseTree(Box::new(T::HashEqual(Sha256dHash::from_data(&[])))),
            "Script(OP_SIZE OP_PUSHBYTES_1 20 OP_EQUALVERIFY OP_SHA256 OP_PUSHBYTES_32 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456 OP_EQUAL)"
        );

        roundtrip(
            &ParseTree(Box::new(T::SwitchOrV(
                Box::new(V::CheckSig(keys[0].clone())),
                Box::new(V::And(
                    Box::new(V::CheckSig(keys[1].clone())),
                    Box::new(V::CheckSig(keys[2].clone())),
                ))),
            )),
            "Script(OP_SIZE OP_EQUALVERIFY OP_IF \
                OP_PUSHBYTES_33 028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa OP_CHECKSIGVERIFY \
                OP_ELSE \
                OP_PUSHBYTES_33 03ab1ac1872a38a2f196bed5a6047f0da2c8130fe8de49fc4d5dfb201f7611d8e2 OP_CHECKSIGVERIFY \
                OP_PUSHBYTES_33 039729247032c0dfcf45b4841fcd72f6e9a2422631fc3466cf863e87154754dd40 OP_CHECKSIGVERIFY \
                OP_ENDIF OP_PUSHNUM_1)"
        );

        // fuzzer
        roundtrip(
            &ParseTree(Box::new(T::SwitchOr(
                Box::new(T::Csv(9)),
                Box::new(T::Csv(7)),
            ))),
            "Script(OP_SIZE OP_EQUALVERIFY OP_IF OP_PUSHNUM_9 OP_NOP3 OP_ELSE OP_PUSHNUM_7 OP_NOP3 OP_ENDIF)"
        );

        roundtrip(
            &ParseTree(Box::new(T::And(
                Box::new(V::SwitchOrT(
                    Box::new(T::Csv(9)),
                    Box::new(T::Csv(7)),
                )),
                Box::new(T::Csv(7))
            ))),
            "Script(OP_SIZE OP_EQUALVERIFY OP_IF OP_PUSHNUM_9 OP_NOP3 OP_ELSE OP_PUSHNUM_7 OP_NOP3 OP_ENDIF OP_VERIFY OP_PUSHNUM_7 OP_NOP3)"
        );

        roundtrip(
            &ParseTree(Box::new(T::ParallelOr(
                Box::new(E::CheckMultiSig(0, vec![])),
                Box::new(W::CheckSig(keys[0].clone())),
            ))),
            "Script(OP_0 OP_0 OP_CHECKMULTISIG OP_SWAP OP_PUSHBYTES_33 028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa OP_CHECKSIG OP_BOOLOR)"
        );
    }

    #[test]
    fn deserialize() {
        // Most of these came from fuzzing, hence the increasing lengths
        assert!(ParseTree::parse(&script::Script::new()).is_err()); // empty script
        assert!(ParseTree::parse(&script::Script::from(vec![0])).is_err()); // FALSE and nothing else
        assert!(ParseTree::parse(&script::Script::from(vec![0x50])).is_err()); // TRUE and nothing else
        assert!(ParseTree::parse(&script::Script::from(vec![0x69])).is_err()); // VERIFY and nothing else
        assert!(ParseTree::parse(&script::Script::from(vec![0x10, 1])).is_err()); // incomplete push and nothing else
        assert!(ParseTree::parse(&script::Script::from(vec![0x03, 0x99, 0x03, 0x00, 0xb2])).is_err()); // non-minimal #
        assert!(ParseTree::parse(&script::Script::from(vec![0x85, 0x59, 0xb2])).is_err()); // leading bytes
        assert!(ParseTree::parse(&script::Script::from(vec![0x4c, 0x01, 0x69, 0xb2])).is_err()); // nonminimal push
        assert!(ParseTree::parse(&script::Script::from(vec![0x00, 0x00, 0xaf, 0x01, 0x01, 0xb2])).is_err()); // nonminimal number

        assert!(ParseTree::parse(&script::Script::from(vec![0x00, 0x00, 0xaf, 0x00, 0x00, 0xae, 0x85])).is_err()); // OR not BOOLOR
        assert!(ParseTree::parse(&script::Script::from(vec![0x00, 0x00, 0xaf, 0x00, 0x00, 0xae, 0x9b])).is_err()); // parallel OR without wrapping
    }
}

