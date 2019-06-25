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

#[cfg(feature = "serde")] use serde::{de, ser};
use std::{fmt, str};

use bitcoin;
use bitcoin::blockdata::script;
use bitcoin_hashes::hash160;

pub mod astelem;
pub mod decode;
pub mod lex;
pub mod satisfy;
pub mod types;

use Error;
use expression;
use ToPublicKey;
use ToPublicKeyHash;
use self::lex::{lex, TokenIter};
use self::satisfy::{Satisfiable, Satisfier};

/// Top-level script AST type
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Miniscript<Pk, Pkh=hash160::Hash>(astelem::AstElem<Pk, Pkh>);

impl<Pk, Pkh> From<astelem::AstElem<Pk, Pkh>> for Miniscript<Pk, Pkh>
where
    Pk: Clone + fmt::Debug,
    Pkh: Clone + fmt::Debug,
{
    fn from(t: astelem::AstElem<Pk, Pkh>) -> Miniscript<Pk, Pkh> {
        let type_check = types::Type::from_fragment(&t, None)
            .expect("typecheck in Miniscript::from");
        assert!(type_check.base == types::Base::B);
        Miniscript(t)
    }
}

impl<Pk, Pkh> fmt::Debug for Miniscript<Pk, Pkh>
where
    Pk: Clone + fmt::Debug,
    Pkh: Clone + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<Pk: fmt::Display, Pkh: fmt::Display> fmt::Display for Miniscript<Pk, Pkh> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<Pk, Pkh> Miniscript<Pk, Pkh> {
    /// Extracts the `AstElem` representing the root of the miniscript
    pub fn into_inner(self) -> astelem::AstElem<Pk, Pkh> {
        self.0
    }
}

impl Miniscript<bitcoin::PublicKey, hash160::Hash> {
    /// Attempt to parse a script into a Miniscript representation
    pub fn parse(script: &script::Script)
        -> Result<Miniscript<bitcoin::PublicKey, hash160::Hash>, Error>
    {
        let tokens = lex(script)?;
        let mut iter = TokenIter::new(tokens);

        let top = decode::parse(&mut iter)?;
        let type_check = types::Type::from_fragment(&top, None)?;
        if type_check.base != types::Base::B {
            return Err(Error::NonTopLevel(
                format!("{:?}", top)
            ));
        };
        if let Some(leading) = iter.next() {
            Err(Error::Trailing(leading.to_string()))
        } else {
            Ok(Miniscript(top))
        }
    }
}

impl<Pk: ToPublicKey, Pkh: ToPublicKeyHash> Miniscript<Pk, Pkh> {
    /// Encode as a Bitcoin script
    pub fn encode(&self) -> script::Script {
        self.0.encode(script::Builder::new()).into_script()
    }

    /// Size, in bytes of the script-pubkey. If this Miniscript is used outside
    /// of segwit (e.g. in a bare or P2SH descriptor), this quantity should be
    /// multiplied by 4 to compute the weight.
    ///
    /// In general, it is not recommended to use this function directly, but
    /// to instead call the corresponding function on a `Descriptor`, which
    /// will handle the segwit/non-segwit technicalities for you.
    pub fn script_size(&self) -> usize {
        self.0.script_size()
    }

    /// Maximum number of witness elements used to satisfy the Miniscript
    /// fragment, including the witness script itself. Used to estimate
    /// the weight of the `VarInt` that specifies this number in a serialized
    /// transaction.
    ///
    /// This function may panic on misformed `Miniscript` objects which do
    /// not correspond to semantically sane Scripts. (Such scripts should be
    /// rejected at parse time. Any exceptions are bugs.)
    pub fn max_satisfaction_witness_elements(&self) -> usize {
        1 + self.0.max_satisfaction_witness_elements()
    }

    /// Maximum size, in bytes, of a satisfying witness. For Segwit outputs
    /// `one_cost` should be set to 2, since the number `1` requires two
    /// bytes to encode. For non-segwit outputs `one_cost` should be set to
    /// 1, since `OP_1` is available in scriptSigs.
    ///
    /// In general, it is not recommended to use this function directly, but
    /// to instead call the corresponding function on a `Descriptor`, which
    /// will handle the segwit/non-segwit technicalities for you.
    ///
    /// All signatures are assumed to be 73 bytes in size, including the
    /// length prefix (segwit) or push opcode (pre-segwit) and sighash
    /// postfix.
    ///
    /// This function may panic on misformed `Miniscript` objects which do not
    /// correspond to semantically sane Scripts. (Such scripts should be
    /// rejected at parse time. Any exceptions are bugs.)
    pub fn max_satisfaction_size(&self, one_cost: usize) -> usize {
        self.0.max_satisfaction_size(one_cost)
    }
}

impl<Pk, Pkh: Clone> Miniscript<Pk, Pkh> {
    pub fn translate_pk<F, Q, E>(&self, translatefn: F)
        -> Result<Miniscript<Q, Pkh>, E>
        where F: FnMut(&Pk) -> Result<Q, E>
    {
        let inner = self.0.translate_pk(translatefn)?;
        Ok(Miniscript(inner))
    }
}

impl<Pk: Clone, Pkh> Miniscript<Pk, Pkh> {
    pub fn translate_pkh<F, Q, E>(&self, translatefn: F)
        -> Result<Miniscript<Pk, Q>, E>
        where F: FnMut(&Pkh) -> Result<Q, E>
    {
        let inner = self.0.translate_pkh(translatefn)?;
        Ok(Miniscript(inner))
    }
}

impl<Pk, Pkh> Miniscript<Pk, Pkh> {
    /// Attempt to produce a satisfying witness for the
    /// witness script represented by the parse tree
    pub fn satisfy<S: Satisfier<Pk, Pkh>>(
        &self,
        satisfier: &S,
        age: u32,
        height: u32,
    ) -> Option<Vec<Vec<u8>>> {
        self.0.satisfy(satisfier, age, height)
    }
}

impl<Pk, Pkh> expression::FromTree for Miniscript<Pk, Pkh> where
    Pk: Clone + fmt::Debug + fmt::Display + str::FromStr,
    Pkh: Clone + fmt::Debug + fmt::Display + str::FromStr,
    <Pk as str::FromStr>::Err: ToString,
    <Pkh as str::FromStr>::Err: ToString,
{
    /// Parse an expression tree into a Miniscript. As a general rule, this
    /// should not be called directly; rather go through the descriptor API.
    fn from_tree(top: &expression::Tree) -> Result<Miniscript<Pk, Pkh>, Error> {
        let inner: astelem::AstElem<Pk, Pkh>
            = expression::FromTree::from_tree(top)?;
        let type_check = types::Type::from_fragment(&inner, None)?;
        if type_check.base == types::Base::B {
            Ok(Miniscript(inner))
        } else {
            Err(Error::NonTopLevel(format!("{:?}", inner)))
        }
    }
}

impl<Pk, Pkh> str::FromStr for Miniscript<Pk, Pkh> where
    Pk: Clone + fmt::Debug + fmt::Display + str::FromStr,
    Pkh: Clone + fmt::Debug + fmt::Display + str::FromStr,
    <Pk as str::FromStr>::Err: ToString,
    <Pkh as str::FromStr>::Err: ToString,
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Miniscript<Pk, Pkh>, Error> {
        for ch in s.as_bytes() {
            if *ch < 20 || *ch > 127 {
                return Err(Error::Unprintable(*ch));
            }
        }

        let top = expression::Tree::from_str(s)?;
        expression::FromTree::from_tree(&top)
    }
}

#[cfg(feature = "serde")]
impl<Pk, Pkh> ser::Serialize for Miniscript<Pk, Pkh> where
    Pk: fmt::Display,
    Pkh: fmt::Display,
{
    fn serialize<S: ser::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de, Pk, Pkh> de::Deserialize<'de> for Miniscript<Pk, Pkh> where
    Pk: fmt::Debug + str::FromStr,
    Pkh: fmt::Debug + str::FromStr,
    <Pk as str::FromStr>::Err: ToString,
    <Pkh as str::FromStr>::Err: ToString,
{
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Miniscript<Pk, Pkh>, D::Error> {
        use std::str::FromStr;
        use std::marker::PhantomData;

        struct StrVisitor<Qk, Qkh>(PhantomData<(Qk, Qkh)>);

        impl<'de, Qk, Qkh> de::Visitor<'de> for StrVisitor<Qk, Qkh> where
            Qk: fmt::Debug + str::FromStr,
            Qkh: fmt::Debug + str::FromStr,
            <Qk as str::FromStr>::Err: ToString,
            <Qkh as str::FromStr>::Err: ToString,
        {
            type Value = Miniscript<Qk, Qkh>;

            fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                fmt.write_str("an ASCII miniscript string")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E> where
                E: de::Error,
            {
                if let Ok(s) = str::from_utf8(v) {
                    Miniscript::from_str(s).map_err(E::custom)
                } else {
                    return Err(E::invalid_value(de::Unexpected::Bytes(v), &self));
                }
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> where
                E: de::Error,
            {
                Miniscript::from_str(v).map_err(E::custom)
            }
        }

        d.deserialize_str(StrVisitor(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use super::Miniscript;
    use DummyKey;
    use DummyKeyHash;
    use miniscript::astelem::AstElem;
    use miniscript::types;
    use hex_script;
    use policy::Liftable;

    use bitcoin::{self, PublicKey};
    use bitcoin_hashes::{Hash, hash160, sha256};
    use secp256k1;
    use std::fmt;
    use std::str::FromStr;

    type DummyScript = Miniscript<DummyKey, DummyKeyHash>;
    type BScript = Miniscript<bitcoin::PublicKey, hash160::Hash>;

    fn pubkeys(n: usize) -> Vec<PublicKey> {
        let mut ret = Vec::with_capacity(n);
        let secp = secp256k1::Secp256k1::new();
        let mut sk = [0; 32];
        for i in 1..n+1 {
            sk[0] = i as u8;
            sk[1] = (i >> 8) as u8;
            sk[2] = (i >> 16) as u8;

            let pk = bitcoin::PublicKey {
                key: secp256k1::PublicKey::from_secret_key(
                    &secp,
                    &secp256k1::SecretKey::from_slice(
                        &sk[..],
                    ).expect("secret key"),
                ),
                compressed: true,
            };
            ret.push(pk);
        }
        ret
    }

    fn string_rtt<Pk, Pkh, Str1, Str2>(
        script: Miniscript<Pk, Pkh>,
        expected_debug: Str1,
        expected_display: Str2,
    ) where
        Pk: Clone + fmt::Debug + fmt::Display + FromStr + Eq,
        Pkh: Clone + fmt::Debug + fmt::Display + FromStr + Eq,
        <Pk as FromStr>::Err: fmt::Display,
        <Pkh as FromStr>::Err: fmt::Display,
        Str1: Into<Option<&'static str>>,
        Str2: Into<Option<&'static str>>,
    {
        let type_check = types::Type::from_fragment(&script.0, None)
            .expect("typecheck");
        assert!(type_check.base == types::Base::B);
        let debug = format!("{:?}", script);
        let display = format!("{}", script);
        if let Some(expected) = expected_debug.into() {
            assert_eq!(debug, expected);
        }
        if let Some(expected) = expected_display.into() {
            assert_eq!(display, expected);
        }
        let roundtrip = Miniscript::<Pk, Pkh>::from_str(&display)
            .expect("parse string serialization");
        assert_eq!(roundtrip, script);
    }

    fn script_rtt<Str1: Into<Option<&'static str>>>(
        script: BScript,
        expected_hex: Str1,
    ) {
        let type_check = types::Type::from_fragment(&script.0, None)
            .expect("typecheck");
        assert!(type_check.base == types::Base::B);
        let bitcoin_script = script.encode();
        assert_eq!(bitcoin_script.len(), script.script_size());
        if let Some(expected) = expected_hex.into() {
            assert_eq!(format!("{:x}", bitcoin_script), expected);
        }
        let roundtrip = Miniscript::parse(&bitcoin_script)
            .expect("parse string serialization");
        assert_eq!(roundtrip, script);
    }

    fn roundtrip(tree: &BScript, s: &str) {
        let type_check = match types::Type::from_fragment(&tree.0, None) {
            Ok(type_check) => type_check,
            Err(e) => panic!("typecheck: {}", e),
        };
        assert!(type_check.base == types::Base::B);
        let ser = tree.encode();
        assert_eq!(ser.len(), tree.script_size());
        assert_eq!(ser.to_string(), s);
        let deser = Miniscript::parse(&ser).expect("deserialize result of serialize");
        assert_eq!(tree, &deser);
    }

    #[test]
    fn basic() {
        let pk = bitcoin::PublicKey::from_str("\
            020202020202020202020202020202020202020202020202020202020202020202\
        ").unwrap();
        let hash = hash160::Hash::from_inner([17; 20]);

        string_rtt(
            DummyScript::from(AstElem::Check(Box::new(AstElem::Pk(DummyKey)))),
            "[B/eonus]c:[K/eonus]pk(DummyKey)",
            "c:pk()",
        );

        string_rtt(
            DummyScript::from(AstElem::Check(
                Box::new(AstElem::PkH(DummyKeyHash))
            )),
            "[B/nus]c:[K/nus]pk_h(DummyKeyHash)",
            "c:pk_h()",
        );

        script_rtt(
            BScript::from(AstElem::Check(Box::new(AstElem::Pk(pk)))),
            "21020202020202020202020202020202020202020202020202020202020\
             202020202ac",
        );
        script_rtt(
            BScript::from(AstElem::Check(Box::new(AstElem::PkH(hash)))),
            "76a914111111111111111111111111111111111111111188ac",
        );
    }

    #[test]
    fn serialize() {
        let keys = pubkeys(5);
        let dummy_hash = hash160::Hash::from_inner([0; 20]);

        roundtrip(
            &Miniscript(AstElem::Check(Box::new(AstElem::PkH(dummy_hash)))),
            "\
                Script(OP_DUP OP_HASH160 OP_PUSHBYTES_20 \
                0000000000000000000000000000000000000000 \
                OP_EQUALVERIFY OP_CHECKSIG)\
            ",
        );

        roundtrip(
            &Miniscript(AstElem::Check(Box::new(AstElem::Pk(keys[0].clone())))),
            "Script(OP_PUSHBYTES_33 028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa OP_CHECKSIG)"
        );
        roundtrip(
            &Miniscript(AstElem::ThreshM(3, keys.clone())),
            "Script(OP_PUSHNUM_3 OP_PUSHBYTES_33 028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa OP_PUSHBYTES_33 03ab1ac1872a38a2f196bed5a6047f0da2c8130fe8de49fc4d5dfb201f7611d8e2 OP_PUSHBYTES_33 039729247032c0dfcf45b4841fcd72f6e9a2422631fc3466cf863e87154754dd40 OP_PUSHBYTES_33 032564fe9b5beef82d3703a607253f31ef8ea1b365772df434226aee642651b3fa OP_PUSHBYTES_33 0289637f97580a796e050791ad5a2f27af1803645d95df021a3c2d82eb8c2ca7ff OP_PUSHNUM_5 OP_CHECKMULTISIG)"
        );

        // Liquid policy
        roundtrip(
            &Miniscript(AstElem::OrD(
                Box::new(AstElem::ThreshM(2, keys[0..2].to_owned())),
                Box::new(AstElem::AndV(
                    Box::new(AstElem::Verify(
                        Box::new(AstElem::ThreshM(2, keys[3..5].to_owned()))
                    )),
                    Box::new(AstElem::After(10000)),
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

        let miniscript = Miniscript::<_, DummyKeyHash>::from(AstElem::OrD(
            Box::new(AstElem::ThreshM(3, keys[0..3].to_owned())),
            Box::new(AstElem::AndV(
                Box::new(AstElem::Verify(
                    Box::new(AstElem::ThreshM(2, keys[3..5].to_owned()))
                )),
                Box::new(AstElem::After(10000)),
            )),
        ));

        let mut abs = miniscript.into_lift();
        assert_eq!(abs.n_keys(), 5);
        assert_eq!(abs.minimum_n_keys(), 2);
        abs = abs.at_age(10000);
        assert_eq!(abs.n_keys(), 5);
        assert_eq!(abs.minimum_n_keys(), 2);
        abs = abs.at_age(9999);
        assert_eq!(abs.n_keys(), 3);
        assert_eq!(abs.minimum_n_keys(), 3);
        abs = abs.at_age(0);
        assert_eq!(abs.n_keys(), 3);
        assert_eq!(abs.minimum_n_keys(), 3);

        roundtrip(
            &Miniscript(AstElem::After(921)),
            "Script(OP_PUSHBYTES_2 9903 OP_NOP3)"
        );

        roundtrip(
            &Miniscript(AstElem::Sha256(sha256::Hash::hash(&[]))),
            "Script(OP_SIZE OP_PUSHBYTES_1 20 OP_EQUALVERIFY OP_SHA256 OP_PUSHBYTES_32 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 OP_EQUAL)"
        );

        roundtrip(
            &Miniscript(AstElem::ThreshM(3, keys[0..5].to_owned())),
            "Script(OP_PUSHNUM_3 \
                    OP_PUSHBYTES_33 028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa \
                    OP_PUSHBYTES_33 03ab1ac1872a38a2f196bed5a6047f0da2c8130fe8de49fc4d5dfb201f7611d8e2 \
                    OP_PUSHBYTES_33 039729247032c0dfcf45b4841fcd72f6e9a2422631fc3466cf863e87154754dd40 \
                    OP_PUSHBYTES_33 032564fe9b5beef82d3703a607253f31ef8ea1b365772df434226aee642651b3fa \
                    OP_PUSHBYTES_33 0289637f97580a796e050791ad5a2f27af1803645d95df021a3c2d82eb8c2ca7ff \
                    OP_PUSHNUM_5 OP_CHECKMULTISIG)"
        );

        roundtrip(
            &Miniscript(AstElem::Sha256(sha256::Hash::hash(&[]))),
            "Script(OP_SIZE OP_PUSHBYTES_1 20 OP_EQUALVERIFY OP_SHA256 OP_PUSHBYTES_32 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 OP_EQUAL)"
        );
    }

    #[test]
    fn deserialize() {
        // Most of these came from fuzzing, hence the increasing lengths
        assert!(Miniscript::parse(&hex_script("")).is_err()); // empty
        assert!(Miniscript::parse(&hex_script("00")).is_ok()); // FALSE
        assert!(Miniscript::parse(&hex_script("51")).is_ok()); // TRUE
        assert!(Miniscript::parse(&hex_script("69")).is_err()); // VERIFY
        assert!(Miniscript::parse(&hex_script("1001")).is_err()); // incomplete push
        assert!(Miniscript::parse(&hex_script("03990300b2")).is_err()); // non-minimal #
        assert!(Miniscript::parse(&hex_script("8559b2")).is_err()); // leading bytes
        assert!(Miniscript::parse(&hex_script("4c0169b2")).is_err()); // non-minimal push
        assert!(Miniscript::parse(&hex_script("0000af0000ae85")).is_err()); // OR not BOOLOR

        // misc fuzzer problems
        assert!(Miniscript::parse(&hex_script("0000000000af")).is_err());
        assert!(Miniscript::parse(&hex_script("04009a2970af00")).is_err()); // giant CMS key num
        assert!(Miniscript::parse(&hex_script(
            "2102ffffffffffffffefefefefefefefefefefef394c0fe5b711179e124008584753ac6900"
        )).is_err());
    }
}
