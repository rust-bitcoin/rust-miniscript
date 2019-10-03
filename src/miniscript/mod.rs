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

#[cfg(feature = "serde")]
use serde::{de, ser};
use std::{fmt, str};

use bitcoin;
use bitcoin::blockdata::script;

pub mod astelem;
pub mod decode;
pub mod lex;
pub mod satisfy;
pub mod types;

use self::lex::{lex, TokenIter};
use self::types::Property;
use miniscript::types::extra_props::ExtData;
use miniscript::types::Type;
use std::cmp;
use std::sync::Arc;
use MiniscriptKey;
use {expression, Error, ToPublicKey};

/// Top-level script AST type
#[derive(Clone, Hash)]
pub struct Miniscript<Pk: MiniscriptKey> {
    ///A node in the Abstract Syntax Tree(
    pub node: decode::Terminal<Pk>,
    ///The correctness and malleability type information for the AST node
    pub ty: types::Type,
    ///Additional information helpful for extra analysis.
    pub ext: types::extra_props::ExtData,
}

/// `PartialOrd` of `Miniscript` must depend only on node and not the type information.
/// The type information and extra_properties can be deterministically determined
/// by the ast tree.
impl<Pk: MiniscriptKey> PartialOrd for Miniscript<Pk> {
    fn partial_cmp(&self, other: &Miniscript<Pk>) -> Option<cmp::Ordering> {
        Some(self.node.cmp(&other.node))
    }
}

/// `Ord` of `Miniscript` must depend only on node and not the type information.
/// The type information and extra_properties can be deterministically determined
/// by the ast tree.
impl<Pk: MiniscriptKey> Ord for Miniscript<Pk> {
    fn cmp(&self, other: &Miniscript<Pk>) -> cmp::Ordering {
        self.node.cmp(&other.node)
    }
}

/// `PartialEq` of `Miniscript` must depend only on node and not the type information.
/// The type information and extra_properties can be deterministically determined
/// by the ast tree.
impl<Pk: MiniscriptKey> PartialEq for Miniscript<Pk> {
    fn eq(&self, other: &Miniscript<Pk>) -> bool {
        self.node.eq(&other.node)
    }
}

/// `Eq` of `Miniscript` must depend only on node and not the type information.
/// The type information and extra_properties can be deterministically determined
/// by the ast tree.
impl<Pk: MiniscriptKey> Eq for Miniscript<Pk> {}

impl<Pk: MiniscriptKey> fmt::Debug for Miniscript<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.node)
    }
}

impl<Pk: MiniscriptKey> Miniscript<Pk> {
    /// Add type information(Type and Extdata) to Miniscript based on
    /// `AstElem` fragment. Dependent on display and clone because of Error
    /// Display code of type_check.
    pub fn from_ast(t: decode::Terminal<Pk>) -> Result<Miniscript<Pk>, Error> {
        Ok(Miniscript {
            ty: Type::type_check(&t, |_| None)?,
            ext: ExtData::type_check(&t, |_| None)?,
            node: t,
        })
    }
}

impl<Pk: MiniscriptKey> fmt::Display for Miniscript<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.node)
    }
}

impl<Pk: MiniscriptKey> Miniscript<Pk> {
    /// Extracts the `AstElem` representing the root of the miniscript
    pub fn into_inner(self) -> decode::Terminal<Pk> {
        self.node
    }

    pub fn as_inner(&self) -> &decode::Terminal<Pk> {
        &self.node
    }
}

impl Miniscript<bitcoin::PublicKey> {
    /// Attempt to parse a script into a Miniscript representation
    pub fn parse(script: &script::Script) -> Result<Miniscript<bitcoin::PublicKey>, Error> {
        let tokens = lex(script)?;
        let mut iter = TokenIter::new(tokens);

        let top = decode::parse(&mut iter)?;
        let type_check = types::Type::type_check(&top.node, |_| None)?;
        if type_check.corr.base != types::Base::B {
            return Err(Error::NonTopLevel(format!("{:?}", top)));
        };
        if let Some(leading) = iter.next() {
            Err(Error::Trailing(leading.to_string()))
        } else {
            Ok(top)
        }
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> Miniscript<Pk> {
    /// Encode as a Bitcoin script
    pub fn encode(&self) -> script::Script {
        self.node.encode(script::Builder::new()).into_script()
    }

    /// Size, in bytes of the script-pubkey. If this Miniscript is used outside
    /// of segwit (e.g. in a bare or P2SH descriptor), this quantity should be
    /// multiplied by 4 to compute the weight.
    ///
    /// In general, it is not recommended to use this function directly, but
    /// to instead call the corresponding function on a `Descriptor`, which
    /// will handle the segwit/non-segwit technicalities for you.
    pub fn script_size(&self) -> usize {
        self.node.script_size()
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
        1 + self.node.max_satisfaction_witness_elements()
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
        self.node.max_satisfaction_size(one_cost)
    }
}

impl<Pk: MiniscriptKey> Miniscript<Pk> {
    pub fn translate_pk<FPk, FPkh, Q, Error>(
        &self,
        translatefpk: &mut FPk,
        translatefpkh: &mut FPkh,
    ) -> Result<Miniscript<Q>, Error>
    where
        FPk: FnMut(&Pk) -> Result<Q, Error>,
        FPkh: FnMut(&Pk::Hash) -> Result<Q::Hash, Error>,
        Q: MiniscriptKey,
    {
        let inner = self.node.translate_pk(translatefpk, translatefpkh)?;
        Ok(Miniscript {
            //directly copying the type and ext is safe because translating public
            //key should not change any properties
            ty: self.ty,
            ext: self.ext,
            node: inner,
        })
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> Miniscript<Pk> {
    /// Attempt to produce a satisfying witness for the
    /// witness script represented by the parse tree
    pub fn satisfy<S: satisfy::Satisfier<Pk>>(&self, satisfier: S) -> Option<Vec<Vec<u8>>> {
        match satisfy::Satisfaction::satisfy(&self.node, &satisfier).stack {
            satisfy::Witness::Stack(stack) => Some(stack),
            satisfy::Witness::Unavailable => None,
        }
    }
}

impl<Pk> expression::FromTree for Arc<Miniscript<Pk>>
where
    Pk: MiniscriptKey,
    <Pk as str::FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as str::FromStr>::Err: ToString,
{
    fn from_tree(top: &expression::Tree) -> Result<Arc<Miniscript<Pk>>, Error> {
        Ok(Arc::new(expression::FromTree::from_tree(top)?))
    }
}

impl<Pk> expression::FromTree for Miniscript<Pk>
where
    Pk: MiniscriptKey,
    <Pk as str::FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as str::FromStr>::Err: ToString,
{
    /// Parse an expression tree into a Miniscript. As a general rule, this
    /// should not be called directly; rather go through the descriptor API.
    fn from_tree(top: &expression::Tree) -> Result<Miniscript<Pk>, Error> {
        let inner: decode::Terminal<Pk> = expression::FromTree::from_tree(top)?;
        Ok(Miniscript {
            ty: Type::type_check(&inner, |_| None)?,
            ext: ExtData::type_check(&inner, |_| None)?,
            node: inner,
        })
    }
}

impl<Pk> str::FromStr for Miniscript<Pk>
where
    Pk: MiniscriptKey,
    <Pk as str::FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as str::FromStr>::Err: ToString,
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Miniscript<Pk>, Error> {
        for ch in s.as_bytes() {
            if *ch < 20 || *ch > 127 {
                return Err(Error::Unprintable(*ch));
            }
        }

        let top = expression::Tree::from_str(s)?;
        let ms: Miniscript<Pk> = expression::FromTree::from_tree(&top)?;

        if ms.ty.corr.base != types::Base::B {
            Err(Error::NonTopLevel(format!("{:?}", ms)))
        } else {
            Ok(ms)
        }
    }
}

#[cfg(feature = "serde")]
impl<Pk: MiniscriptKey> ser::Serialize for Miniscript<Pk> {
    fn serialize<S: ser::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de, Pk> de::Deserialize<'de> for Miniscript<Pk>
where
    Pk: MiniscriptKey,
    <Pk as str::FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as str::FromStr>::Err: ToString,
{
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Miniscript<Pk>, D::Error> {
        use std::marker::PhantomData;
        use std::str::FromStr;

        struct StrVisitor<Qk>(PhantomData<(Qk)>);

        impl<'de, Qk> de::Visitor<'de> for StrVisitor<Qk>
        where
            Qk: MiniscriptKey,
            <Qk as str::FromStr>::Err: ToString,
            <<Qk as MiniscriptKey>::Hash as str::FromStr>::Err: ToString,
        {
            type Value = Miniscript<Qk>;

            fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                fmt.write_str("an ASCII miniscript string")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if let Ok(s) = str::from_utf8(v) {
                    Miniscript::from_str(s).map_err(E::custom)
                } else {
                    return Err(E::invalid_value(de::Unexpected::Bytes(v), &self));
                }
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
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
    use hex_script;
    use miniscript::decode::Terminal;
    use miniscript::types::{self, ExtData, Property, Type};
    use policy::Liftable;
    use DummyKey;
    use DummyKeyHash;

    use bitcoin::hashes::{hash160, sha256, Hash};
    use bitcoin::{self, secp256k1};
    use std::str;
    use std::str::FromStr;
    use std::sync::Arc;
    use MiniscriptKey;

    type BScript = Miniscript<bitcoin::PublicKey>;

    fn pubkeys(n: usize) -> Vec<bitcoin::PublicKey> {
        let mut ret = Vec::with_capacity(n);
        let secp = secp256k1::Secp256k1::new();
        let mut sk = [0; 32];
        for i in 1..n + 1 {
            sk[0] = i as u8;
            sk[1] = (i >> 8) as u8;
            sk[2] = (i >> 16) as u8;

            let pk = bitcoin::PublicKey {
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

    fn string_rtt<Pk, Str1, Str2>(
        script: Miniscript<Pk>,
        expected_debug: Str1,
        expected_display: Str2,
    ) where
        Pk: MiniscriptKey,
        <Pk as str::FromStr>::Err: ToString,
        <<Pk as MiniscriptKey>::Hash as str::FromStr>::Err: ToString,
        Str1: Into<Option<&'static str>>,
        Str2: Into<Option<&'static str>>,
    {
        assert_eq!(script.ty.corr.base, types::Base::B);
        let debug = format!("{:?}", script);
        let display = format!("{}", script);
        if let Some(expected) = expected_debug.into() {
            assert_eq!(debug, expected);
        }
        if let Some(expected) = expected_display.into() {
            assert_eq!(display, expected);
        }
        let roundtrip = Miniscript::from_str(&display).expect("parse string serialization");
        assert_eq!(roundtrip, script);

        let translated: Result<_, ()> =
            script.translate_pk(&mut |k| Ok(k.clone()), &mut |h| Ok(h.clone()));
        assert_eq!(translated, Ok(script));
    }

    fn script_rtt<Str1: Into<Option<&'static str>>>(script: BScript, expected_hex: Str1) {
        assert_eq!(script.ty.corr.base, types::Base::B);
        let bitcoin_script = script.encode();
        assert_eq!(bitcoin_script.len(), script.script_size());
        if let Some(expected) = expected_hex.into() {
            assert_eq!(format!("{:x}", bitcoin_script), expected);
        }
        let roundtrip = Miniscript::parse(&bitcoin_script).expect("parse string serialization");
        assert_eq!(roundtrip, script);
    }

    fn roundtrip(tree: &Miniscript<bitcoin::PublicKey>, s: &str) {
        assert_eq!(tree.ty.corr.base, types::Base::B);
        let ser = tree.encode();
        assert_eq!(ser.len(), tree.script_size());
        assert_eq!(ser.to_string(), s);
        let deser = Miniscript::parse(&ser).expect("deserialize result of serialize");
        assert_eq!(*tree, deser);
    }

    #[test]
    fn basic() {
        let pk = bitcoin::PublicKey::from_str(
            "\
             020202020202020202020202020202020202020202020202020202020202020202\
             ",
        )
        .unwrap();
        let hash = hash160::Hash::from_inner([17; 20]);

        let pk_ms: Miniscript<DummyKey> = Miniscript {
            node: Terminal::Check(Arc::new(Miniscript {
                node: Terminal::Pk(DummyKey),
                ty: Type::from_pk(),
                ext: types::extra_props::ExtData::from_pk(),
            })),
            ty: Type::cast_check(Type::from_pk()).unwrap(),
            ext: ExtData::cast_check(ExtData::from_pk()).unwrap(),
        };
        string_rtt(pk_ms, "[B/onduesm]c:[K/onduesm]pk(DummyKey)", "c:pk()");

        let pkh_ms: Miniscript<DummyKey> = Miniscript {
            node: Terminal::Check(Arc::new(Miniscript {
                node: Terminal::PkH(DummyKeyHash),
                ty: Type::from_pk_h(),
                ext: types::extra_props::ExtData::from_pk_h(),
            })),
            ty: Type::cast_check(Type::from_pk_h()).unwrap(),
            ext: ExtData::cast_check(ExtData::from_pk_h()).unwrap(),
        };
        string_rtt(
            pkh_ms,
            "[B/nduesm]c:[K/nduesm]pk_h(DummyKeyHash)",
            "c:pk_h()",
        );

        let pk_ms: Miniscript<bitcoin::PublicKey> = Miniscript {
            node: Terminal::Check(Arc::new(Miniscript {
                node: Terminal::Pk(pk),
                ty: Type::from_pk(),
                ext: types::extra_props::ExtData::from_pk(),
            })),
            ty: Type::cast_check(Type::from_pk()).unwrap(),
            ext: ExtData::cast_check(ExtData::from_pk()).unwrap(),
        };

        script_rtt(
            pk_ms,
            "21020202020202020202020202020202020202020202020202020202020\
             202020202ac",
        );

        let pkh_ms: Miniscript<bitcoin::PublicKey> = Miniscript {
            node: Terminal::Check(Arc::new(Miniscript {
                node: Terminal::PkH(hash),
                ty: Type::from_pk_h(),
                ext: types::extra_props::ExtData::from_pk_h(),
            })),
            ty: Type::cast_check(Type::from_pk_h()).unwrap(),
            ext: ExtData::cast_check(ExtData::from_pk_h()).unwrap(),
        };

        script_rtt(pkh_ms, "76a914111111111111111111111111111111111111111188ac");
    }

    #[test]
    fn true_false() {
        roundtrip(&ms_str!("1"), "Script(OP_PUSHNUM_1)");
        roundtrip(
            &ms_str!("tv:1"),
            "Script(OP_PUSHNUM_1 OP_VERIFY OP_PUSHNUM_1)",
        );
        roundtrip(&ms_str!("0"), "Script(OP_0)");

        assert!(Miniscript::<bitcoin::PublicKey>::from_str("1()").is_err());
        assert!(Miniscript::<bitcoin::PublicKey>::from_str("tv:1()").is_err());
    }

    #[test]
    fn serialize() {
        let keys = pubkeys(5);
        let dummy_hash = hash160::Hash::from_inner([0; 20]);

        roundtrip(
            &ms_str!("c:pk_h({})", dummy_hash),
            "\
             Script(OP_DUP OP_HASH160 OP_PUSHBYTES_20 \
             0000000000000000000000000000000000000000 \
             OP_EQUALVERIFY OP_CHECKSIG)\
             ",
        );

        roundtrip(
            &ms_str!("c:pk({})", keys[0]),
            "Script(OP_PUSHBYTES_33 028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa OP_CHECKSIG)"
        );
        roundtrip(
            &ms_str!("thresh_m(3,{},{},{},{},{})", keys[0], keys[1], keys[2], keys[3], keys[4]),
            "Script(OP_PUSHNUM_3 OP_PUSHBYTES_33 028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa OP_PUSHBYTES_33 03ab1ac1872a38a2f196bed5a6047f0da2c8130fe8de49fc4d5dfb201f7611d8e2 OP_PUSHBYTES_33 039729247032c0dfcf45b4841fcd72f6e9a2422631fc3466cf863e87154754dd40 OP_PUSHBYTES_33 032564fe9b5beef82d3703a607253f31ef8ea1b365772df434226aee642651b3fa OP_PUSHBYTES_33 0289637f97580a796e050791ad5a2f27af1803645d95df021a3c2d82eb8c2ca7ff OP_PUSHNUM_5 OP_CHECKMULTISIG)"
        );

        // Liquid policy
        roundtrip(
            &ms_str!("or_d(thresh_m(2,{},{}),and_v(v:thresh_m(2,{},{}),older(10000)))",
                      keys[0].to_string(),
                      keys[1].to_string(),
                      keys[3].to_string(),
                      keys[4].to_string()),
            "Script(OP_PUSHNUM_2 OP_PUSHBYTES_33 028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa \
                                  OP_PUSHBYTES_33 03ab1ac1872a38a2f196bed5a6047f0da2c8130fe8de49fc4d5dfb201f7611d8e2 \
                                  OP_PUSHNUM_2 OP_CHECKMULTISIG \
                     OP_IFDUP OP_NOTIF \
                         OP_PUSHNUM_2 OP_PUSHBYTES_33 032564fe9b5beef82d3703a607253f31ef8ea1b365772df434226aee642651b3fa \
                                      OP_PUSHBYTES_33 0289637f97580a796e050791ad5a2f27af1803645d95df021a3c2d82eb8c2ca7ff \
                                      OP_PUSHNUM_2 OP_CHECKMULTISIGVERIFY \
                         OP_PUSHBYTES_2 1027 OP_CSV \
                     OP_ENDIF)"
        );

        let miniscript: Miniscript<bitcoin::PublicKey> = ms_str!(
            "or_d(thresh_m(3,{},{},{}),and_v(v:thresh_m(2,{},{}),older(10000)))",
            keys[0].to_string(),
            keys[1].to_string(),
            keys[2].to_string(),
            keys[3].to_string(),
            keys[4].to_string(),
        );

        let mut abs = miniscript.lift();
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

        roundtrip(&ms_str!("older(921)"), "Script(OP_PUSHBYTES_2 9903 OP_CSV)");

        roundtrip(
            &ms_str!("sha256({})",sha256::Hash::hash(&[])),
            "Script(OP_SIZE OP_PUSHBYTES_1 20 OP_EQUALVERIFY OP_SHA256 OP_PUSHBYTES_32 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 OP_EQUAL)"
        );

        roundtrip(
            &ms_str!(
                "thresh_m(3,{},{},{},{},{})",
                keys[0],
                keys[1],
                keys[2],
                keys[3],
                keys[4]
            ),
            "Script(OP_PUSHNUM_3 \
             OP_PUSHBYTES_33 028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa \
             OP_PUSHBYTES_33 03ab1ac1872a38a2f196bed5a6047f0da2c8130fe8de49fc4d5dfb201f7611d8e2 \
             OP_PUSHBYTES_33 039729247032c0dfcf45b4841fcd72f6e9a2422631fc3466cf863e87154754dd40 \
             OP_PUSHBYTES_33 032564fe9b5beef82d3703a607253f31ef8ea1b365772df434226aee642651b3fa \
             OP_PUSHBYTES_33 0289637f97580a796e050791ad5a2f27af1803645d95df021a3c2d82eb8c2ca7ff \
             OP_PUSHNUM_5 OP_CHECKMULTISIG)",
        );
    }

    #[test]
    fn deserialize() {
        // Most of these came from fuzzing, hence the increasing lengths
        assert!(Miniscript::parse(&hex_script("")).is_err()); // empty
        assert!(Miniscript::parse(&hex_script("00")).is_ok()); // FALSE
        assert!(Miniscript::parse(&hex_script("51")).is_ok()); // TRUE
        assert!(Miniscript::parse(&hex_script("69")).is_err()); // VERIFY
        assert!(Miniscript::parse(&hex_script("0000")).is_err()); //and_v(FALSE,FALSE)
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
        ))
        .is_err());
    }
}
