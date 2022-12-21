// Written in 2019 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! # Abstract Syntax Tree
//!
//! Defines a variety of data structures for describing Miniscript, a subset of
//! Bitcoin Script which can be efficiently parsed and serialized from Script,
//! and from which it is easy to extract data needed to construct witnesses.
//!
//! Users of the library in general will only need to use the structures exposed
//! from the top level of this module; however for people wanting to do advanced
//! things, the submodules are public as well which provide visibility into the
//! components of the AST.
//!

use core::marker::PhantomData;
use core::{fmt, hash, str};

use bitcoin::blockdata::script;
use bitcoin::util::taproot::{LeafVersion, TapLeafHash};

use self::analyzable::ExtParams;
pub use self::context::{BareCtx, Legacy, Segwitv0, Tap};
use crate::prelude::*;

pub mod analyzable;
pub mod astelem;
pub(crate) mod context;
pub mod decode;
pub mod hash256;
pub mod iter;
pub mod lex;
pub mod limits;
pub mod satisfy;
pub mod types;

use core::cmp;

use sync::Arc;

use self::lex::{lex, TokenIter};
use self::types::Property;
pub use crate::miniscript::context::ScriptContext;
use crate::miniscript::decode::Terminal;
use crate::miniscript::types::extra_props::ExtData;
use crate::miniscript::types::Type;
use crate::{expression, Error, ForEachKey, MiniscriptKey, ToPublicKey, TranslatePk, Translator};
#[cfg(test)]
mod ms_tests;

/// Top-level script AST type
#[derive(Clone)]
pub struct Miniscript<Pk: MiniscriptKey, Ctx: ScriptContext> {
    ///A node in the Abstract Syntax Tree(
    pub node: Terminal<Pk, Ctx>,
    ///The correctness and malleability type information for the AST node
    pub ty: types::Type,
    ///Additional information helpful for extra analysis.
    pub ext: types::extra_props::ExtData,
    /// Context PhantomData. Only accessible inside this crate
    pub(crate) phantom: PhantomData<Ctx>,
}

/// `PartialOrd` of `Miniscript` must depend only on node and not the type information.
/// The type information and extra_properties can be deterministically determined
/// by the ast.
impl<Pk: MiniscriptKey, Ctx: ScriptContext> PartialOrd for Miniscript<Pk, Ctx> {
    fn partial_cmp(&self, other: &Miniscript<Pk, Ctx>) -> Option<cmp::Ordering> {
        Some(self.node.cmp(&other.node))
    }
}

/// `Ord` of `Miniscript` must depend only on node and not the type information.
/// The type information and extra_properties can be deterministically determined
/// by the ast.
impl<Pk: MiniscriptKey, Ctx: ScriptContext> Ord for Miniscript<Pk, Ctx> {
    fn cmp(&self, other: &Miniscript<Pk, Ctx>) -> cmp::Ordering {
        self.node.cmp(&other.node)
    }
}

/// `PartialEq` of `Miniscript` must depend only on node and not the type information.
/// The type information and extra_properties can be deterministically determined
/// by the ast.
impl<Pk: MiniscriptKey, Ctx: ScriptContext> PartialEq for Miniscript<Pk, Ctx> {
    fn eq(&self, other: &Miniscript<Pk, Ctx>) -> bool {
        self.node.eq(&other.node)
    }
}

/// `Eq` of `Miniscript` must depend only on node and not the type information.
/// The type information and extra_properties can be deterministically determined
/// by the ast.
impl<Pk: MiniscriptKey, Ctx: ScriptContext> Eq for Miniscript<Pk, Ctx> {}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> fmt::Debug for Miniscript<Pk, Ctx> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.node)
    }
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> hash::Hash for Miniscript<Pk, Ctx> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.node.hash(state);
    }
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> Miniscript<Pk, Ctx> {
    /// Add type information(Type and Extdata) to Miniscript based on
    /// `AstElem` fragment. Dependent on display and clone because of Error
    /// Display code of type_check.
    pub fn from_ast(t: Terminal<Pk, Ctx>) -> Result<Miniscript<Pk, Ctx>, Error> {
        Ok(Miniscript {
            ty: Type::type_check(&t, |_| None)?,
            ext: ExtData::type_check(&t, |_| None)?,
            node: t,
            phantom: PhantomData,
        })
    }
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> fmt::Display for Miniscript<Pk, Ctx> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.node)
    }
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> Miniscript<Pk, Ctx> {
    /// Extracts the `AstElem` representing the root of the miniscript
    pub fn into_inner(self) -> Terminal<Pk, Ctx> {
        self.node
    }

    /// Get a reference to the inner `AstElem` representing the root of miniscript
    pub fn as_inner(&self) -> &Terminal<Pk, Ctx> {
        &self.node
    }
}

impl<Ctx: ScriptContext> Miniscript<Ctx::Key, Ctx> {
    /// Attempt to parse an insane(scripts don't clear sanity checks)
    /// script into a Miniscript representation.
    /// Use this to parse scripts with repeated pubkeys, timelock mixing, malleable
    /// scripts without sig or scripts that can exceed resource limits.
    /// Some of the analysis guarantees of miniscript are lost when dealing with
    /// insane scripts. In general, in a multi-party setting users should only
    /// accept sane scripts.
    pub fn parse_insane(script: &script::Script) -> Result<Miniscript<Ctx::Key, Ctx>, Error> {
        Miniscript::parse_with_ext(script, &ExtParams::insane())
    }

    /// Attempt to parse an miniscript with extra features that not yet specified in the spec.
    /// Users should not use this function unless they scripts can/will change in the future.
    /// Currently, this function supports the following features:
    ///     - Parsing all insane scripts
    ///     - Parsing miniscripts with raw pubkey hashes
    ///
    /// Allowed extra features can be specified by the ext [`ExtParams`] argument.
    pub fn parse_with_ext(
        script: &script::Script,
        ext: &ExtParams,
    ) -> Result<Miniscript<Ctx::Key, Ctx>, Error> {
        let tokens = lex(script)?;
        let mut iter = TokenIter::new(tokens);

        let top = decode::parse(&mut iter)?;
        Ctx::check_global_validity(&top)?;
        let type_check = types::Type::type_check(&top.node, |_| None)?;
        if type_check.corr.base != types::Base::B {
            return Err(Error::NonTopLevel(format!("{:?}", top)));
        };
        if let Some(leading) = iter.next() {
            Err(Error::Trailing(leading.to_string()))
        } else {
            top.ext_check(ext)?;
            Ok(top)
        }
    }

    /// Attempt to parse a Script into Miniscript representation.
    ///
    /// This function will fail parsing for scripts that do not clear the
    /// [`Miniscript::sanity_check`] checks. Use [`Miniscript::parse_insane`] to
    /// parse such scripts.
    ///
    /// ## Decode/Parse a miniscript from script hex
    ///
    /// ```rust
    /// use miniscript::{Miniscript, Segwitv0, Tap};
    /// use miniscript::bitcoin::secp256k1::XOnlyPublicKey;
    /// use miniscript::bitcoin::hashes::hex::FromHex;
    ///
    /// type Segwitv0Script = Miniscript<bitcoin::PublicKey, Segwitv0>;
    /// type TapScript = Miniscript<XOnlyPublicKey, Tap>;
    ///
    /// // parse x-only miniscript in Taproot context
    /// let tapscript_ms = TapScript::parse(&bitcoin::Script::from(Vec::<u8>::from_hex(
    ///     "202788ee41e76f4f3af603da5bc8fa22997bc0344bb0f95666ba6aaff0242baa99ac",
    /// ).expect("Even length hex")))
    ///     .expect("Xonly keys are valid only in taproot context");
    /// // tapscript fails decoding when we use them with compressed keys
    /// let err = TapScript::parse(&bitcoin::Script::from(Vec::<u8>::from_hex(
    ///     "21022788ee41e76f4f3af603da5bc8fa22997bc0344bb0f95666ba6aaff0242baa99ac",
    /// ).expect("Even length hex")))
    ///     .expect_err("Compressed keys cannot be used in Taproot context");
    /// // Segwitv0 succeeds decoding with full keys.
    /// Segwitv0Script::parse(&bitcoin::Script::from(Vec::<u8>::from_hex(
    ///     "21022788ee41e76f4f3af603da5bc8fa22997bc0344bb0f95666ba6aaff0242baa99ac",
    /// ).expect("Even length hex")))
    ///     .expect("Compressed keys are allowed in Segwit context");
    ///
    /// ```
    pub fn parse(script: &script::Script) -> Result<Miniscript<Ctx::Key, Ctx>, Error> {
        let ms = Self::parse_with_ext(script, &ExtParams::sane())?;
        Ok(ms)
    }
}

impl<Pk, Ctx> Miniscript<Pk, Ctx>
where
    Pk: MiniscriptKey,
    Ctx: ScriptContext,
{
    /// Encode as a Bitcoin script
    pub fn encode(&self) -> script::Script
    where
        Pk: ToPublicKey,
    {
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
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> Miniscript<Pk, Ctx> {
    /// Maximum number of witness elements used to satisfy the Miniscript
    /// fragment, including the witness script itself. Used to estimate
    /// the weight of the `VarInt` that specifies this number in a serialized
    /// transaction.
    ///
    /// This function may returns Error when the Miniscript is
    /// impossible to satisfy
    pub fn max_satisfaction_witness_elements(&self) -> Result<usize, Error> {
        self.ext
            .stack_elem_count_sat
            .map(|x| x + 1)
            .ok_or(Error::ImpossibleSatisfaction)
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
    pub fn max_satisfaction_size(&self) -> Result<usize, Error> {
        Ctx::max_satisfaction_size(self).ok_or(Error::ImpossibleSatisfaction)
    }
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> ForEachKey<Pk> for Miniscript<Pk, Ctx> {
    fn for_each_key<'a, F: FnMut(&'a Pk) -> bool>(&'a self, mut pred: F) -> bool
    where
        Pk: 'a,
    {
        self.real_for_each_key(&mut pred)
    }
}

impl<Pk, Q, Ctx> TranslatePk<Pk, Q> for Miniscript<Pk, Ctx>
where
    Pk: MiniscriptKey,
    Q: MiniscriptKey,
    Ctx: ScriptContext,
{
    type Output = Miniscript<Q, Ctx>;

    /// Translates a struct from one generic to another where the translation
    /// for Pk is provided by [`Translator`]
    fn translate_pk<T, E>(&self, translate: &mut T) -> Result<Self::Output, E>
    where
        T: Translator<Pk, Q, E>,
    {
        self.real_translate_pk(translate)
    }
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> Miniscript<Pk, Ctx> {
    fn real_for_each_key<'a, F: FnMut(&'a Pk) -> bool>(&'a self, pred: &mut F) -> bool
    where
        Pk: 'a,
    {
        self.node.real_for_each_key(pred)
    }

    pub(super) fn real_translate_pk<Q, CtxQ, T, FuncError>(
        &self,
        t: &mut T,
    ) -> Result<Miniscript<Q, CtxQ>, FuncError>
    where
        Q: MiniscriptKey,
        CtxQ: ScriptContext,
        T: Translator<Pk, Q, FuncError>,
    {
        let inner = self.node.real_translate_pk(t)?;
        let ms = Miniscript {
            //directly copying the type and ext is safe because translating public
            //key should not change any properties
            ty: self.ty,
            ext: self.ext,
            node: inner,
            phantom: PhantomData,
        };
        Ok(ms)
    }
}

impl_block_str!(
    ;Ctx; ScriptContext,
    Miniscript<Pk, Ctx>,
    /// Attempt to parse an insane(scripts don't clear sanity checks)
    /// from string into a Miniscript representation.
    /// Use this to parse scripts with repeated pubkeys, timelock mixing, malleable
    /// scripts without sig or scripts that can exceed resource limits.
    /// Some of the analysis guarantees of miniscript are lost when dealing with
    /// insane scripts. In general, in a multi-party setting users should only
    /// accept sane scripts.
    pub fn from_str_insane(s: &str,) -> Result<Miniscript<Pk, Ctx>, Error>
    {
        Miniscript::from_str_ext(s, &ExtParams::insane())
    }
);

impl_block_str!(
    ;Ctx; ScriptContext,
    Miniscript<Pk, Ctx>,
    /// Attempt to parse an Miniscripts that don't follow the spec.
    /// Use this to parse scripts with repeated pubkeys, timelock mixing, malleable
    /// scripts, raw pubkey hashes without sig or scripts that can exceed resource limits.
    ///
    /// Use [`ExtParams`] builder to specify the types of non-sane rules to allow while parsing.
    pub fn from_str_ext(s: &str, ext: &ExtParams,) -> Result<Miniscript<Pk, Ctx>, Error>
    {
        // This checks for invalid ASCII chars
        let top = expression::Tree::from_str(s)?;
        let ms: Miniscript<Pk, Ctx> = expression::FromTree::from_tree(&top)?;
        ms.ext_check(ext)?;

        if ms.ty.corr.base != types::Base::B {
            Err(Error::NonTopLevel(format!("{:?}", ms)))
        } else {
            Ok(ms)
        }
    }
);

impl<Pk: MiniscriptKey, Ctx: ScriptContext> Miniscript<Pk, Ctx> {
    /// Attempt to produce non-malleable satisfying witness for the
    /// witness script represented by the parse tree
    pub fn satisfy<S: satisfy::Satisfier<Pk>>(&self, satisfier: S) -> Result<Vec<Vec<u8>>, Error>
    where
        Pk: ToPublicKey,
    {
        // Only satisfactions for default versions (0xc0) are allowed.
        let leaf_hash = TapLeafHash::from_script(&self.encode(), LeafVersion::TapScript);
        match satisfy::Satisfaction::satisfy(&self.node, &satisfier, self.ty.mall.safe, &leaf_hash)
            .stack
        {
            satisfy::Witness::Stack(stack) => {
                Ctx::check_witness::<Pk>(&stack)?;
                Ok(stack)
            }
            satisfy::Witness::Unavailable | satisfy::Witness::Impossible => {
                Err(Error::CouldNotSatisfy)
            }
        }
    }

    /// Attempt to produce a malleable satisfying witness for the
    /// witness script represented by the parse tree
    pub fn satisfy_malleable<S: satisfy::Satisfier<Pk>>(
        &self,
        satisfier: S,
    ) -> Result<Vec<Vec<u8>>, Error>
    where
        Pk: ToPublicKey,
    {
        let leaf_hash = TapLeafHash::from_script(&self.encode(), LeafVersion::TapScript);
        match satisfy::Satisfaction::satisfy_mall(
            &self.node,
            &satisfier,
            self.ty.mall.safe,
            &leaf_hash,
        )
        .stack
        {
            satisfy::Witness::Stack(stack) => {
                Ctx::check_witness::<Pk>(&stack)?;
                Ok(stack)
            }
            satisfy::Witness::Unavailable | satisfy::Witness::Impossible => {
                Err(Error::CouldNotSatisfy)
            }
        }
    }
}

impl_from_tree!(
    ;Ctx; ScriptContext,
    Arc<Miniscript<Pk, Ctx>>,
    fn from_tree(top: &expression::Tree) -> Result<Arc<Miniscript<Pk, Ctx>>, Error> {
        Ok(Arc::new(expression::FromTree::from_tree(top)?))
    }
);

impl_from_tree!(
    ;Ctx; ScriptContext,
    Miniscript<Pk, Ctx>,
    /// Parse an expression tree into a Miniscript. As a general rule, this
    /// should not be called directly; rather go through the descriptor API.
    fn from_tree(top: &expression::Tree) -> Result<Miniscript<Pk, Ctx>, Error> {
        let inner: Terminal<Pk, Ctx> = expression::FromTree::from_tree(top)?;
        Ok(Miniscript {
            ty: Type::type_check(&inner, |_| None)?,
            ext: ExtData::type_check(&inner, |_| None)?,
            node: inner,
            phantom: PhantomData,
        })
    }
);

impl_from_str!(
    ;Ctx; ScriptContext,
    Miniscript<Pk, Ctx>,
    type Err = Error;,
    /// Parse a Miniscript from string and perform sanity checks
    /// See [Miniscript::from_str_insane] to parse scripts from string that
    /// do not clear the [Miniscript::sanity_check] checks.
    fn from_str(s: &str) -> Result<Miniscript<Pk, Ctx>, Error> {
        let ms = Self::from_str_ext(s, &ExtParams::sane())?;
        Ok(ms)
    }
);

serde_string_impl_pk!(Miniscript, "a miniscript", Ctx; ScriptContext);

#[cfg(test)]
mod tests {

    use core::marker::PhantomData;
    use core::str;
    use core::str::FromStr;

    use bitcoin::hashes::{hash160, sha256, Hash};
    use bitcoin::secp256k1::XOnlyPublicKey;
    use bitcoin::util::taproot::TapLeafHash;
    use bitcoin::{self, secp256k1, Sequence};
    use sync::Arc;

    use super::{Miniscript, ScriptContext, Segwitv0, Tap};
    use crate::miniscript::types::{self, ExtData, Property, Type};
    use crate::miniscript::Terminal;
    use crate::policy::Liftable;
    use crate::prelude::*;
    use crate::test_utils::{StrKeyTranslator, StrXOnlyKeyTranslator};
    use crate::{hex_script, DummyKey, ExtParams, Satisfier, ToPublicKey, TranslatePk};

    type Segwitv0Script = Miniscript<bitcoin::PublicKey, Segwitv0>;
    type Tapscript = Miniscript<bitcoin::secp256k1::XOnlyPublicKey, Tap>;

    fn pubkeys(n: usize) -> Vec<bitcoin::PublicKey> {
        let mut ret = Vec::with_capacity(n);
        let secp = secp256k1::Secp256k1::new();
        let mut sk = [0; 32];
        for i in 1..n + 1 {
            sk[0] = i as u8;
            sk[1] = (i >> 8) as u8;
            sk[2] = (i >> 16) as u8;

            let pk = bitcoin::PublicKey {
                inner: secp256k1::PublicKey::from_secret_key(
                    &secp,
                    &secp256k1::SecretKey::from_slice(&sk[..]).expect("secret key"),
                ),
                compressed: true,
            };
            ret.push(pk);
        }
        ret
    }

    fn string_rtt<Ctx: ScriptContext>(
        script: Miniscript<bitcoin::PublicKey, Ctx>,
        expected_debug: &str,
        expected_display: &str,
    ) {
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
    }

    fn string_display_debug_test<Ctx: ScriptContext>(
        script: Miniscript<bitcoin::PublicKey, Ctx>,
        expected_debug: &str,
        expected_display: &str,
    ) {
        assert_eq!(script.ty.corr.base, types::Base::B);
        let debug = format!("{:?}", script);
        let display = format!("{}", script);
        if let Some(expected) = expected_debug.into() {
            assert_eq!(debug, expected);
        }
        if let Some(expected) = expected_display.into() {
            assert_eq!(display, expected);
        }
    }

    fn dummy_string_rtt<Ctx: ScriptContext>(
        script: Miniscript<DummyKey, Ctx>,
        expected_debug: &str,
        expected_display: &str,
    ) {
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
    }

    fn script_rtt<Str1: Into<Option<&'static str>>>(script: Segwitv0Script, expected_hex: Str1) {
        assert_eq!(script.ty.corr.base, types::Base::B);
        let bitcoin_script = script.encode();
        assert_eq!(bitcoin_script.len(), script.script_size());
        if let Some(expected) = expected_hex.into() {
            assert_eq!(format!("{:x}", bitcoin_script), expected);
        }
        // Parse scripts with all extensions
        let roundtrip = Segwitv0Script::parse_with_ext(&bitcoin_script, &ExtParams::allow_all())
            .expect("parse string serialization");
        assert_eq!(roundtrip, script);
    }

    fn roundtrip(tree: &Segwitv0Script, s: &str) {
        assert_eq!(tree.ty.corr.base, types::Base::B);
        let ser = tree.encode();
        assert_eq!(ser.len(), tree.script_size());
        assert_eq!(ser.to_string(), s);
        let deser = Segwitv0Script::parse_insane(&ser).expect("deserialize result of serialize");
        assert_eq!(*tree, deser);
    }

    fn ms_attributes_test(
        ms: &str,
        expected_hex: &str,
        valid: bool,
        non_mal: bool,
        need_sig: bool,
        ops: usize,
        _stack: usize,
    ) {
        let ms: Result<Segwitv0Script, _> = Miniscript::from_str_insane(ms);
        match (ms, valid) {
            (Ok(ms), true) => {
                assert_eq!(format!("{:x}", ms.encode()), expected_hex);
                assert_eq!(ms.ty.mall.non_malleable, non_mal);
                assert_eq!(ms.ty.mall.safe, need_sig);
                assert_eq!(ms.ext.ops.op_count().unwrap(), ops);
            }
            (Err(_), false) => {}
            _ => unreachable!(),
        }
    }

    #[test]
    fn all_attribute_tests() {
        ms_attributes_test(
            "lltvln:after(1231488000)",
            "6300676300676300670400046749b1926869516868",
            true,
            true,
            false,
            12,
            3,
        );
        ms_attributes_test("uuj:and_v(v:multi(2,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a,025601570cb47f238d2b0286db4a990fa0f3ba28d1a319f5e7cf55c2a2444da7cc),after(1231488000))", "6363829263522103d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a21025601570cb47f238d2b0286db4a990fa0f3ba28d1a319f5e7cf55c2a2444da7cc52af0400046749b168670068670068", true, true, true, 14, 5);
        ms_attributes_test("or_b(un:multi(2,03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729,024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),al:older(16))", "63522103daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee872921024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c9752ae926700686b63006760b2686c9b", true, false, false, 14, 5);
        ms_attributes_test(
            "j:and_v(vdv:after(1567547623),older(2016))",
            "829263766304e7e06e5db169686902e007b268",
            true,
            true,
            false,
            11,
            1,
        );
        ms_attributes_test("t:and_v(vu:hash256(131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b),v:sha256(ec4916dd28fc4c10d78e287ca5d9cc51ee1ae73cbfde08c6b37324cbfaac8bc5))", "6382012088aa20131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b876700686982012088a820ec4916dd28fc4c10d78e287ca5d9cc51ee1ae73cbfde08c6b37324cbfaac8bc58851", true, true, false, 12, 3);
        ms_attributes_test("t:andor(multi(3,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e,03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556,02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13),v:older(4194305),v:sha256(9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2))", "532102d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e2103fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a14602975562102e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd1353ae6482012088a8209267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2886703010040b2696851", true, true, false, 13, 5);
        ms_attributes_test("or_d(multi(1,02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9),or_b(multi(3,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01,032fa2104d6b38d11b0230010559879124e42ab8dfeff5ff29dc9cdadd4ecacc3f,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a),su:after(500000)))", "512102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f951ae73645321022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a0121032fa2104d6b38d11b0230010559879124e42ab8dfeff5ff29dc9cdadd4ecacc3f2103d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a53ae7c630320a107b16700689b68", true, true, false, 15, 7);
        ms_attributes_test("or_d(sha256(38df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b6),and_n(un:after(499999999),older(4194305)))", "82012088a82038df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b68773646304ff64cd1db19267006864006703010040b26868", true, false, false, 16, 1);
        ms_attributes_test("and_v(or_i(v:multi(2,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb),v:multi(2,03e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc)),sha256(d1ec675902ef1633427ca360b290b0b3045a0d9058ddb5e648b4c3c3224c5c68))", "63522102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee52103774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb52af67522103e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a21025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc52af6882012088a820d1ec675902ef1633427ca360b290b0b3045a0d9058ddb5e648b4c3c3224c5c6887", true, true, true, 11, 5);
        ms_attributes_test("j:and_b(multi(2,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),s:or_i(older(1),older(4252898)))", "82926352210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179821024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c9752ae7c6351b26703e2e440b2689a68", true, false, true, 14, 4);
        ms_attributes_test("and_b(older(16),s:or_d(sha256(e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f),n:after(1567547623)))", "60b27c82012088a820e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f87736404e7e06e5db192689a", true, false, false, 12, 1);
        ms_attributes_test("j:and_v(v:hash160(20195b5a3d650c17f0f29f91c33f8f6335193d07),or_d(sha256(96de8fc8c256fa1e1556d41af431cace7dca68707c78dd88c3acab8b17164c47),older(16)))", "82926382012088a91420195b5a3d650c17f0f29f91c33f8f6335193d078882012088a82096de8fc8c256fa1e1556d41af431cace7dca68707c78dd88c3acab8b17164c4787736460b26868", true, false, false, 16, 2);
        ms_attributes_test("and_b(hash256(32ba476771d01e37807990ead8719f08af494723de1d228f2c2c07cc0aa40bac),a:and_b(hash256(131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b),a:older(1)))", "82012088aa2032ba476771d01e37807990ead8719f08af494723de1d228f2c2c07cc0aa40bac876b82012088aa20131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b876b51b26c9a6c9a", true, true, false, 15, 2);
        ms_attributes_test("thresh(2,multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),a:multi(1,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),ac:pk_k(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01))", "522103a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c721036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a0052ae6b5121036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a0051ae6c936b21022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01ac6c935287", true, true, true, 13, 6);
        ms_attributes_test("and_n(sha256(d1ec675902ef1633427ca360b290b0b3045a0d9058ddb5e648b4c3c3224c5c68),t:or_i(v:older(4252898),v:older(144)))", "82012088a820d1ec675902ef1633427ca360b290b0b3045a0d9058ddb5e648b4c3c3224c5c68876400676303e2e440b26967029000b269685168", true, false, false, 14, 2);
        ms_attributes_test("or_d(nd:and_v(v:older(4252898),v:older(4252898)),sha256(38df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b6))", "766303e2e440b26903e2e440b2696892736482012088a82038df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b68768", true, false, false, 15, 2);
        ms_attributes_test("c:and_v(or_c(sha256(9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2),v:multi(1,02c44d12c7065d812e8acf28d7cbb19f9011ecd9e9fdf281b0e6a3b5e87d22e7db)),pk_k(03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe))", "82012088a8209267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed28764512102c44d12c7065d812e8acf28d7cbb19f9011ecd9e9fdf281b0e6a3b5e87d22e7db51af682103acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbeac", true, false, true, 9, 2);
        ms_attributes_test("c:and_v(or_c(multi(2,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00,02352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5),v:ripemd160(1b0f3c404d12075c68c938f9f60ebea4f74941a0)),pk_k(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))", "5221036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a002102352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d552ae6482012088a6141b0f3c404d12075c68c938f9f60ebea4f74941a088682103fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556ac", true, true, true, 10, 5);
        ms_attributes_test("and_v(andor(hash256(8a35d9ca92a48eaade6f53a64985e9e2afeb74dcf8acb4c3721e0dc7e4294b25),v:hash256(939894f70e6c3a25da75da0cc2071b4076d9b006563cf635986ada2e93c0d735),v:older(50000)),after(499999999))", "82012088aa208a35d9ca92a48eaade6f53a64985e9e2afeb74dcf8acb4c3721e0dc7e4294b2587640350c300b2696782012088aa20939894f70e6c3a25da75da0cc2071b4076d9b006563cf635986ada2e93c0d735886804ff64cd1db1", true, false, false, 14, 2);
        ms_attributes_test("andor(hash256(5f8d30e655a7ba0d7596bb3ddfb1d2d20390d23b1845000e1e118b3be1b3f040),j:and_v(v:hash160(3a2bff0da9d96868e66abc4427bea4691cf61ccd),older(4194305)),ripemd160(44d90e2d3714c8663b632fcf0f9d5f22192cc4c8))", "82012088aa205f8d30e655a7ba0d7596bb3ddfb1d2d20390d23b1845000e1e118b3be1b3f040876482012088a61444d90e2d3714c8663b632fcf0f9d5f22192cc4c8876782926382012088a9143a2bff0da9d96868e66abc4427bea4691cf61ccd8803010040b26868", true, false, false, 20, 2);
        ms_attributes_test("or_i(c:and_v(v:after(500000),pk_k(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)),sha256(d9147961436944f43cd99d28b2bbddbf452ef872b30c8279e255e7daafc7f946))", "630320a107b1692102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ac6782012088a820d9147961436944f43cd99d28b2bbddbf452ef872b30c8279e255e7daafc7f9468768", true, true, false, 10, 2);
        ms_attributes_test("thresh(2,c:pk_h(03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729),s:sha256(e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f),a:hash160(dd69735817e0e3f6f826a9238dc2e291184f0131))", "76a91420d637c1a6404d2227f3561fdbaff5a680dba64888ac7c82012088a820e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f87936b82012088a914dd69735817e0e3f6f826a9238dc2e291184f0131876c935287", true, false, false, 18, 4);
        ms_attributes_test("and_n(sha256(9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2),uc:and_v(v:older(144),pk_k(03fe72c435413d33d48ac09c9161ba8b09683215439d62b7940502bda8b202e6ce)))", "82012088a8209267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed28764006763029000b2692103fe72c435413d33d48ac09c9161ba8b09683215439d62b7940502bda8b202e6ceac67006868", true, false, true, 13, 3);
        ms_attributes_test("and_n(c:pk_k(03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729),and_b(l:older(4252898),a:older(16)))", "2103daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729ac64006763006703e2e440b2686b60b26c9a68", true, true, true, 12, 2);
        ms_attributes_test("c:or_i(and_v(v:older(16),pk_h(03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729)),pk_h(02352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5))", "6360b26976a91420d637c1a6404d2227f3561fdbaff5a680dba648886776a9148f9dff39a81ee4abcbad2ad8bafff090415a2be88868ac", true, true, true, 12, 3);
        ms_attributes_test("or_d(c:pk_h(02352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5),andor(c:pk_k(024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),older(2016),after(1567547623)))", "76a9148f9dff39a81ee4abcbad2ad8bafff090415a2be888ac736421024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97ac6404e7e06e5db16702e007b26868", true, true, false, 13, 3);
        ms_attributes_test("c:andor(ripemd160(6ad07d21fd5dfc646f0b30577045ce201616b9ba),pk_h(03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729),and_v(v:hash256(8a35d9ca92a48eaade6f53a64985e9e2afeb74dcf8acb4c3721e0dc7e4294b25),pk_h(02352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5)))", "82012088a6146ad07d21fd5dfc646f0b30577045ce201616b9ba876482012088aa208a35d9ca92a48eaade6f53a64985e9e2afeb74dcf8acb4c3721e0dc7e4294b258876a9148f9dff39a81ee4abcbad2ad8bafff090415a2be8886776a91420d637c1a6404d2227f3561fdbaff5a680dba6488868ac", true, false, true, 18, 3);
        ms_attributes_test("c:andor(u:ripemd160(6ad07d21fd5dfc646f0b30577045ce201616b9ba),pk_h(03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729),or_i(pk_h(024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),pk_h(02352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5)))", "6382012088a6146ad07d21fd5dfc646f0b30577045ce201616b9ba87670068646376a914385defb0ed10fe95817943ed37b4984f8f4255d6886776a9148f9dff39a81ee4abcbad2ad8bafff090415a2be888686776a91420d637c1a6404d2227f3561fdbaff5a680dba6488868ac", true, false, true, 23, 4);
        ms_attributes_test("c:or_i(andor(c:pk_h(02352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5),pk_h(024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),pk_h(03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729)),pk_k(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))", "6376a9148f9dff39a81ee4abcbad2ad8bafff090415a2be888ac6476a91420d637c1a6404d2227f3561fdbaff5a680dba648886776a914385defb0ed10fe95817943ed37b4984f8f4255d68868672103fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a146029755668ac", true, true, true, 17, 5);
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

        let pkk_ms: Miniscript<DummyKey, Segwitv0> = Miniscript {
            node: Terminal::Check(Arc::new(Miniscript {
                node: Terminal::PkK(DummyKey),
                ty: Type::from_pk_k::<Segwitv0>(),
                ext: types::extra_props::ExtData::from_pk_k::<Segwitv0>(),
                phantom: PhantomData,
            })),
            ty: Type::cast_check(Type::from_pk_k::<Segwitv0>()).unwrap(),
            ext: ExtData::cast_check(ExtData::from_pk_k::<Segwitv0>()).unwrap(),
            phantom: PhantomData,
        };
        dummy_string_rtt(pkk_ms, "[B/onduesm]c:[K/onduesm]pk_k(DummyKey)", "pk()");

        let pkh_ms: Miniscript<DummyKey, Segwitv0> = Miniscript {
            node: Terminal::Check(Arc::new(Miniscript {
                node: Terminal::PkH(DummyKey),
                ty: Type::from_pk_h::<Segwitv0>(),
                ext: types::extra_props::ExtData::from_pk_h::<Segwitv0>(),
                phantom: PhantomData,
            })),
            ty: Type::cast_check(Type::from_pk_h::<Segwitv0>()).unwrap(),
            ext: ExtData::cast_check(ExtData::from_pk_h::<Segwitv0>()).unwrap(),
            phantom: PhantomData,
        };

        let expected_debug = "[B/nduesm]c:[K/nduesm]pk_h(DummyKey)";
        let expected_display = "pkh()";

        assert_eq!(pkh_ms.ty.corr.base, types::Base::B);
        let debug = format!("{:?}", pkh_ms);
        let display = format!("{}", pkh_ms);
        if let Some(expected) = expected_debug.into() {
            assert_eq!(debug, expected);
        }
        if let Some(expected) = expected_display.into() {
            assert_eq!(display, expected);
        }

        let pkk_ms: Segwitv0Script = Miniscript {
            node: Terminal::Check(Arc::new(Miniscript {
                node: Terminal::PkK(pk),
                ty: Type::from_pk_k::<Segwitv0>(),
                ext: types::extra_props::ExtData::from_pk_k::<Segwitv0>(),
                phantom: PhantomData,
            })),
            ty: Type::cast_check(Type::from_pk_k::<Segwitv0>()).unwrap(),
            ext: ExtData::cast_check(ExtData::from_pk_k::<Segwitv0>()).unwrap(),
            phantom: PhantomData,
        };

        script_rtt(
            pkk_ms,
            "21020202020202020202020202020202020202020202020202020202020\
             202020202ac",
        );

        let pkh_ms: Segwitv0Script = Miniscript {
            node: Terminal::Check(Arc::new(Miniscript {
                node: Terminal::RawPkH(hash),
                ty: Type::from_pk_h::<Segwitv0>(),
                ext: types::extra_props::ExtData::from_pk_h::<Segwitv0>(),
                phantom: PhantomData,
            })),
            ty: Type::cast_check(Type::from_pk_h::<Segwitv0>()).unwrap(),
            ext: ExtData::cast_check(ExtData::from_pk_h::<Segwitv0>()).unwrap(),
            phantom: PhantomData,
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
        roundtrip(
            &ms_str!("andor(0,1,0)"),
            "Script(OP_0 OP_NOTIF OP_0 OP_ELSE OP_PUSHNUM_1 OP_ENDIF)",
        );

        assert!(Segwitv0Script::from_str("1()").is_err());
        assert!(Segwitv0Script::from_str("tv:1()").is_err());
    }

    #[test]
    fn verify_parse() {
        let ms = "and_v(v:hash160(20195b5a3d650c17f0f29f91c33f8f6335193d07),or_d(sha256(96de8fc8c256fa1e1556d41af431cace7dca68707c78dd88c3acab8b17164c47),older(16)))";
        let ms: Segwitv0Script = Miniscript::from_str_insane(ms).unwrap();
        assert_eq!(ms, Segwitv0Script::parse_insane(&ms.encode()).unwrap());

        let ms = "and_v(v:sha256(96de8fc8c256fa1e1556d41af431cace7dca68707c78dd88c3acab8b17164c47),or_d(sha256(96de8fc8c256fa1e1556d41af431cace7dca68707c78dd88c3acab8b17164c47),older(16)))";
        let ms: Segwitv0Script = Miniscript::from_str_insane(ms).unwrap();
        assert_eq!(ms, Segwitv0Script::parse_insane(&ms.encode()).unwrap());

        let ms = "and_v(v:ripemd160(20195b5a3d650c17f0f29f91c33f8f6335193d07),or_d(sha256(96de8fc8c256fa1e1556d41af431cace7dca68707c78dd88c3acab8b17164c47),older(16)))";
        let ms: Segwitv0Script = Miniscript::from_str_insane(ms).unwrap();
        assert_eq!(ms, Segwitv0Script::parse_insane(&ms.encode()).unwrap());

        let ms = "and_v(v:hash256(96de8fc8c256fa1e1556d41af431cace7dca68707c78dd88c3acab8b17164c47),or_d(sha256(96de8fc8c256fa1e1556d41af431cace7dca68707c78dd88c3acab8b17164c47),older(16)))";
        let ms: Segwitv0Script = Miniscript::from_str_insane(ms).unwrap();
        assert_eq!(ms, Segwitv0Script::parse_insane(&ms.encode()).unwrap());
    }

    #[test]
    fn pk_alias() {
        let pubkey = pubkeys(1)[0];

        let script: Segwitv0Script = ms_str!("c:pk_k({})", pubkey.to_string());

        string_rtt(
            script,
            "[B/onduesm]c:[K/onduesm]pk_k(PublicKey { compressed: true, inner: PublicKey(aa4c32e50fb34a95a372940ae3654b692ea35294748c3dd2c08b29f87ba9288c8294efcb73dc719e45b91c45f084e77aebc07c1ff3ed8f37935130a36304a340) })",
            "pk(028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa)"
        );

        let script: Segwitv0Script = ms_str!("pk({})", pubkey.to_string());

        string_rtt(
            script,
            "[B/onduesm]c:[K/onduesm]pk_k(PublicKey { compressed: true, inner: PublicKey(aa4c32e50fb34a95a372940ae3654b692ea35294748c3dd2c08b29f87ba9288c8294efcb73dc719e45b91c45f084e77aebc07c1ff3ed8f37935130a36304a340) })",
            "pk(028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa)"
        );

        let script: Segwitv0Script = ms_str!("tv:pk({})", pubkey.to_string());

        string_rtt(
            script,
            "[B/onufsm]t[V/onfsm]v[B/onduesm]c:[K/onduesm]pk_k(PublicKey { compressed: true, inner: PublicKey(aa4c32e50fb34a95a372940ae3654b692ea35294748c3dd2c08b29f87ba9288c8294efcb73dc719e45b91c45f084e77aebc07c1ff3ed8f37935130a36304a340) })",
            "tv:pk(028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa)"
        );

        let script: Segwitv0Script = ms_str!("c:pk_h({})", pubkey.to_string());

        string_display_debug_test(
            script,
            "[B/nduesm]c:[K/nduesm]pk_h(PublicKey { compressed: true, inner: PublicKey(aa4c32e50fb34a95a372940ae3654b692ea35294748c3dd2c08b29f87ba9288c8294efcb73dc719e45b91c45f084e77aebc07c1ff3ed8f37935130a36304a340) })",
            "pkh(028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa)",
        );

        let script: Segwitv0Script = ms_str!("pkh({})", pubkey.to_string());

        string_display_debug_test(
            script,
            "[B/nduesm]c:[K/nduesm]pk_h(PublicKey { compressed: true, inner: PublicKey(aa4c32e50fb34a95a372940ae3654b692ea35294748c3dd2c08b29f87ba9288c8294efcb73dc719e45b91c45f084e77aebc07c1ff3ed8f37935130a36304a340) })",
            "pkh(028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa)",
        );

        let script: Segwitv0Script = ms_str!("tv:pkh({})", pubkey.to_string());

        string_display_debug_test(
            script,
            "[B/nufsm]t[V/nfsm]v[B/nduesm]c:[K/nduesm]pk_h(PublicKey { compressed: true, inner: PublicKey(aa4c32e50fb34a95a372940ae3654b692ea35294748c3dd2c08b29f87ba9288c8294efcb73dc719e45b91c45f084e77aebc07c1ff3ed8f37935130a36304a340) })",
            "tv:pkh(028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa)",
        );
    }

    #[test]
    fn serialize() {
        let keys = pubkeys(6);

        let tree: &Segwitv0Script = &ms_str!("c:pk_h({})", keys[5]);
        assert_eq!(tree.ty.corr.base, types::Base::B);
        let ser = tree.encode();
        let s = "\
             Script(OP_DUP OP_HASH160 OP_PUSHBYTES_20 \
             7e5a2a6a7610ca4ea78bd65a087bd75b1870e319 \
             OP_EQUALVERIFY OP_CHECKSIG)\
             ";
        assert_eq!(ser.len(), tree.script_size());
        assert_eq!(ser.to_string(), s);

        roundtrip(
            &ms_str!("pk({})", keys[0]),
            "Script(OP_PUSHBYTES_33 028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa OP_CHECKSIG)"
        );
        roundtrip(
            &ms_str!("multi(3,{},{},{},{},{})", keys[0], keys[1], keys[2], keys[3], keys[4]),
            "Script(OP_PUSHNUM_3 OP_PUSHBYTES_33 028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa OP_PUSHBYTES_33 03ab1ac1872a38a2f196bed5a6047f0da2c8130fe8de49fc4d5dfb201f7611d8e2 OP_PUSHBYTES_33 039729247032c0dfcf45b4841fcd72f6e9a2422631fc3466cf863e87154754dd40 OP_PUSHBYTES_33 032564fe9b5beef82d3703a607253f31ef8ea1b365772df434226aee642651b3fa OP_PUSHBYTES_33 0289637f97580a796e050791ad5a2f27af1803645d95df021a3c2d82eb8c2ca7ff OP_PUSHNUM_5 OP_CHECKMULTISIG)"
        );

        // Liquid policy
        roundtrip(
            &ms_str!("or_d(multi(2,{},{}),and_v(v:multi(2,{},{}),older(10000)))",
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

        let miniscript: Segwitv0Script = ms_str!(
            "or_d(multi(3,{},{},{}),and_v(v:multi(2,{},{}),older(10000)))",
            keys[0].to_string(),
            keys[1].to_string(),
            keys[2].to_string(),
            keys[3].to_string(),
            keys[4].to_string(),
        );

        let mut abs = miniscript.lift().unwrap();
        assert_eq!(abs.n_keys(), 5);
        assert_eq!(abs.minimum_n_keys(), Some(2));
        abs = abs.at_age(Sequence::from_height(10000));
        assert_eq!(abs.n_keys(), 5);
        assert_eq!(abs.minimum_n_keys(), Some(2));
        abs = abs.at_age(Sequence::from_height(9999));
        assert_eq!(abs.n_keys(), 3);
        assert_eq!(abs.minimum_n_keys(), Some(3));
        abs = abs.at_age(Sequence::ZERO);
        assert_eq!(abs.n_keys(), 3);
        assert_eq!(abs.minimum_n_keys(), Some(3));

        roundtrip(&ms_str!("older(921)"), "Script(OP_PUSHBYTES_2 9903 OP_CSV)");

        roundtrip(
            &ms_str!("sha256({})",sha256::Hash::hash(&[])),
            "Script(OP_SIZE OP_PUSHBYTES_1 20 OP_EQUALVERIFY OP_SHA256 OP_PUSHBYTES_32 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 OP_EQUAL)"
        );

        roundtrip(
            &ms_str!(
                "multi(3,{},{},{},{},{})",
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

        roundtrip(
            &ms_str!(
                "t:and_v(\
                     vu:hash256(131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b),\
                     v:sha256(ec4916dd28fc4c10d78e287ca5d9cc51ee1ae73cbfde08c6b37324cbfaac8bc5)\
                 )"),
            "Script(OP_IF OP_SIZE OP_PUSHBYTES_1 20 OP_EQUALVERIFY OP_HASH256 OP_PUSHBYTES_32 131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b OP_EQUAL OP_ELSE OP_0 OP_ENDIF OP_VERIFY OP_SIZE OP_PUSHBYTES_1 20 OP_EQUALVERIFY OP_SHA256 OP_PUSHBYTES_32 ec4916dd28fc4c10d78e287ca5d9cc51ee1ae73cbfde08c6b37324cbfaac8bc5 OP_EQUALVERIFY OP_PUSHNUM_1)"
        );
        roundtrip(
            &ms_str!("and_n(pk(03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729),and_b(l:older(4252898),a:older(16)))"),
            "Script(OP_PUSHBYTES_33 03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729 OP_CHECKSIG OP_NOTIF OP_0 OP_ELSE OP_IF OP_0 OP_ELSE OP_PUSHBYTES_3 e2e440 OP_CSV OP_ENDIF OP_TOALTSTACK OP_PUSHNUM_16 OP_CSV OP_FROMALTSTACK OP_BOOLAND OP_ENDIF)"
        );
        roundtrip(
            &ms_str!(
                "t:andor(multi(\
                    3,\
                    02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e,\
                    03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556,\
                    02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13\
                 ),\
                 v:older(4194305),\
                 v:sha256(9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2)\
                 )"),
            "Script(OP_PUSHNUM_3 OP_PUSHBYTES_33 02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e \
             OP_PUSHBYTES_33 03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556 \
             OP_PUSHBYTES_33 02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13 \
             OP_PUSHNUM_3 OP_CHECKMULTISIG OP_NOTIF OP_SIZE OP_PUSHBYTES_1 20 OP_EQUALVERIFY OP_SHA256 \
             OP_PUSHBYTES_32 9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2 OP_EQUALVERIFY \
             OP_ELSE OP_PUSHBYTES_3 010040 OP_CSV OP_VERIFY OP_ENDIF OP_PUSHNUM_1)"
        );
        roundtrip(
            &ms_str!(
                "t:and_v(\
                    vu:hash256(131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b),\
                    v:sha256(ec4916dd28fc4c10d78e287ca5d9cc51ee1ae73cbfde08c6b37324cbfaac8bc5)\
                 )"),
            "Script(\
             OP_IF OP_SIZE OP_PUSHBYTES_1 20 OP_EQUALVERIFY OP_HASH256 OP_PUSHBYTES_32 131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b OP_EQUAL \
             OP_ELSE OP_0 OP_ENDIF OP_VERIFY OP_SIZE OP_PUSHBYTES_1 20 OP_EQUALVERIFY OP_SHA256 OP_PUSHBYTES_32 ec4916dd28fc4c10d78e287ca5d9cc51ee1ae73cbfde08c6b37324cbfaac8bc5 OP_EQUALVERIFY \
             OP_PUSHNUM_1\
             )"
        );

        // Thresh bug with equal verify roundtrip
        roundtrip(
            &ms_str!("tv:thresh(1,pk(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e))", ),
            "Script(OP_PUSHBYTES_33 02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e OP_CHECKSIG OP_PUSHNUM_1 OP_EQUALVERIFY OP_PUSHNUM_1)",
        );
    }

    #[test]
    fn deserialize() {
        // Most of these came from fuzzing, hence the increasing lengths
        assert!(Segwitv0Script::parse_insane(&hex_script("")).is_err()); // empty
        assert!(Segwitv0Script::parse_insane(&hex_script("00")).is_ok()); // FALSE
        assert!(Segwitv0Script::parse_insane(&hex_script("51")).is_ok()); // TRUE
        assert!(Segwitv0Script::parse_insane(&hex_script("69")).is_err()); // VERIFY
        assert!(Segwitv0Script::parse_insane(&hex_script("0000")).is_err()); //and_v(FALSE,FALSE)
        assert!(Segwitv0Script::parse_insane(&hex_script("1001")).is_err()); // incomplete push
        assert!(Segwitv0Script::parse_insane(&hex_script("03990300b2")).is_err()); // non-minimal #
        assert!(Segwitv0Script::parse_insane(&hex_script("8559b2")).is_err()); // leading bytes
        assert!(Segwitv0Script::parse_insane(&hex_script("4c0169b2")).is_err()); // non-minimal push
        assert!(Segwitv0Script::parse_insane(&hex_script("0000af0000ae85")).is_err()); // OR not BOOLOR

        // misc fuzzer problems
        assert!(Segwitv0Script::parse_insane(&hex_script("0000000000af")).is_err());
        assert!(Segwitv0Script::parse_insane(&hex_script("04009a2970af00")).is_err()); // giant CMS key num
        assert!(Segwitv0Script::parse_insane(&hex_script(
            "2102ffffffffffffffefefefefefefefefefefef394c0fe5b711179e124008584753ac6900"
        ))
        .is_err());
    }

    #[test]
    fn non_ascii() {
        assert!(Segwitv0Script::from_str_insane("🌏")
            .unwrap_err()
            .to_string()
            .contains("unprintable character"));
    }

    #[test]
    fn test_tapscript_rtt() {
        // Test x-only invalid under segwitc0 context
        let ms = Segwitv0Script::from_str_insane(
            "pk(2788ee41e76f4f3af603da5bc8fa22997bc0344bb0f95666ba6aaff0242baa99)",
        );
        assert_eq!(
            ms.unwrap_err().to_string(),
            "unexpected «key hex decoding error»",
        );
        Tapscript::from_str_insane(
            "pk(2788ee41e76f4f3af603da5bc8fa22997bc0344bb0f95666ba6aaff0242baa99)",
        )
        .unwrap();

        // Now test that bitcoin::PublicKey works with Taproot context
        Miniscript::<bitcoin::PublicKey, Tap>::from_str_insane(
            "pk(022788ee41e76f4f3af603da5bc8fa22997bc0344bb0f95666ba6aaff0242baa99)",
        )
        .unwrap();

        // uncompressed keys should not be allowed
        Miniscript::<bitcoin::PublicKey, Tap>::from_str_insane(
            "pk(04eed24a081bf1b1e49e3300df4bebe04208ac7e516b6f3ea8eb6e094584267c13483f89dcf194132e12238cc5a34b6b286fc7990d68ed1db86b69ebd826c63b29)"
        )
        .unwrap_err();

        //---------------- test script <-> miniscript ---------------
        // Test parsing from scripts: x-only fails decoding in segwitv0 ctx
        Segwitv0Script::parse_insane(&hex_script(
            "202788ee41e76f4f3af603da5bc8fa22997bc0344bb0f95666ba6aaff0242baa99ac",
        ))
        .unwrap_err();
        // x-only succeeds in tap ctx
        Tapscript::parse_insane(&hex_script(
            "202788ee41e76f4f3af603da5bc8fa22997bc0344bb0f95666ba6aaff0242baa99ac",
        ))
        .unwrap();
        // tapscript fails decoding with compressed
        Tapscript::parse_insane(&hex_script(
            "21022788ee41e76f4f3af603da5bc8fa22997bc0344bb0f95666ba6aaff0242baa99ac",
        ))
        .unwrap_err();
        // Segwitv0 succeeds decoding with tapscript.
        Segwitv0Script::parse_insane(&hex_script(
            "21022788ee41e76f4f3af603da5bc8fa22997bc0344bb0f95666ba6aaff0242baa99ac",
        ))
        .unwrap();

        // multi not allowed in tapscript
        Tapscript::from_str_insane(
            "multi(1,2788ee41e76f4f3af603da5bc8fa22997bc0344bb0f95666ba6aaff0242baa99)",
        )
        .unwrap_err();
        // but allowed in segwit
        Segwitv0Script::from_str_insane(
            "multi(1,022788ee41e76f4f3af603da5bc8fa22997bc0344bb0f95666ba6aaff0242baa99)",
        )
        .unwrap();
    }

    #[test]
    fn multi_a_tests() {
        // Test from string tests
        type Segwitv0Ms = Miniscript<String, Segwitv0>;
        type TapMs = Miniscript<String, Tap>;
        let segwit_multi_a_ms = Segwitv0Ms::from_str_insane("multi_a(1,A,B,C)");
        assert_eq!(
            segwit_multi_a_ms.unwrap_err().to_string(),
            "Multi a(CHECKSIGADD) only allowed post tapscript"
        );
        let tap_multi_a_ms = TapMs::from_str_insane("multi_a(1,A,B,C)").unwrap();
        assert_eq!(tap_multi_a_ms.to_string(), "multi_a(1,A,B,C)");

        // Test encode/decode and translation tests
        let tap_ms = tap_multi_a_ms
            .translate_pk(&mut StrXOnlyKeyTranslator::new())
            .unwrap();
        // script rtt test
        assert_eq!(
            Miniscript::<XOnlyPublicKey, Tap>::parse_insane(&tap_ms.encode()).unwrap(),
            tap_ms
        );
        assert_eq!(tap_ms.script_size(), 104);
        assert_eq!(tap_ms.encode().len(), tap_ms.script_size());

        // Test satisfaction code
        struct SimpleSatisfier(secp256k1::schnorr::Signature);

        // a simple satisfier that always outputs the same signature
        impl<Pk: ToPublicKey> Satisfier<Pk> for SimpleSatisfier {
            fn lookup_tap_leaf_script_sig(
                &self,
                _pk: &Pk,
                _h: &TapLeafHash,
            ) -> Option<bitcoin::SchnorrSig> {
                Some(bitcoin::SchnorrSig {
                    sig: self.0,
                    hash_ty: bitcoin::SchnorrSighashType::Default,
                })
            }
        }

        let schnorr_sig = secp256k1::schnorr::Signature::from_str("84526253c27c7aef56c7b71a5cd25bebb66dddda437826defc5b2568bde81f0784526253c27c7aef56c7b71a5cd25bebb66dddda437826defc5b2568bde81f07").unwrap();
        let s = SimpleSatisfier(schnorr_sig);

        let wit = tap_ms.satisfy(s).unwrap();
        assert_eq!(wit, vec![schnorr_sig.as_ref().to_vec(), vec![], vec![]]);
    }

    #[test]
    fn decode_bug_cpp_review() {
        let ms = Miniscript::<String, Segwitv0>::from_str_insane(
            "and_b(1,s:and_v(v:older(9),c:pk_k(A)))",
        )
        .unwrap();
        let ms_trans = ms.translate_pk(&mut StrKeyTranslator::new()).unwrap();
        let enc = ms_trans.encode();
        let ms = Miniscript::<bitcoin::PublicKey, Segwitv0>::parse_insane(&enc).unwrap();
        assert_eq!(ms_trans.encode(), ms.encode());
    }

    #[test]
    fn expr_features() {
        // test that parsing raw hash160 does not work with
        let hash160_str = "e9f171df53e04b270fa6271b42f66b0f4a99c5a2";
        let ms_str = &format!("c:expr_raw_pkh({})", hash160_str);
        type SegwitMs = Miniscript<bitcoin::PublicKey, Segwitv0>;

        // Test that parsing raw hash160 from string does not work without extra features
        SegwitMs::from_str(ms_str).unwrap_err();
        SegwitMs::from_str_insane(ms_str).unwrap_err();
        let ms = SegwitMs::from_str_ext(ms_str, &ExtParams::allow_all()).unwrap();

        let script = ms.encode();
        // The same test, but parsing from script
        SegwitMs::parse(&script).unwrap_err();
        SegwitMs::parse_insane(&script).unwrap_err();
        SegwitMs::parse_with_ext(&script, &ExtParams::allow_all()).unwrap();
    }
}
