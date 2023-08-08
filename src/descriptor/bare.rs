// SPDX-License-Identifier: CC0-1.0

//! # Bare Output Descriptors
//!
//! Implementation of Bare Descriptors (i.e descriptors that are)
//! wrapped inside wsh, or sh fragments.
//! Also includes pk, and pkh descriptors
//!

use core::fmt;

use bitcoin::script::{self, PushBytes};
use bitcoin::{Address, Network, ScriptBuf};

use super::checksum::{self, verify_checksum};
use crate::expression::{self, FromTree};
use crate::miniscript::context::{Context, ContextError};
use crate::policy::{semantic, Liftable};
use crate::prelude::*;
use crate::util::{varint_len, witness_to_scriptsig};
use crate::{
    BareCtx, Error, ForEachKey, Key, Miniscript, Satisfier, ToPublicKey, TranslateErr, TranslatePk,
    Translator,
};

/// Create a Bare Descriptor. That is descriptor that is
/// not wrapped in sh or wsh. This covers the Pk descriptor
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Bare<Pk: Key> {
    /// underlying miniscript
    ms: Miniscript<Pk, BareCtx>,
}

impl<Pk: Key> Bare<Pk> {
    /// Create a new raw descriptor
    pub fn new(ms: Miniscript<Pk, BareCtx>) -> Result<Self, Error> {
        // do the top-level checks
        BareCtx::top_level_checks(&ms)?;
        Ok(Self { ms })
    }

    /// get the inner
    pub fn into_inner(self) -> Miniscript<Pk, BareCtx> {
        self.ms
    }

    /// get the inner
    pub fn as_inner(&self) -> &Miniscript<Pk, BareCtx> {
        &self.ms
    }

    /// Checks whether the descriptor is safe.
    pub fn sanity_check(&self) -> Result<(), Error> {
        self.ms.sanity_check()?;
        Ok(())
    }

    /// Computes an upper bound on the difference between a non-satisfied
    /// `TxIn`'s `segwit_weight` and a satisfied `TxIn`'s `segwit_weight`
    ///
    /// Since this method uses `segwit_weight` instead of `legacy_weight`,
    /// if you want to include only legacy inputs in your transaction,
    /// you should remove 1WU from each input's `max_weight_to_satisfy`
    /// for a more accurate estimate.
    ///
    /// Assumes all ECDSA signatures are 73 bytes, including push opcode and
    /// sighash suffix.
    ///
    /// # Errors
    /// When the descriptor is impossible to safisfy (ex: sh(OP_FALSE)).
    pub fn max_weight_to_satisfy(&self) -> Result<usize, Error> {
        let scriptsig_size = self.ms.max_satisfaction_size()?;
        // scriptSig varint difference between non-satisfied (0) and satisfied
        let scriptsig_varint_diff = varint_len(scriptsig_size) - varint_len(0);
        Ok(4 * (scriptsig_varint_diff + scriptsig_size))
    }

    /// Computes an upper bound on the weight of a satisfying witness to the
    /// transaction.
    ///
    /// Assumes all ec-signatures are 73 bytes, including push opcode and
    /// sighash suffix. Includes the weight of the VarInts encoding the
    /// scriptSig and witness stack length.
    ///
    /// # Errors
    /// When the descriptor is impossible to safisfy (ex: sh(OP_FALSE)).
    #[deprecated(note = "use max_weight_to_satisfy instead")]
    pub fn max_satisfaction_weight(&self) -> Result<usize, Error> {
        let scriptsig_len = self.ms.max_satisfaction_size()?;
        Ok(4 * (varint_len(scriptsig_len) + scriptsig_len))
    }
}

impl<Pk: Key + ToPublicKey> Bare<Pk> {
    /// Obtains the corresponding script pubkey for this descriptor.
    pub fn script_pubkey(&self) -> ScriptBuf {
        self.ms.encode()
    }

    /// Obtains the underlying miniscript for this descriptor.
    pub fn inner_script(&self) -> ScriptBuf {
        self.script_pubkey()
    }

    /// Obtains the pre bip-340 signature script code for this descriptor.
    pub fn ecdsa_sighash_script_code(&self) -> ScriptBuf {
        self.script_pubkey()
    }

    /// Returns satisfying non-malleable witness and scriptSig with minimum
    /// weight to spend an output controlled by the given descriptor if it is
    /// possible to construct one using the `satisfier`.
    pub fn get_satisfaction<S>(&self, satisfier: S) -> Result<(Vec<Vec<u8>>, ScriptBuf), Error>
    where
        S: Satisfier<Pk>,
    {
        let ms = self.ms.satisfy(satisfier)?;
        let script_sig = witness_to_scriptsig(&ms);
        let witness = vec![];
        Ok((witness, script_sig))
    }

    /// Returns satisfying, possibly malleable, witness and scriptSig with
    /// minimum weight to spend an output controlled by the given descriptor if
    /// it is possible to construct one using the `satisfier`.
    pub fn get_satisfaction_mall<S>(&self, satisfier: S) -> Result<(Vec<Vec<u8>>, ScriptBuf), Error>
    where
        S: Satisfier<Pk>,
    {
        let ms = self.ms.satisfy_malleable(satisfier)?;
        let script_sig = witness_to_scriptsig(&ms);
        let witness = vec![];
        Ok((witness, script_sig))
    }
}

impl<Pk: Key> fmt::Debug for Bare<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.ms)
    }
}

impl<Pk: Key> fmt::Display for Bare<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use fmt::Write;
        let mut wrapped_f = checksum::Formatter::new(f);
        write!(wrapped_f, "{}", self.ms)?;
        wrapped_f.write_checksum_if_not_alt()
    }
}

impl<Pk: Key> Liftable<Pk> for Bare<Pk> {
    fn lift(&self) -> Result<semantic::Policy<Pk>, Error> {
        self.ms.lift()
    }
}

impl_from_tree!(
    Bare<Pk>,
    fn from_tree(top: &expression::Tree) -> Result<Self, Error> {
        let sub = Miniscript::<Pk, BareCtx>::from_tree(top)?;
        BareCtx::top_level_checks(&sub)?;
        Bare::new(sub)
    }
);

impl_from_str!(
    Bare<Pk>,
    type Err = Error;,
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let desc_str = verify_checksum(s)?;
        let top = expression::Tree::from_str(desc_str)?;
        Self::from_tree(&top)
    }
);

impl<Pk: Key> ForEachKey<Pk> for Bare<Pk> {
    fn for_each_key<'a, F: FnMut(&'a Pk) -> bool>(&'a self, pred: F) -> bool {
        self.ms.for_each_key(pred)
    }
}

impl<P: Key, Q: Key> TranslatePk<P, Q> for Bare<P> {
    type Output = Bare<Q>;

    fn translate_pk<T, E>(&self, t: &mut T) -> Result<Bare<Q>, TranslateErr<E>>
    where
        T: Translator<P, Q, E>,
    {
        Bare::new(self.ms.translate_pk(t)?).map_err(TranslateErr::OuterError)
    }
}

/// A bare PkH descriptor at top level
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Pkh<Pk: Key> {
    /// underlying publickey
    pk: Pk,
}

impl<Pk: Key> Pkh<Pk> {
    /// Create a new Pkh descriptor
    pub fn new(pk: Pk) -> Result<Self, ContextError> {
        // do the top-level checks
        match BareCtx::check_pk(&pk) {
            Ok(()) => Ok(Pkh { pk }),
            Err(e) => Err(e),
        }
    }

    /// Get a reference to the inner key
    pub fn as_inner(&self) -> &Pk {
        &self.pk
    }

    /// Get the inner key
    pub fn into_inner(self) -> Pk {
        self.pk
    }

    /// Computes an upper bound on the difference between a non-satisfied
    /// `TxIn`'s `segwit_weight` and a satisfied `TxIn`'s `segwit_weight`
    ///
    /// Since this method uses `segwit_weight` instead of `legacy_weight`,
    /// if you want to include only legacy inputs in your transaction,
    /// you should remove 1WU from each input's `max_weight_to_satisfy`
    /// for a more accurate estimate.
    ///
    /// Assumes all ECDSA signatures are 73 bytes, including push opcode and
    /// sighash suffix.
    ///
    /// # Errors
    /// When the descriptor is impossible to safisfy (ex: sh(OP_FALSE)).
    pub fn max_weight_to_satisfy(&self) -> usize {
        // OP_72 + <sig(71)+sigHash(1)> + OP_33 + <pubkey>
        let scriptsig_size = 73 + BareCtx::pk_len(&self.pk);
        // scriptSig varint different between non-satisfied (0) and satisfied
        let scriptsig_varint_diff = varint_len(scriptsig_size) - varint_len(0);
        4 * (scriptsig_varint_diff + scriptsig_size)
    }

    /// Computes an upper bound on the weight of a satisfying witness to the
    /// transaction.
    ///
    /// Assumes all ec-signatures are 73 bytes, including push opcode and
    /// sighash suffix. Includes the weight of the VarInts encoding the
    /// scriptSig and witness stack length.
    pub fn max_satisfaction_weight(&self) -> usize {
        4 * (1 + 73 + BareCtx::pk_len(&self.pk))
    }
}

impl<Pk: Key + ToPublicKey> Pkh<Pk> {
    /// Obtains the corresponding script pubkey for this descriptor.
    pub fn script_pubkey(&self) -> ScriptBuf {
        // Fine to hard code the `Network` here because we immediately call
        // `script_pubkey` which does not use the `network` field of `Address`.
        let addr = self.address(Network::Bitcoin);
        addr.script_pubkey()
    }

    /// Obtains the corresponding script pubkey for this descriptor.
    pub fn address(&self, network: Network) -> Address {
        Address::p2pkh(&self.pk.to_public_key(), network)
    }

    /// Obtains the underlying miniscript for this descriptor.
    pub fn inner_script(&self) -> ScriptBuf {
        self.script_pubkey()
    }

    /// Obtains the pre bip-340 signature script code for this descriptor.
    pub fn ecdsa_sighash_script_code(&self) -> ScriptBuf {
        self.script_pubkey()
    }

    /// Returns satisfying non-malleable witness and scriptSig with minimum
    /// weight to spend an output controlled by the given descriptor if it is
    /// possible to construct one using the `satisfier`.
    pub fn get_satisfaction<S>(&self, satisfier: S) -> Result<(Vec<Vec<u8>>, ScriptBuf), Error>
    where
        S: Satisfier<Pk>,
    {
        if let Some(sig) = satisfier.lookup_ecdsa_sig(&self.pk) {
            let script_sig = script::Builder::new()
                .push_slice::<&PushBytes>(
                    // serialize() does not allocate here
                    sig.serialize().as_ref(),
                )
                .push_key(&self.pk.to_public_key())
                .into_script();
            let witness = vec![];
            Ok((witness, script_sig))
        } else {
            Err(Error::MissingSig(self.pk.to_public_key()))
        }
    }

    /// Returns satisfying, possibly malleable, witness and scriptSig with
    /// minimum weight to spend an output controlled by the given descriptor if
    /// it is possible to construct one using the `satisfier`.
    pub fn get_satisfaction_mall<S>(&self, satisfier: S) -> Result<(Vec<Vec<u8>>, ScriptBuf), Error>
    where
        S: Satisfier<Pk>,
    {
        self.get_satisfaction(satisfier)
    }
}

impl<Pk: Key> fmt::Debug for Pkh<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "pkh({:?})", self.pk)
    }
}

impl<Pk: Key> fmt::Display for Pkh<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use fmt::Write;
        let mut wrapped_f = checksum::Formatter::new(f);
        write!(wrapped_f, "pkh({})", self.pk)?;
        wrapped_f.write_checksum_if_not_alt()
    }
}

impl<Pk: Key> Liftable<Pk> for Pkh<Pk> {
    fn lift(&self) -> Result<semantic::Policy<Pk>, Error> {
        Ok(semantic::Policy::Key(self.pk.clone()))
    }
}

impl_from_tree!(
    Pkh<Pk>,
    fn from_tree(top: &expression::Tree) -> Result<Self, Error> {
        if top.name == "pkh" && top.args.len() == 1 {
            Ok(Pkh::new(expression::terminal(&top.args[0], |pk| {
                Pk::from_str(pk)
            })?)?)
        } else {
            Err(Error::Unexpected(format!(
                "{}({} args) while parsing pkh descriptor",
                top.name,
                top.args.len(),
            )))
        }
    }
);

impl_from_str!(
    Pkh<Pk>,
    type Err = Error;,
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let desc_str = verify_checksum(s)?;
        let top = expression::Tree::from_str(desc_str)?;
        Self::from_tree(&top)
    }
);

impl<Pk: Key> ForEachKey<Pk> for Pkh<Pk> {
    fn for_each_key<'a, F: FnMut(&'a Pk) -> bool>(&'a self, mut pred: F) -> bool {
        pred(&self.pk)
    }
}

impl<P: Key, Q: Key> TranslatePk<P, Q> for Pkh<P> {
    type Output = Pkh<Q>;

    fn translate_pk<T, E>(&self, t: &mut T) -> Result<Self::Output, TranslateErr<E>>
    where
        T: Translator<P, Q, E>,
    {
        let res = Pkh::new(t.pk(&self.pk)?);
        match res {
            Ok(pk) => Ok(pk),
            Err(e) => Err(TranslateErr::OuterError(Error::from(e))),
        }
    }
}
