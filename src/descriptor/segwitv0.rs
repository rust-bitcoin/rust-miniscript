// SPDX-License-Identifier: CC0-1.0

//! # Segwit Output Descriptors
//!
//! Implementation of Segwit Descriptors. Contains the implementation
//! of wsh, wpkh and sortedmulti inside wsh.

use core::convert::TryFrom;
use core::fmt;

use bitcoin::{Address, Network, ScriptBuf, Weight};

use crate::descriptor::write_descriptor;
use crate::expression::{self, FromTree};
use crate::miniscript::context::{ScriptContext, ScriptContextError};
use crate::miniscript::limits::MAX_PUBKEYS_PER_MULTISIG;
use crate::miniscript::satisfy::{Placeholder, Satisfaction, Witness};
use crate::plan::AssetProvider;
use crate::policy::{Liftable, Semantic};
use crate::prelude::*;
use crate::util::varint_len;
use crate::{
    Error, ForEachKey, FromStrKey, Miniscript, MiniscriptKey, Satisfier, Segwitv0, Terminal,
    Threshold, ToPublicKey, TranslateErr, Translator,
};
/// A Segwitv0 wsh descriptor
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Wsh<Pk: MiniscriptKey> {
    /// underlying miniscript
    ms: Miniscript<Pk, Segwitv0>,
}

impl<Pk: MiniscriptKey> Wsh<Pk> {
    /// Get the inner Miniscript
    pub fn into_inner(self) -> Miniscript<Pk, Segwitv0> { self.ms }

    /// Get a reference to inner Miniscript
    pub fn as_inner(&self) -> &Miniscript<Pk, Segwitv0> { &self.ms }

    /// Create a new wsh descriptor
    pub fn new(ms: Miniscript<Pk, Segwitv0>) -> Result<Self, Error> {
        // do the top-level checks
        Segwitv0::top_level_checks(&ms)?;
        Ok(Self { ms })
    }

    /// Create a new sortedmulti wsh descriptor
    pub fn new_sortedmulti(thresh: Threshold<Pk, MAX_PUBKEYS_PER_MULTISIG>) -> Result<Self, Error> {
        Ok(Self { ms: Miniscript::sortedmulti(thresh) })
    }

    /// Get the descriptor without the checksum
    #[deprecated(since = "8.0.0", note = "use format!(\"{:#}\") instead")]
    pub fn to_string_no_checksum(&self) -> String { format!("{:#}", self) }

    /// Checks whether the descriptor is safe.
    pub fn sanity_check(&self) -> Result<(), Error> {
        self.ms.sanity_check()?;
        Ok(())
    }

    /// Computes an upper bound on the difference between a non-satisfied
    /// `TxIn`'s `segwit_weight` and a satisfied `TxIn`'s `segwit_weight`
    ///
    /// Assumes all ECDSA signatures are 73 bytes, including push opcode and
    /// sighash suffix.
    ///
    /// # Errors
    /// When the descriptor is impossible to safisfy (ex: sh(OP_FALSE)).
    pub fn max_weight_to_satisfy(&self) -> Result<Weight, Error> {
        let (redeem_script_size, max_sat_elems, max_sat_size) = (
            self.ms.script_size(),
            self.ms.max_satisfaction_witness_elements()?,
            self.ms.max_satisfaction_size()?,
        );
        // stack size varint difference between non-satisfied (0) and satisfied
        // `max_sat_elems` is inclusive of the "witness script" (redeem script)
        let stack_varint_diff = varint_len(max_sat_elems) - varint_len(0);

        Ok(Weight::from_wu(
            (stack_varint_diff + varint_len(redeem_script_size) + redeem_script_size + max_sat_size)
                as u64,
        ))
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
    #[deprecated(
        since = "10.0.0",
        note = "Use max_weight_to_satisfy instead. The method to count bytes was redesigned and the results will differ from max_weight_to_satisfy. For more details check rust-bitcoin/rust-miniscript#476."
    )]
    pub fn max_satisfaction_weight(&self) -> Result<usize, Error> {
        let (script_size, max_sat_elems, max_sat_size) = (
            self.ms.script_size(),
            self.ms.max_satisfaction_witness_elements()?,
            self.ms.max_satisfaction_size()?,
        );
        Ok(4 +  // scriptSig length byte
            varint_len(script_size) +
            script_size +
            varint_len(max_sat_elems) +
            max_sat_size)
    }

    /// Converts the keys in a script from one type to another.
    pub fn translate_pk<T>(&self, t: &mut T) -> Result<Wsh<T::TargetPk>, TranslateErr<T::Error>>
    where
        T: Translator<Pk>,
    {
        Ok(Wsh { ms: self.ms.translate_pk(t)? })
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> Wsh<Pk> {
    /// Obtains the corresponding script pubkey for this descriptor.
    pub fn script_pubkey(&self) -> ScriptBuf { self.inner_script().to_p2wsh() }

    /// Obtains the corresponding script pubkey for this descriptor.
    pub fn address(&self, network: Network) -> Address {
        Address::p2wsh(&self.ms.encode(), network)
    }

    /// Obtains the underlying miniscript for this descriptor.
    pub fn inner_script(&self) -> ScriptBuf { self.ms.encode() }

    /// Obtains the pre bip-340 signature script code for this descriptor.
    pub fn ecdsa_sighash_script_code(&self) -> ScriptBuf { self.inner_script() }

    /// Returns satisfying non-malleable witness and scriptSig with minimum
    /// weight to spend an output controlled by the given descriptor if it is
    /// possible to construct one using the `satisfier`.
    pub fn get_satisfaction<S>(&self, satisfier: S) -> Result<(Vec<Vec<u8>>, ScriptBuf), Error>
    where
        S: Satisfier<Pk>,
    {
        let mut witness = self.ms.satisfy(satisfier)?;
        let witness_script = self.inner_script();
        witness.push(witness_script.into_bytes());
        let script_sig = ScriptBuf::new();
        Ok((witness, script_sig))
    }

    /// Returns satisfying, possibly malleable, witness and scriptSig with
    /// minimum weight to spend an output controlled by the given descriptor if
    /// it is possible to construct one using the `satisfier`.
    pub fn get_satisfaction_mall<S>(&self, satisfier: S) -> Result<(Vec<Vec<u8>>, ScriptBuf), Error>
    where
        S: Satisfier<Pk>,
    {
        let mut witness = self.ms.satisfy_malleable(satisfier)?;
        witness.push(self.inner_script().into_bytes());
        let script_sig = ScriptBuf::new();
        Ok((witness, script_sig))
    }

    /// Returns a plan if the provided assets are sufficient to produce a non-malleable satisfaction
    pub fn plan_satisfaction<P>(&self, provider: &P) -> Satisfaction<Placeholder<Pk>>
    where
        P: AssetProvider<Pk>,
    {
        self.ms.build_template(provider)
    }

    /// Returns a plan if the provided assets are sufficient to produce a malleable satisfaction
    pub fn plan_satisfaction_mall<P>(&self, provider: &P) -> Satisfaction<Placeholder<Pk>>
    where
        P: AssetProvider<Pk>,
    {
        if let Terminal::SortedMulti(..) = self.ms.node {
            self.ms.build_template(provider)
        } else {
            self.ms.build_template_mall(provider)
        }
    }
}

impl<Pk: MiniscriptKey> Liftable<Pk> for Wsh<Pk> {
    fn lift(&self) -> Result<Semantic<Pk>, Error> { self.ms.lift() }
}

impl<Pk: FromStrKey> crate::expression::FromTree for Wsh<Pk> {
    fn from_tree(top: expression::TreeIterItem) -> Result<Self, Error> {
        let top = top
            .verify_toplevel("wsh", 1..=1)
            .map_err(From::from)
            .map_err(Error::Parse)?;

        let sub = Miniscript::from_tree(top)?;
        Segwitv0::top_level_checks(&sub)?;
        Ok(Self { ms: sub })
    }
}

impl<Pk: MiniscriptKey> fmt::Debug for Wsh<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "wsh({:?})", self.ms) }
}

impl<Pk: MiniscriptKey> fmt::Display for Wsh<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_descriptor!(f, "wsh({})", self.ms)
    }
}

impl<Pk: FromStrKey> core::str::FromStr for Wsh<Pk> {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let top = expression::Tree::from_str(s)?;
        Self::from_tree(top.root())
    }
}

impl<Pk: MiniscriptKey> ForEachKey<Pk> for Wsh<Pk> {
    fn for_each_key<'a, F: FnMut(&'a Pk) -> bool>(&'a self, pred: F) -> bool {
        self.ms.for_each_key(pred)
    }
}

/// A bare Wpkh descriptor at top level
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Wpkh<Pk: MiniscriptKey> {
    /// underlying publickey
    pk: Pk,
}

impl<Pk: MiniscriptKey> Wpkh<Pk> {
    /// Create a new Wpkh descriptor
    pub fn new(pk: Pk) -> Result<Self, ScriptContextError> {
        // do the top-level checks
        match Segwitv0::check_pk(&pk) {
            Ok(_) => Ok(Self { pk }),
            Err(e) => Err(e),
        }
    }

    /// Get the inner key
    pub fn into_inner(self) -> Pk { self.pk }

    /// Get the inner key
    pub fn as_inner(&self) -> &Pk { &self.pk }

    /// Get the descriptor without the checksum
    #[deprecated(since = "8.0.0", note = "use format!(\"{:#}\") instead")]
    pub fn to_string_no_checksum(&self) -> String { format!("{:#}", self) }

    /// Checks whether the descriptor is safe.
    pub fn sanity_check(&self) -> Result<(), Error> {
        if self.pk.is_uncompressed() {
            Err(Error::ContextError(ScriptContextError::CompressedOnly(self.pk.to_string())))
        } else {
            Ok(())
        }
    }

    /// Computes an upper bound on the difference between a non-satisfied
    /// `TxIn`'s `segwit_weight` and a satisfied `TxIn`'s `segwit_weight`
    ///
    /// Assumes all ec-signatures are 73 bytes, including push opcode and
    /// sighash suffix.
    pub fn max_weight_to_satisfy(&self) -> Weight {
        // stack items: <varint(sig+sigHash)> <sig(71)+sigHash(1)> <varint(pubkey)> <pubkey>
        let stack_items_size = 73 + Segwitv0::pk_len(&self.pk);
        // stackLen varint difference between non-satisfied (0) and satisfied
        let stack_varint_diff = varint_len(2) - varint_len(0);
        Weight::from_wu((stack_varint_diff + stack_items_size) as u64)
    }

    /// Computes an upper bound on the weight of a satisfying witness to the
    /// transaction.
    ///
    /// Assumes all ec-signatures are 73 bytes, including push opcode and
    /// sighash suffix. Includes the weight of the VarInts encoding the
    /// scriptSig and witness stack length.
    #[deprecated(
        since = "10.0.0",
        note = "Use max_weight_to_satisfy instead. The method to count bytes was redesigned and the results will differ from max_weight_to_satisfy. For more details check rust-bitcoin/rust-miniscript#476."
    )]
    pub fn max_satisfaction_weight(&self) -> usize { 4 + 1 + 73 + Segwitv0::pk_len(&self.pk) }

    /// Converts the keys in a script from one type to another.
    pub fn translate_pk<T>(&self, t: &mut T) -> Result<Wpkh<T::TargetPk>, TranslateErr<T::Error>>
    where
        T: Translator<Pk>,
    {
        let res = Wpkh::new(t.pk(&self.pk)?);
        match res {
            Ok(pk) => Ok(pk),
            Err(e) => Err(TranslateErr::OuterError(Error::from(e))),
        }
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> Wpkh<Pk> {
    /// Obtains the corresponding script pubkey for this descriptor.
    pub fn script_pubkey(&self) -> ScriptBuf {
        let pk = self.pk.to_public_key();
        let compressed = bitcoin::key::CompressedPublicKey::try_from(pk)
            .expect("wpkh descriptors have compressed keys");

        let addr = Address::p2wpkh(&compressed, Network::Bitcoin);
        addr.script_pubkey()
    }

    /// Obtains the corresponding script pubkey for this descriptor.
    pub fn address(&self, network: Network) -> Address {
        let pk = self.pk.to_public_key();
        let compressed = bitcoin::key::CompressedPublicKey::try_from(pk)
            .expect("Rust Miniscript types don't allow uncompressed pks in segwit descriptors");

        Address::p2wpkh(&compressed, network)
    }

    /// Obtains the underlying miniscript for this descriptor.
    pub fn inner_script(&self) -> ScriptBuf { self.script_pubkey() }

    /// Obtains the pre bip-340 signature script code for this descriptor.
    pub fn ecdsa_sighash_script_code(&self) -> ScriptBuf {
        // For SegWit outputs, it is defined by bip-0143 (quoted below) and is different from
        // the previous txo's scriptPubKey.
        // The item 5:
        //     - For P2WPKH witness program, the scriptCode is `0x1976a914{20-byte-pubkey-hash}88ac`.
        let addr = Address::p2pkh(self.pk.to_public_key(), Network::Bitcoin);
        addr.script_pubkey()
    }

    /// Returns satisfying non-malleable witness and scriptSig with minimum
    /// weight to spend an output controlled by the given descriptor if it is
    /// possible to construct one using the `satisfier`.
    pub fn get_satisfaction<S>(&self, satisfier: S) -> Result<(Vec<Vec<u8>>, ScriptBuf), Error>
    where
        S: Satisfier<Pk>,
    {
        if let Some(sig) = satisfier.lookup_ecdsa_sig(&self.pk) {
            let sig_vec = sig.to_vec();
            let script_sig = ScriptBuf::new();
            let witness = vec![sig_vec, self.pk.to_public_key().to_bytes()];
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

    /// Returns a plan if the provided assets are sufficient to produce a non-malleable satisfaction
    pub fn plan_satisfaction<P>(&self, provider: &P) -> Satisfaction<Placeholder<Pk>>
    where
        P: AssetProvider<Pk>,
    {
        let stack = if provider.provider_lookup_ecdsa_sig(&self.pk) {
            let stack = vec![
                Placeholder::EcdsaSigPk(self.pk.clone()),
                Placeholder::Pubkey(self.pk.clone(), Segwitv0::pk_len(&self.pk)),
            ];
            Witness::Stack(stack)
        } else {
            Witness::Unavailable
        };

        Satisfaction { stack, has_sig: true, relative_timelock: None, absolute_timelock: None }
    }

    /// Returns a plan if the provided assets are sufficient to produce a malleable satisfaction
    pub fn plan_satisfaction_mall<P>(&self, provider: &P) -> Satisfaction<Placeholder<Pk>>
    where
        P: AssetProvider<Pk>,
    {
        self.plan_satisfaction(provider)
    }
}

impl<Pk: MiniscriptKey> fmt::Debug for Wpkh<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "wpkh({:?})", self.pk) }
}

impl<Pk: MiniscriptKey> fmt::Display for Wpkh<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_descriptor!(f, "wpkh({})", self.pk)
    }
}

impl<Pk: MiniscriptKey> Liftable<Pk> for Wpkh<Pk> {
    fn lift(&self) -> Result<Semantic<Pk>, Error> { Ok(Semantic::Key(self.pk.clone())) }
}

impl<Pk: FromStrKey> crate::expression::FromTree for Wpkh<Pk> {
    fn from_tree(top: expression::TreeIterItem) -> Result<Self, Error> {
        let pk = top
            .verify_terminal_parent("wpkh", "public key")
            .map_err(Error::Parse)?;
        Self::new(pk).map_err(Error::ContextError)
    }
}

impl<Pk: FromStrKey> core::str::FromStr for Wpkh<Pk> {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let top = expression::Tree::from_str(s)?;
        Self::from_tree(top.root())
    }
}

impl<Pk: MiniscriptKey> ForEachKey<Pk> for Wpkh<Pk> {
    fn for_each_key<'a, F: FnMut(&'a Pk) -> bool>(&'a self, mut pred: F) -> bool { pred(&self.pk) }
}
