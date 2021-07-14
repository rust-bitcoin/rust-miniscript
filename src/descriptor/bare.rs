// Miniscript
// Written in 2020 by rust-miniscript developers
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

//! # Bare Output Descriptors
//!
//! Implementation of Bare Descriptors (i.e descriptors that are)
//! wrapped inside wsh, or sh fragments.
//! Also includes pk, and pkh descriptors
//!

use std::{fmt, str::FromStr};

use bitcoin::{self, blockdata::script, Script};

use expression::{self, FromTree};
use miniscript::context::ScriptContext;
use policy::{semantic, Liftable};
use util::{varint_len, witness_to_scriptsig};
use {
    BareCtx, Error, ForEach, ForEachKey, Miniscript, MiniscriptKey, Satisfier, ToPublicKey,
    TranslatePk,
};

use super::{
    checksum::{desc_checksum, verify_checksum},
    DescriptorTrait,
};

/// Create a Bare Descriptor. That is descriptor that is
/// not wrapped in sh or wsh. This covers the Pk descriptor
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Bare<Pk: MiniscriptKey> {
    /// underlying miniscript
    ms: Miniscript<Pk, BareCtx>,
}

impl<Pk: MiniscriptKey> Bare<Pk> {
    /// Create a new raw descriptor
    pub fn new(ms: Miniscript<Pk, BareCtx>) -> Result<Self, Error> {
        // do the top-level checks
        BareCtx::top_level_checks(&ms)?;
        Ok(Self { ms: ms })
    }

    /// get the inner
    pub fn into_inner(self) -> Miniscript<Pk, BareCtx> {
        self.ms
    }

    /// get the inner
    pub fn as_inner(&self) -> &Miniscript<Pk, BareCtx> {
        &self.ms
    }
}

impl<'a, Pk: MiniscriptKey> IntoIterator for &'a Bare<Pk> {
    type Item = &'a Pk;
    type IntoIter = Box<dyn Iterator<Item = &'a Pk> + 'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.ms.into_iter()
    }
}

impl<Pk: MiniscriptKey> fmt::Debug for Bare<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.ms)
    }
}

impl<Pk: MiniscriptKey> fmt::Display for Bare<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let desc = format!("{}", self.ms);
        let checksum = desc_checksum(&desc).map_err(|_| fmt::Error)?;
        write!(f, "{}#{}", &desc, &checksum)
    }
}

impl<Pk: MiniscriptKey> Liftable<Pk> for Bare<Pk> {
    fn lift(&self) -> Result<semantic::Policy<Pk>, Error> {
        self.ms.lift()
    }
}

impl<Pk> FromTree for Bare<Pk>
where
    Pk: MiniscriptKey + FromStr,
    Pk::Hash: FromStr,
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    fn from_tree(top: &expression::Tree) -> Result<Self, Error> {
        let sub = Miniscript::<Pk, BareCtx>::from_tree(&top)?;
        BareCtx::top_level_checks(&sub)?;
        Bare::new(sub)
    }
}

impl<Pk> FromStr for Bare<Pk>
where
    Pk: MiniscriptKey + FromStr,
    Pk::Hash: FromStr,
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let desc_str = verify_checksum(s)?;
        let top = expression::Tree::from_str(desc_str)?;
        Self::from_tree(&top)
    }
}

impl<Pk: MiniscriptKey> DescriptorTrait<Pk> for Bare<Pk> {
    fn sanity_check(&self) -> Result<(), Error> {
        self.ms.sanity_check()?;
        Ok(())
    }

    fn address(&self, _network: bitcoin::Network) -> Result<bitcoin::Address, Error>
    where
        Pk: ToPublicKey,
    {
        Err(Error::BareDescriptorAddr)
    }

    fn script_pubkey(&self) -> Script
    where
        Pk: ToPublicKey,
    {
        self.ms.encode()
    }

    fn unsigned_script_sig(&self) -> Script
    where
        Pk: ToPublicKey,
    {
        Script::new()
    }

    fn explicit_script(&self) -> Script
    where
        Pk: ToPublicKey,
    {
        self.ms.encode()
    }

    fn get_satisfaction<S>(&self, satisfier: S) -> Result<(Vec<Vec<u8>>, Script), Error>
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        let ms = self.ms.satisfy(satisfier)?;
        let script_sig = witness_to_scriptsig(&ms);
        let witness = vec![];
        Ok((witness, script_sig))
    }

    fn max_satisfaction_weight(&self) -> Result<usize, Error> {
        let scriptsig_len = self.ms.max_satisfaction_size()?;
        Ok(4 * (varint_len(scriptsig_len) + scriptsig_len))
    }

    fn script_code(&self) -> Script
    where
        Pk: ToPublicKey,
    {
        self.script_pubkey()
    }
}

impl<Pk: MiniscriptKey> ForEachKey<Pk> for Bare<Pk> {
    fn for_each_key<'a, F: FnMut(ForEach<'a, Pk>) -> bool>(&'a self, pred: F) -> bool
    where
        Pk: 'a,
        Pk::Hash: 'a,
    {
        self.ms.for_each_key(pred)
    }
}

impl<P: MiniscriptKey, Q: MiniscriptKey> TranslatePk<P, Q> for Bare<P> {
    type Output = Bare<Q>;

    fn translate_pk<Fpk, Fpkh, E>(
        &self,
        mut translatefpk: Fpk,
        mut translatefpkh: Fpkh,
    ) -> Result<Self::Output, E>
    where
        Fpk: FnMut(&P) -> Result<Q, E>,
        Fpkh: FnMut(&P::Hash) -> Result<Q::Hash, E>,
        Q: MiniscriptKey,
    {
        Ok(Bare::new(
            self.ms
                .translate_pk(&mut translatefpk, &mut translatefpkh)?,
        )
        .expect("Translation cannot fail inside Bare"))
    }
}

/// A bare PkH descriptor at top level
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Pkh<Pk: MiniscriptKey> {
    /// underlying publickey
    pk: Pk,
}

impl<Pk: MiniscriptKey> Pkh<Pk> {
    /// Create a new Pkh descriptor
    pub fn new(pk: Pk) -> Self {
        // do the top-level checks
        Self { pk: pk }
    }

    /// Get a reference to the inner key
    pub fn as_inner(&self) -> &Pk {
        &self.pk
    }

    /// Get the inner key
    pub fn into_inner(self) -> Pk {
        self.pk
    }
}

impl<'a, Pk: MiniscriptKey> IntoIterator for &'a Pkh<Pk> {
    type Item = &'a Pk;
    type IntoIter = Box<dyn Iterator<Item = &'a Pk> + 'a>;

    fn into_iter(self) -> Self::IntoIter {
        Box::new(::std::iter::once(&self.pk))
    }
}

impl<Pk: MiniscriptKey> fmt::Debug for Pkh<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "pkh({:?})", self.pk)
    }
}

impl<Pk: MiniscriptKey> fmt::Display for Pkh<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let desc = format!("pkh({})", self.pk);
        let checksum = desc_checksum(&desc).map_err(|_| fmt::Error)?;
        write!(f, "{}#{}", &desc, &checksum)
    }
}

impl<Pk: MiniscriptKey> Liftable<Pk> for Pkh<Pk> {
    fn lift(&self) -> Result<semantic::Policy<Pk>, Error> {
        Ok(semantic::Policy::KeyHash(self.pk.to_pubkeyhash()))
    }
}

impl<Pk> FromTree for Pkh<Pk>
where
    Pk: MiniscriptKey + FromStr,
    Pk::Hash: FromStr,
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    fn from_tree(top: &expression::Tree) -> Result<Self, Error> {
        if top.name == "pkh" && top.args.len() == 1 {
            Ok(Pkh::new(expression::terminal(&top.args[0], |pk| {
                Pk::from_str(pk)
            })?))
        } else {
            Err(Error::Unexpected(format!(
                "{}({} args) while parsing pkh descriptor",
                top.name,
                top.args.len(),
            )))
        }
    }
}

impl<Pk> FromStr for Pkh<Pk>
where
    Pk: MiniscriptKey + FromStr,
    Pk::Hash: FromStr,
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let desc_str = verify_checksum(s)?;
        let top = expression::Tree::from_str(desc_str)?;
        Self::from_tree(&top)
    }
}

impl<Pk: MiniscriptKey> DescriptorTrait<Pk> for Pkh<Pk> {
    fn sanity_check(&self) -> Result<(), Error> {
        Ok(())
    }

    fn address(&self, network: bitcoin::Network) -> Result<bitcoin::Address, Error>
    where
        Pk: ToPublicKey,
    {
        Ok(bitcoin::Address::p2pkh(&self.pk.to_public_key(), network))
    }

    fn script_pubkey(&self) -> Script
    where
        Pk: ToPublicKey,
    {
        let addr = bitcoin::Address::p2pkh(&self.pk.to_public_key(), bitcoin::Network::Bitcoin);
        addr.script_pubkey()
    }

    fn unsigned_script_sig(&self) -> Script
    where
        Pk: ToPublicKey,
    {
        Script::new()
    }

    fn explicit_script(&self) -> Script
    where
        Pk: ToPublicKey,
    {
        self.script_pubkey()
    }

    fn get_satisfaction<S>(&self, satisfier: S) -> Result<(Vec<Vec<u8>>, Script), Error>
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        if let Some(sig) = satisfier.lookup_sig(&self.pk) {
            let mut sig_vec = sig.0.serialize_der().to_vec();
            sig_vec.push(sig.1.as_u32() as u8);
            let script_sig = script::Builder::new()
                .push_slice(&sig_vec[..])
                .push_key(&self.pk.to_public_key())
                .into_script();
            let witness = vec![];
            Ok((witness, script_sig))
        } else {
            Err(Error::MissingSig(self.pk.to_public_key()))
        }
    }

    fn max_satisfaction_weight(&self) -> Result<usize, Error> {
        Ok(4 * (1 + 73 + self.pk.serialized_len()))
    }

    fn script_code(&self) -> Script
    where
        Pk: ToPublicKey,
    {
        self.script_pubkey()
    }
}

impl<Pk: MiniscriptKey> ForEachKey<Pk> for Pkh<Pk> {
    fn for_each_key<'a, F: FnMut(ForEach<'a, Pk>) -> bool>(&'a self, mut pred: F) -> bool
    where
        Pk: 'a,
        Pk::Hash: 'a,
    {
        pred(ForEach::Key(&self.pk))
    }
}

impl<P: MiniscriptKey, Q: MiniscriptKey> TranslatePk<P, Q> for Pkh<P> {
    type Output = Pkh<Q>;

    fn translate_pk<Fpk, Fpkh, E>(
        &self,
        mut translatefpk: Fpk,
        _translatefpkh: Fpkh,
    ) -> Result<Self::Output, E>
    where
        Fpk: FnMut(&P) -> Result<Q, E>,
        Fpkh: FnMut(&P::Hash) -> Result<Q::Hash, E>,
        Q: MiniscriptKey,
    {
        Ok(Pkh::new(translatefpk(&self.pk)?))
    }
}
