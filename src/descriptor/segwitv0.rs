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

//! # Segwit Output Descriptors
//!
//! Implementation of Segwit Descriptors. Contains the implementation
//! of wsh, wpkh and sortedmulti inside wsh.

use std::{fmt, str::FromStr};

use bitcoin::{self, Script};

use expression::{self, FromTree};
use miniscript::context::{ScriptContext, ScriptContextError};
use policy::{semantic, Liftable};
use util::varint_len;
use {Error, Miniscript, MiniscriptKey, Satisfier, Segwitv0, ToPublicKey};

use super::{
    checksum::{desc_checksum, verify_checksum},
    DescriptorTrait, PkTranslate, SortedMultiVec,
};
/// A Segwitv0 wsh descriptor
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct Wsh<Pk: MiniscriptKey> {
    /// underlying miniscript
    inner: WshInner<Pk>,
}

impl<Pk: MiniscriptKey> Wsh<Pk> {
    /// Create a new wsh descriptor
    pub fn new(ms: Miniscript<Pk, Segwitv0>) -> Result<Self, Error> {
        // do the top-level checks
        Segwitv0::top_level_checks(&ms)?;
        Ok(Self {
            inner: WshInner::Ms(ms),
        })
    }

    /// Create a new sortedmulti wsh descriptor
    pub fn new_sortedmulti(k: usize, pks: Vec<Pk>) -> Result<Self, Error> {
        // The context checks will be carried out inside new function for
        // sortedMultiVec
        Ok(Self {
            inner: WshInner::SortedMulti(SortedMultiVec::new(k, pks)?),
        })
    }

    /// Get the inner key
    pub fn as_inner(&self) -> &WshInner<Pk> {
        &self.inner
    }
}

/// Wsh Inner
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum WshInner<Pk: MiniscriptKey> {
    /// Sorted Multi
    SortedMulti(SortedMultiVec<Pk, Segwitv0>),
    /// Wsh Miniscript
    Ms(Miniscript<Pk, Segwitv0>),
}

impl<Pk: MiniscriptKey> Liftable<Pk> for Wsh<Pk> {
    fn lift(&self) -> Result<semantic::Policy<Pk>, Error> {
        match self.inner {
            WshInner::SortedMulti(ref smv) => smv.lift(),
            WshInner::Ms(ref ms) => ms.lift(),
        }
    }
}

impl<Pk: MiniscriptKey> FromTree for Wsh<Pk>
where
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    fn from_tree(top: &expression::Tree) -> Result<Self, Error> {
        if top.name == "wsh" && top.args.len() == 1 {
            let top = &top.args[0];
            if top.name == "sortedmulti" {
                return Ok(Wsh {
                    inner: WshInner::SortedMulti(SortedMultiVec::from_tree(&top)?),
                });
            }
            let sub = Miniscript::from_tree(&top)?;
            Segwitv0::top_level_checks(&sub)?;
            Ok(Wsh {
                inner: WshInner::Ms(sub),
            })
        } else {
            Err(Error::Unexpected(format!(
                "{}({} args) while parsing wsh descriptor",
                top.name,
                top.args.len(),
            )))
        }
    }
}
impl<Pk: MiniscriptKey> fmt::Debug for Wsh<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.inner {
            WshInner::SortedMulti(ref smv) => write!(f, "wsh({:?})", smv),
            WshInner::Ms(ref ms) => write!(f, "wsh({:?})", ms),
        }
    }
}

impl<Pk: MiniscriptKey> fmt::Display for Wsh<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let desc = match self.inner {
            WshInner::SortedMulti(ref smv) => format!("wsh({})", smv),
            WshInner::Ms(ref ms) => format!("wsh({})", ms),
        };
        let checksum = desc_checksum(&desc).map_err(|_| fmt::Error)?;
        write!(f, "{}#{}", &desc, &checksum)
    }
}

impl<Pk: MiniscriptKey> FromStr for Wsh<Pk>
where
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let desc_str = verify_checksum(s)?;
        let top = expression::Tree::from_str(desc_str)?;
        Wsh::<Pk>::from_tree(&top)
    }
}

impl<Pk: MiniscriptKey> DescriptorTrait<Pk> for Wsh<Pk>
where
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    fn sanity_check(&self) -> Result<(), Error> {
        match self.inner {
            WshInner::SortedMulti(ref smv) => smv.sanity_check()?,
            WshInner::Ms(ref ms) => ms.sanity_check()?,
        }
        Ok(())
    }

    fn address<ToPkCtx: Copy>(
        &self,
        to_pk_ctx: ToPkCtx,
        network: bitcoin::Network,
    ) -> Option<bitcoin::Address>
    where
        Pk: ToPublicKey<ToPkCtx>,
    {
        match self.inner {
            WshInner::SortedMulti(ref smv) => {
                Some(bitcoin::Address::p2wsh(&smv.encode(to_pk_ctx), network))
            }
            WshInner::Ms(ref ms) => Some(bitcoin::Address::p2wsh(&ms.encode(to_pk_ctx), network)),
        }
    }

    fn script_pubkey<ToPkCtx: Copy>(&self, to_pk_ctx: ToPkCtx) -> Script
    where
        Pk: ToPublicKey<ToPkCtx>,
    {
        self.witness_script(to_pk_ctx).to_v0_p2wsh()
    }

    fn unsigned_script_sig<ToPkCtx: Copy>(&self, _to_pk_ctx: ToPkCtx) -> Script
    where
        Pk: ToPublicKey<ToPkCtx>,
    {
        Script::new()
    }

    fn witness_script<ToPkCtx: Copy>(&self, to_pk_ctx: ToPkCtx) -> Script
    where
        Pk: ToPublicKey<ToPkCtx>,
    {
        match self.inner {
            WshInner::SortedMulti(ref smv) => smv.encode(to_pk_ctx),
            WshInner::Ms(ref ms) => ms.encode(to_pk_ctx),
        }
    }

    fn get_satisfaction<ToPkCtx, S>(
        &self,
        satisfier: S,
        to_pk_ctx: ToPkCtx,
    ) -> Result<(Vec<Vec<u8>>, Script), Error>
    where
        ToPkCtx: Copy,
        Pk: ToPublicKey<ToPkCtx>,
        S: Satisfier<ToPkCtx, Pk>,
    {
        let mut witness = match self.inner {
            WshInner::SortedMulti(ref smv) => smv.satisfy(satisfier, to_pk_ctx)?,
            WshInner::Ms(ref ms) => ms.satisfy(satisfier, to_pk_ctx)?,
        };
        witness.push(self.witness_script(to_pk_ctx).into_bytes());
        let script_sig = Script::new();
        Ok((witness, script_sig))
    }

    fn max_satisfaction_weight<ToPkCtx: Copy>(&self) -> Option<usize>
    where
        Pk: ToPublicKey<ToPkCtx>,
    {
        // TODO: Change the max sat functions in sortedmulti for consistency
        let (script_size, max_sat_elems, max_sat_size) = match self.inner {
            WshInner::SortedMulti(ref smv) => (
                smv.script_size(),
                smv.max_satisfaction_witness_elements(),
                smv.max_satisfaction_size(2), // OP_1 size dummy parameter
            ),
            WshInner::Ms(ref ms) => (
                ms.script_size(),
                ms.max_satisfaction_witness_elements()?,
                ms.max_satisfaction_size()?, // OP_1 size dummy parameter
            ),
        };
        Some(
            4 +  // scriptSig length byte
            varint_len(script_size) +
            script_size +
            varint_len(max_sat_elems) +
            max_sat_size,
        )
    }

    fn script_code<ToPkCtx: Copy>(&self, to_pk_ctx: ToPkCtx) -> Script
    where
        Pk: ToPublicKey<ToPkCtx>,
    {
        self.witness_script(to_pk_ctx)
    }
}

impl<P: MiniscriptKey, Q: MiniscriptKey> PkTranslate<P, Q> for Wsh<P> {
    type Output = Wsh<Q>;

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
        let inner = match self.inner {
            WshInner::SortedMulti(ref smv) => {
                WshInner::SortedMulti(smv.translate_pk(&mut translatefpk)?)
            }
            WshInner::Ms(ref ms) => {
                WshInner::Ms(ms.translate_pk(&mut translatefpk, &mut translatefpkh)?)
            }
        };
        Ok(Wsh { inner: inner })
    }
}

/// A bare Wpkh descriptor at top level
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct Wpkh<Pk: MiniscriptKey> {
    /// underlying publickey
    pk: Pk,
}

impl<Pk: MiniscriptKey> Wpkh<Pk> {
    /// Create a new Wpkh descriptor
    pub fn new(pk: Pk) -> Result<Self, Error> {
        // do the top-level checks
        if pk.is_uncompressed() {
            Err(Error::ContextError(ScriptContextError::CompressedOnly))
        } else {
            Ok(Self { pk: pk })
        }
    }

    /// Get the inner key
    pub fn as_inner(&self) -> &Pk {
        &self.pk
    }
}

impl<Pk: MiniscriptKey> fmt::Debug for Wpkh<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "wpkh({:?})", self.pk)
    }
}

impl<Pk: MiniscriptKey> fmt::Display for Wpkh<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let desc = format!("wpkh({})", self.pk);
        let checksum = desc_checksum(&desc).map_err(|_| fmt::Error)?;
        write!(f, "{}#{}", &desc, &checksum)
    }
}

impl<Pk: MiniscriptKey> Liftable<Pk> for Wpkh<Pk> {
    fn lift(&self) -> Result<semantic::Policy<Pk>, Error> {
        Ok(semantic::Policy::KeyHash(self.pk.to_pubkeyhash()))
    }
}

impl<Pk: MiniscriptKey> FromTree for Wpkh<Pk>
where
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    fn from_tree(top: &expression::Tree) -> Result<Self, Error> {
        if top.name == "pkh" && top.args.len() == 1 {
            Ok(Wpkh::new(expression::terminal(&top.args[0], |pk| {
                Pk::from_str(pk)
            })?)?)
        } else {
            Err(Error::Unexpected(format!(
                "{}({} args) while parsing wpkh descriptor",
                top.name,
                top.args.len(),
            )))
        }
    }
}

impl<Pk: MiniscriptKey> FromStr for Wpkh<Pk>
where
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

impl<Pk: MiniscriptKey> DescriptorTrait<Pk> for Wpkh<Pk>
where
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    fn sanity_check(&self) -> Result<(), Error> {
        if self.pk.is_uncompressed() {
            Err(Error::ContextError(ScriptContextError::CompressedOnly))
        } else {
            Ok(())
        }
    }

    fn address<ToPkCtx: Copy>(
        &self,
        to_pk_ctx: ToPkCtx,
        network: bitcoin::Network,
    ) -> Option<bitcoin::Address>
    where
        Pk: ToPublicKey<ToPkCtx>,
    {
        bitcoin::Address::p2wpkh(&self.pk.to_public_key(to_pk_ctx), network).ok()
    }

    fn script_pubkey<ToPkCtx: Copy>(&self, to_pk_ctx: ToPkCtx) -> Script
    where
        Pk: ToPublicKey<ToPkCtx>,
    {
        let addr =
            bitcoin::Address::p2wpkh(&self.pk.to_public_key(to_pk_ctx), bitcoin::Network::Bitcoin)
                .expect("wpkh descriptors have compressed keys");
        addr.script_pubkey()
    }

    fn unsigned_script_sig<ToPkCtx: Copy>(&self, _to_pk_ctx: ToPkCtx) -> Script
    where
        Pk: ToPublicKey<ToPkCtx>,
    {
        Script::new()
    }

    fn witness_script<ToPkCtx: Copy>(&self, to_pk_ctx: ToPkCtx) -> Script
    where
        Pk: ToPublicKey<ToPkCtx>,
    {
        self.script_pubkey(to_pk_ctx)
    }

    fn get_satisfaction<ToPkCtx, S>(
        &self,
        satisfier: S,
        to_pk_ctx: ToPkCtx,
    ) -> Result<(Vec<Vec<u8>>, Script), Error>
    where
        ToPkCtx: Copy,
        Pk: ToPublicKey<ToPkCtx>,
        S: Satisfier<ToPkCtx, Pk>,
    {
        if let Some(sig) = satisfier.lookup_sig(&self.pk, to_pk_ctx) {
            let mut sig_vec = sig.0.serialize_der().to_vec();
            sig_vec.push(sig.1.as_u32() as u8);
            let script_sig = Script::new();
            let witness = vec![sig_vec, self.pk.to_public_key(to_pk_ctx).to_bytes()];
            Ok((witness, script_sig))
        } else {
            Err(Error::MissingSig(self.pk.to_public_key(to_pk_ctx)))
        }
    }

    fn max_satisfaction_weight<ToPkCtx: Copy>(&self) -> Option<usize>
    where
        Pk: ToPublicKey<ToPkCtx>,
    {
        Some(4 + 1 + 73 + self.pk.serialized_len())
    }

    fn script_code<ToPkCtx: Copy>(&self, to_pk_ctx: ToPkCtx) -> Script
    where
        Pk: ToPublicKey<ToPkCtx>,
    {
        // For SegWit outputs, it is defined by bip-0143 (quoted below) and is different from
        // the previous txo's scriptPubKey.
        // The item 5:
        //     - For P2WPKH witness program, the scriptCode is `0x1976a914{20-byte-pubkey-hash}88ac`.
        let addr =
            bitcoin::Address::p2pkh(&self.pk.to_public_key(to_pk_ctx), bitcoin::Network::Bitcoin);
        addr.script_pubkey()
    }
}

impl<P: MiniscriptKey, Q: MiniscriptKey> PkTranslate<P, Q> for Wpkh<P> {
    type Output = Wpkh<Q>;

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
        Ok(Wpkh::new(translatefpk(&self.pk)?).expect("Uncompressed keys in Wpkh"))
    }
}
