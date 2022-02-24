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

//! # P2SH Descriptors
//!
//! Implementation of p2sh descriptors. Contains the implementation
//! of sh, wrapped fragments for sh which include wsh, sortedmulti
//! sh(miniscript), and sh(wpkh)
//!

use std::{fmt, str::FromStr};

use bitcoin::{self, blockdata::script, Script};

use expression::{self, FromTree};
use miniscript::context::ScriptContext;
use policy::{semantic, Liftable};
use push_opcode_size;
use util::{varint_len, witness_to_scriptsig};
use {
    Error, ForEach, ForEachKey, Legacy, Miniscript, MiniscriptKey, Satisfier, Segwitv0,
    ToPublicKey, TranslatePk,
};

use super::{
    checksum::{desc_checksum, verify_checksum},
    DescriptorTrait, SortedMultiVec, Wpkh, Wsh,
};

/// A Legacy p2sh Descriptor
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Sh<Pk: MiniscriptKey> {
    /// underlying miniscript
    inner: ShInner<Pk>,
}

/// Sh Inner
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum ShInner<Pk: MiniscriptKey> {
    /// Nested Wsh
    Wsh(Wsh<Pk>),
    /// Nested Wpkh
    Wpkh(Wpkh<Pk>),
    /// Inner Sorted Multi
    SortedMulti(SortedMultiVec<Pk, Legacy>),
    /// p2sh miniscript
    Ms(Miniscript<Pk, Legacy>),
}

impl<Pk: MiniscriptKey> Liftable<Pk> for Sh<Pk> {
    fn lift(&self) -> Result<semantic::Policy<Pk>, Error> {
        match self.inner {
            ShInner::Wsh(ref wsh) => wsh.lift(),
            ShInner::Wpkh(ref pk) => Ok(semantic::Policy::KeyHash(pk.as_inner().to_pubkeyhash())),
            ShInner::SortedMulti(ref smv) => smv.lift(),
            ShInner::Ms(ref ms) => ms.lift(),
        }
    }
}

impl<Pk: MiniscriptKey> fmt::Debug for Sh<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.inner {
            ShInner::Wsh(ref wsh_inner) => write!(f, "sh({:?})", wsh_inner),
            ShInner::Wpkh(ref pk) => write!(f, "sh({:?})", pk),
            ShInner::SortedMulti(ref smv) => write!(f, "sh({:?})", smv),
            ShInner::Ms(ref ms) => write!(f, "sh({:?})", ms),
        }
    }
}

impl<Pk: MiniscriptKey> fmt::Display for Sh<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let desc = match self.inner {
            ShInner::Wsh(ref wsh) => format!("sh({})", wsh.to_string_no_checksum()),
            ShInner::Wpkh(ref pk) => format!("sh({})", pk.to_string_no_checksum()),
            ShInner::SortedMulti(ref smv) => format!("sh({})", smv),
            ShInner::Ms(ref ms) => format!("sh({})", ms),
        };
        let checksum = desc_checksum(&desc).map_err(|_| fmt::Error)?;
        write!(f, "{}#{}", &desc, &checksum)
    }
}

impl<Pk> FromTree for Sh<Pk>
where
    Pk: MiniscriptKey + FromStr,
    Pk::Hash: FromStr,
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    fn from_tree(top: &expression::Tree) -> Result<Self, Error> {
        if top.name == "sh" && top.args.len() == 1 {
            let top = &top.args[0];
            let inner = match top.name {
                "wsh" => ShInner::Wsh(Wsh::from_tree(&top)?),
                "wpkh" => ShInner::Wpkh(Wpkh::from_tree(&top)?),
                "sortedmulti" => ShInner::SortedMulti(SortedMultiVec::from_tree(&top)?),
                _ => {
                    let sub = Miniscript::from_tree(&top)?;
                    Legacy::top_level_checks(&sub)?;
                    ShInner::Ms(sub)
                }
            };
            Ok(Sh { inner: inner })
        } else {
            Err(Error::Unexpected(format!(
                "{}({} args) while parsing sh descriptor",
                top.name,
                top.args.len(),
            )))
        }
    }
}

impl<Pk> FromStr for Sh<Pk>
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

impl<Pk: MiniscriptKey> Sh<Pk> {
    /// Get the Inner
    pub fn into_inner(self) -> ShInner<Pk> {
        self.inner
    }

    /// Get a reference to inner
    pub fn as_inner(&self) -> &ShInner<Pk> {
        &self.inner
    }

    /// Create a new p2sh descriptor with the raw miniscript
    pub fn new(ms: Miniscript<Pk, Legacy>) -> Result<Self, Error> {
        // do the top-level checks
        Legacy::top_level_checks(&ms)?;
        Ok(Self {
            inner: ShInner::Ms(ms),
        })
    }

    /// Create a new p2sh sortedmulti descriptor with threshold `k`
    /// and Vec of `pks`.
    pub fn new_sortedmulti(k: usize, pks: Vec<Pk>) -> Result<Self, Error> {
        // The context checks will be carried out inside new function for
        // sortedMultiVec
        Ok(Self {
            inner: ShInner::SortedMulti(SortedMultiVec::new(k, pks)?),
        })
    }

    /// Create a new p2sh wrapped wsh descriptor with the raw miniscript
    pub fn new_wsh(ms: Miniscript<Pk, Segwitv0>) -> Result<Self, Error> {
        Ok(Self {
            inner: ShInner::Wsh(Wsh::new(ms)?),
        })
    }

    /// Create a new p2sh wrapper for the given wsh descriptor
    pub fn new_with_wsh(wsh: Wsh<Pk>) -> Self {
        Self {
            inner: ShInner::Wsh(wsh),
        }
    }

    /// Create a new p2sh wrapped wsh sortedmulti descriptor from threshold
    /// `k` and Vec of `pks`
    pub fn new_wsh_sortedmulti(k: usize, pks: Vec<Pk>) -> Result<Self, Error> {
        // The context checks will be carried out inside new function for
        // sortedMultiVec
        Ok(Self {
            inner: ShInner::Wsh(Wsh::new_sortedmulti(k, pks)?),
        })
    }

    /// Create a new p2sh wrapped wpkh from `Pk`
    pub fn new_wpkh(pk: Pk) -> Result<Self, Error> {
        Ok(Self {
            inner: ShInner::Wpkh(Wpkh::new(pk)?),
        })
    }

    /// Create a new p2sh wrapper for the given wpkh descriptor
    pub fn new_with_wpkh(wpkh: Wpkh<Pk>) -> Self {
        Self {
            inner: ShInner::Wpkh(wpkh),
        }
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> Sh<Pk> {
    /// Obtain the corresponding script pubkey for this descriptor
    /// Non failing verion of [`DescriptorTrait::script_pubkey`] for this descriptor
    pub fn spk(&self) -> Script {
        match self.inner {
            ShInner::Wsh(ref wsh) => wsh.spk().to_p2sh(),
            ShInner::Wpkh(ref wpkh) => wpkh.spk().to_p2sh(),
            ShInner::SortedMulti(ref smv) => smv.encode().to_p2sh(),
            ShInner::Ms(ref ms) => ms.encode().to_p2sh(),
        }
    }

    /// Obtain the corresponding script pubkey for this descriptor
    /// Non failing verion of [`DescriptorTrait::address`] for this descriptor
    pub fn addr(&self, network: bitcoin::Network) -> bitcoin::Address {
        match self.inner {
            ShInner::Wsh(ref wsh) => {
                bitcoin::Address::p2sh(&wsh.spk(), network).expect("Size checked in Miniscript")
            }
            ShInner::Wpkh(ref wpkh) => {
                bitcoin::Address::p2sh(&wpkh.spk(), network).expect("Size checked in Miniscript")
            }
            ShInner::SortedMulti(ref smv) => {
                bitcoin::Address::p2sh(&smv.encode(), network).expect("Size checked in Miniscript")
            }
            ShInner::Ms(ref ms) => {
                bitcoin::Address::p2sh(&ms.encode(), network).expect("Size checked in Miniscript")
            }
        }
    }

    /// Obtain the underlying miniscript for this descriptor
    /// Non failing verion of [`DescriptorTrait::explicit_script`] for this descriptor
    pub fn inner_script(&self) -> Script {
        match self.inner {
            ShInner::Wsh(ref wsh) => wsh.inner_script(),
            ShInner::Wpkh(ref wpkh) => wpkh.spk(),
            ShInner::SortedMulti(ref smv) => smv.encode(),
            ShInner::Ms(ref ms) => ms.encode(),
        }
    }

    /// Obtain the pre bip-340 signature script code for this descriptor
    /// Non failing verion of [`DescriptorTrait::script_code`] for this descriptor
    pub fn ecdsa_sighash_script_code(&self) -> Script {
        match self.inner {
            //     - For P2WSH witness program, if the witnessScript does not contain any `OP_CODESEPARATOR`,
            //       the `scriptCode` is the `witnessScript` serialized as scripts inside CTxOut.
            ShInner::Wsh(ref wsh) => wsh.ecdsa_sighash_script_code(),
            ShInner::SortedMulti(ref smv) => smv.encode(),
            ShInner::Wpkh(ref wpkh) => wpkh.ecdsa_sighash_script_code(),
            // For "legacy" P2SH outputs, it is defined as the txo's redeemScript.
            ShInner::Ms(ref ms) => ms.encode(),
        }
    }
}

impl<Pk: MiniscriptKey> DescriptorTrait<Pk> for Sh<Pk> {
    fn sanity_check(&self) -> Result<(), Error> {
        match self.inner {
            ShInner::Wsh(ref wsh) => wsh.sanity_check()?,
            ShInner::Wpkh(ref wpkh) => wpkh.sanity_check()?,
            ShInner::SortedMulti(ref smv) => smv.sanity_check()?,
            ShInner::Ms(ref ms) => ms.sanity_check()?,
        }
        Ok(())
    }

    fn address(&self, network: bitcoin::Network) -> Result<bitcoin::Address, Error>
    where
        Pk: ToPublicKey,
    {
        match self.inner {
            ShInner::Wsh(ref wsh) => Ok(bitcoin::Address::p2sh(&wsh.spk(), network)?),
            ShInner::Wpkh(ref wpkh) => Ok(bitcoin::Address::p2sh(&wpkh.spk(), network)?),
            ShInner::SortedMulti(ref smv) => Ok(bitcoin::Address::p2sh(&smv.encode(), network)?),
            ShInner::Ms(ref ms) => Ok(bitcoin::Address::p2sh(&ms.encode(), network)?),
        }
    }

    fn script_pubkey(&self) -> Script
    where
        Pk: ToPublicKey,
    {
        self.spk()
    }

    fn unsigned_script_sig(&self) -> Script
    where
        Pk: ToPublicKey,
    {
        match self.inner {
            ShInner::Wsh(ref wsh) => {
                // wsh explicit must contain exactly 1 element
                let witness_script = wsh.inner_script();
                script::Builder::new()
                    .push_slice(&witness_script.to_v0_p2wsh()[..])
                    .into_script()
            }
            ShInner::Wpkh(ref wpkh) => {
                let redeem_script = wpkh.spk();
                script::Builder::new()
                    .push_slice(&redeem_script[..])
                    .into_script()
            }
            ShInner::SortedMulti(..) | ShInner::Ms(..) => Script::new(),
        }
    }

    fn explicit_script(&self) -> Result<Script, Error>
    where
        Pk: ToPublicKey,
    {
        Ok(self.inner_script())
    }

    fn get_satisfaction<S>(&self, satisfier: S) -> Result<(Vec<Vec<u8>>, Script), Error>
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        let script_sig = self.unsigned_script_sig();
        match self.inner {
            ShInner::Wsh(ref wsh) => {
                let (witness, _) = wsh.get_satisfaction(satisfier)?;
                Ok((witness, script_sig))
            }
            ShInner::Wpkh(ref wpkh) => {
                let (witness, _) = wpkh.get_satisfaction(satisfier)?;
                Ok((witness, script_sig))
            }
            ShInner::SortedMulti(ref smv) => {
                let mut script_witness = smv.satisfy(satisfier)?;
                script_witness.push(smv.encode().into_bytes());
                let script_sig = witness_to_scriptsig(&script_witness);
                let witness = vec![];
                Ok((witness, script_sig))
            }
            ShInner::Ms(ref ms) => {
                let mut script_witness = ms.satisfy(satisfier)?;
                script_witness.push(ms.encode().into_bytes());
                let script_sig = witness_to_scriptsig(&script_witness);
                let witness = vec![];
                Ok((witness, script_sig))
            }
        }
    }

    fn get_satisfaction_mall<S>(&self, satisfier: S) -> Result<(Vec<Vec<u8>>, Script), Error>
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        let script_sig = self.unsigned_script_sig();
        match self.inner {
            ShInner::Wsh(ref wsh) => {
                let (witness, _) = wsh.get_satisfaction_mall(satisfier)?;
                Ok((witness, script_sig))
            }
            ShInner::Ms(ref ms) => {
                let mut script_witness = ms.satisfy_malleable(satisfier)?;
                script_witness.push(ms.encode().into_bytes());
                let script_sig = witness_to_scriptsig(&script_witness);
                let witness = vec![];
                Ok((witness, script_sig))
            }
            _ => self.get_satisfaction(satisfier),
        }
    }

    fn max_satisfaction_weight(&self) -> Result<usize, Error> {
        Ok(match self.inner {
            // add weighted script sig, len byte stays the same
            ShInner::Wsh(ref wsh) => 4 * 35 + wsh.max_satisfaction_weight()?,
            ShInner::SortedMulti(ref smv) => {
                let ss = smv.script_size();
                let ps = push_opcode_size(ss);
                let scriptsig_len = ps + ss + smv.max_satisfaction_size();
                4 * (varint_len(scriptsig_len) + scriptsig_len)
            }
            // add weighted script sig, len byte stays the same
            ShInner::Wpkh(ref wpkh) => 4 * 23 + wpkh.max_satisfaction_weight()?,
            ShInner::Ms(ref ms) => {
                let ss = ms.script_size();
                let ps = push_opcode_size(ss);
                let scriptsig_len = ps + ss + ms.max_satisfaction_size()?;
                4 * (varint_len(scriptsig_len) + scriptsig_len)
            }
        })
    }

    fn script_code(&self) -> Result<Script, Error>
    where
        Pk: ToPublicKey,
    {
        Ok(self.ecdsa_sighash_script_code())
    }
}

impl<Pk: MiniscriptKey> ForEachKey<Pk> for Sh<Pk> {
    fn for_each_key<'a, F: FnMut(ForEach<'a, Pk>) -> bool>(&'a self, pred: F) -> bool
    where
        Pk: 'a,
        Pk::Hash: 'a,
    {
        match self.inner {
            ShInner::Wsh(ref wsh) => wsh.for_each_key(pred),
            ShInner::SortedMulti(ref smv) => smv.for_each_key(pred),
            ShInner::Wpkh(ref wpkh) => wpkh.for_each_key(pred),
            ShInner::Ms(ref ms) => ms.for_each_key(pred),
        }
    }
}

impl<P: MiniscriptKey, Q: MiniscriptKey> TranslatePk<P, Q> for Sh<P> {
    type Output = Sh<Q>;

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
            ShInner::Wsh(ref wsh) => {
                ShInner::Wsh(wsh.translate_pk(&mut translatefpk, &mut translatefpkh)?)
            }
            ShInner::Wpkh(ref wpkh) => {
                ShInner::Wpkh(wpkh.translate_pk(&mut translatefpk, &mut translatefpkh)?)
            }
            ShInner::SortedMulti(ref smv) => {
                ShInner::SortedMulti(smv.translate_pk(&mut translatefpk)?)
            }
            ShInner::Ms(ref ms) => {
                ShInner::Ms(ms.translate_pk(&mut translatefpk, &mut translatefpkh)?)
            }
        };
        Ok(Sh { inner: inner })
    }
}
