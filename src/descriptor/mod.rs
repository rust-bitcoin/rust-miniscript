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

//! # Output Descriptors
//!
//! Tools for representing Bitcoin output's scriptPubKeys as abstract spending
//! policies known as "output descriptors". These include a Miniscript which
//! describes the actual signing policy, as well as the blockchain format (P2SH,
//! Segwit v0, etc.)
//!
//! The format represents EC public keys abstractly to allow wallets to replace
//! these with BIP32 paths, pay-to-contract instructions, etc.
//!

use bitcoin::blockdata::{opcodes, script};
use bitcoin::{self, PublicKey, Script};
#[cfg(feature = "serde")]
use serde::{de, ser};
use std::fmt;
use std::str::{self, FromStr};

use bitcoin::blockdata::{opcodes, script};
use bitcoin::{self, Script};

use expression;
use miniscript;
use miniscript::context::ScriptContextError;
use miniscript::{Legacy, Miniscript, Segwitv0};
use Error;
use MiniscriptKey;
use Satisfier;
use ToPublicKey;

mod create_descriptor;
mod satisfied_constraints;

pub use self::create_descriptor::from_txin_with_witness_stack;
pub use self::satisfied_constraints::Error as InterpreterError;
pub use self::satisfied_constraints::SatisfiedConstraint;
pub use self::satisfied_constraints::SatisfiedConstraints;
pub use self::satisfied_constraints::Stack;
use bitcoin::hashes::core::fmt::Formatter;
use bitcoin::hashes::hash160;
use bitcoin::hashes::hex::FromHex;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::bip32::{ChildNumber, DerivationPath, Error as Bip32Error, ExtendedPubKey};
use std::fmt::{Display, Write};

/// Script descriptor
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Descriptor<Pk: MiniscriptKey> {
    /// A raw scriptpubkey (including pay-to-pubkey) under Legacy context
    Bare(Miniscript<Pk, Legacy>),
    /// Pay-to-Pubkey
    Pk(Pk),
    /// Pay-to-PubKey-Hash
    Pkh(Pk),
    /// Pay-to-Witness-PubKey-Hash
    Wpkh(Pk),
    /// Pay-to-Witness-PubKey-Hash inside P2SH
    ShWpkh(Pk),
    /// Pay-to-ScriptHash with Legacy context
    Sh(Miniscript<Pk, Legacy>),
    /// Pay-to-Witness-ScriptHash with Segwitv0 context
    Wsh(Miniscript<Pk, Segwitv0>),
    /// P2SH-P2WSH with Segwitv0 context
    ShWsh(Miniscript<Pk, Segwitv0>),
}

#[derive(Debug, Eq, PartialEq, Clone, Ord, PartialOrd, Hash)]
pub enum DescriptorKey {
    PukKey(bitcoin::PublicKey),
    XPub(DescriptorXPub),
}

#[derive(Debug, Eq, PartialEq, Clone, Ord, PartialOrd, Hash)]
pub struct DescriptorXPub {
    source: Option<([u8; 4], DerivationPath)>,
    xpub: bitcoin::util::bip32::ExtendedPubKey,
    derivation_path: DerivationPath,
    is_wildcard: bool,
}

#[derive(Debug)]
pub struct DescriptorKeyParseError(&'static str);

impl Display for DescriptorKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DescriptorKey::PukKey(pk) => pk.fmt(f),
            DescriptorKey::XPub(xpub) => {
                if let Some((master_id, ref master_deriv)) = &xpub.source {
                    f.write_char('[')?;
                    for byte in master_id {
                        write!(f, "{:02x}", byte)?;
                    }
                    fmt_derivation_path(f, master_deriv)?;
                    f.write_char(']')?;
                }
                xpub.xpub.fmt(f)?;
                fmt_derivation_path(f, &xpub.derivation_path)?;
                if xpub.is_wildcard {
                    write!(f, "/*")?;
                }
                Ok(())
            }
        }
    }
}

fn fmt_derivation_path(f: &mut Formatter<'_>, path: &DerivationPath) -> std::fmt::Result {
    for child in path {
        write!(f, "/{}", child)?;
    }
    Ok(())
}

impl FromStr for DescriptorKey {
    type Err = DescriptorKeyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() < 66 {
            Err(DescriptorKeyParseError(
                "Key too short (<66 char), doesn't match any format",
            ))
        } else if s.chars().next().unwrap() == '[' {
            let mut parts = s[1..].split(']');
            let mut origin = parts
                .next()
                .ok_or(DescriptorKeyParseError("Unclosed '['"))?
                .split('/');

            let origin_id_hex = origin.next().ok_or(DescriptorKeyParseError(
                "No master fingerprint found after '['",
            ))?;

            if origin_id_hex.len() != 8 {
                return Err(DescriptorKeyParseError(
                    "Master fingerprint should be 8 characters long",
                ));
            }

            let origin_id: [u8; 4] = FromHex::from_hex(origin_id_hex).map_err(|_| {
                DescriptorKeyParseError("Malformed master fingerprint, expected 8 hex chars")
            })?;

            let origin_path = origin
                .map(|p| ChildNumber::from_str(p))
                .collect::<Result<DerivationPath, Bip32Error>>()
                .map_err(|_| {
                    DescriptorKeyParseError("Error while parsing master derivation path")
                })?;

            let key_deriv = parts.next().ok_or(DescriptorKeyParseError(
                "No key found after origin description",
            ))?;

            let (xpub, derivation_path, is_wildcard) = Self::parse_xpub_deriv(key_deriv)?;

            Ok(DescriptorKey::XPub(DescriptorXPub {
                source: Some((origin_id, origin_path)),
                xpub,
                derivation_path,
                is_wildcard,
            }))
        } else if s.starts_with("02") || s.starts_with("03") || s.starts_with("04") {
            let pk = PublicKey::from_str(s)
                .map_err(|_| DescriptorKeyParseError("Error while parsing simple public key"))?;
            Ok(DescriptorKey::PukKey(pk))
        } else {
            let (xpub, derivation_path, is_wildcard) = Self::parse_xpub_deriv(s)?;
            Ok(DescriptorKey::XPub(DescriptorXPub {
                source: None,
                xpub,
                derivation_path,
                is_wildcard,
            }))
        }
    }
}

impl DescriptorKey {
    fn parse_xpub_deriv(
        key_deriv: &str,
    ) -> Result<(ExtendedPubKey, DerivationPath, bool), DescriptorKeyParseError> {
        let mut key_deriv = key_deriv.split('/');
        let xpub_str = key_deriv.next().ok_or(DescriptorKeyParseError(
            "No key found after origin description",
        ))?;
        let xpub = ExtendedPubKey::from_str(xpub_str)
            .map_err(|_| DescriptorKeyParseError("Error while parsing xpub."))?;

        let mut is_wildcard = false;
        let derivation_path = key_deriv
            .filter_map(|p| {
                if !is_wildcard && p == "*" {
                    is_wildcard = true;
                    None
                } else if is_wildcard {
                    Some(Err(DescriptorKeyParseError(
                        "'*' may only appear as last element in a derivation path.",
                    )))
                } else {
                    Some(ChildNumber::from_str(p).map_err(|_| {
                        DescriptorKeyParseError("Error while parsing key derivation path")
                    }))
                }
            })
            .collect::<Result<DerivationPath, _>>()?;

        if (&derivation_path).into_iter().all(|c| c.is_normal()) {
            Ok((xpub, derivation_path, is_wildcard))
        } else {
            Err(DescriptorKeyParseError(
                "Hardened derivation is currently not supported.",
            ))
        }
    }
}

impl MiniscriptKey for DescriptorKey {
    type Hash = hash160::Hash;

    fn to_pubkeyhash(&self) -> Self::Hash {
        match self {
            DescriptorKey::PukKey(pk) => pk.to_pubkeyhash(),
            DescriptorKey::XPub(xpub) => {
                let ctx = Secp256k1::verification_only();
                xpub.xpub
                    .derive_pub(&ctx, &xpub.derivation_path)
                    .expect("Shouldn't fail, only normal derivations")
                    .public_key
                    .to_pubkeyhash()
            }
        }
    }
}

impl ToPublicKey for DescriptorKey {
    fn to_public_key(&self) -> PublicKey {
        match self {
            DescriptorKey::PukKey(pk) => *pk,
            DescriptorKey::XPub(xpub) => {
                let ctx = Secp256k1::verification_only();
                xpub.xpub
                    .derive_pub(&ctx, &xpub.derivation_path)
                    .expect("Shouldn't fail, only normal derivations")
                    .public_key
            }
        }
    }

    fn hash_to_hash160(hash: &Self::Hash) -> hash160::Hash {
        *hash
    }
}

impl<Pk: MiniscriptKey> Descriptor<Pk> {
    /// Convert a descriptor using abstract keys to one using specific keys
    /// This will panic if translatefpk returns an uncompressed key when
    /// converting to a Segwit descriptor. To prevent this panic, ensure
    /// translatefpk returns an error in this case instead.
    pub fn translate_pk<Fpk, Fpkh, Q, E>(
        &self,
        mut translatefpk: Fpk,
        mut translatefpkh: Fpkh,
    ) -> Result<Descriptor<Q>, E>
    where
        Fpk: FnMut(&Pk) -> Result<Q, E>,
        Fpkh: FnMut(&Pk::Hash) -> Result<Q::Hash, E>,
        Q: MiniscriptKey,
    {
        match *self {
            Descriptor::Bare(ref ms) => Ok(Descriptor::Bare(
                ms.translate_pk(&mut translatefpk, &mut translatefpkh)?,
            )),
            Descriptor::Pk(ref pk) => translatefpk(pk).map(Descriptor::Pk),
            Descriptor::Pkh(ref pk) => translatefpk(pk).map(Descriptor::Pkh),
            Descriptor::Wpkh(ref pk) => {
                if pk.is_uncompressed() {
                    panic!("Uncompressed pubkeys are not allowed in segwit v0 scripts");
                }
                translatefpk(pk).map(Descriptor::Wpkh)
            }
            Descriptor::ShWpkh(ref pk) => {
                if pk.is_uncompressed() {
                    panic!("Uncompressed pubkeys are not allowed in segwit v0 scripts");
                }
                translatefpk(pk).map(Descriptor::ShWpkh)
            }
            Descriptor::Sh(ref ms) => Ok(Descriptor::Sh(
                ms.translate_pk(&mut translatefpk, &mut translatefpkh)?,
            )),
            Descriptor::Wsh(ref ms) => Ok(Descriptor::Wsh(
                ms.translate_pk(&mut translatefpk, &mut translatefpkh)?,
            )),
            Descriptor::ShWsh(ref ms) => Ok(Descriptor::ShWsh(
                ms.translate_pk(&mut translatefpk, &mut translatefpkh)?,
            )),
        }
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> Descriptor<Pk> {
    /// Computes the Bitcoin address of the descriptor, if one exists
    pub fn address(&self, network: bitcoin::Network) -> Option<bitcoin::Address> {
        match *self {
            Descriptor::Bare(..) => None,
            Descriptor::Pk(..) => None,
            Descriptor::Pkh(ref pk) => Some(bitcoin::Address::p2pkh(&pk.to_public_key(), network)),
            Descriptor::Wpkh(ref pk) => {
                Some(bitcoin::Address::p2wpkh(&pk.to_public_key(), network))
            }
            Descriptor::ShWpkh(ref pk) => {
                Some(bitcoin::Address::p2shwpkh(&pk.to_public_key(), network))
            }
            Descriptor::Sh(ref miniscript) => {
                Some(bitcoin::Address::p2sh(&miniscript.encode(), network))
            }
            Descriptor::Wsh(ref miniscript) => {
                Some(bitcoin::Address::p2wsh(&miniscript.encode(), network))
            }
            Descriptor::ShWsh(ref miniscript) => {
                Some(bitcoin::Address::p2shwsh(&miniscript.encode(), network))
            }
        }
    }

    /// Computes the scriptpubkey of the descriptor
    pub fn script_pubkey(&self) -> Script {
        match *self {
            Descriptor::Bare(ref d) => d.encode(),
            Descriptor::Pk(ref pk) => script::Builder::new()
                .push_key(&pk.to_public_key())
                .push_opcode(opcodes::all::OP_CHECKSIG)
                .into_script(),
            Descriptor::Pkh(ref pk) => {
                let addr = bitcoin::Address::p2pkh(&pk.to_public_key(), bitcoin::Network::Bitcoin);
                addr.script_pubkey()
            }
            Descriptor::Wpkh(ref pk) => {
                let addr = bitcoin::Address::p2wpkh(&pk.to_public_key(), bitcoin::Network::Bitcoin);
                addr.script_pubkey()
            }
            Descriptor::ShWpkh(ref pk) => {
                let addr =
                    bitcoin::Address::p2shwpkh(&pk.to_public_key(), bitcoin::Network::Bitcoin);
                addr.script_pubkey()
            }
            Descriptor::Sh(ref miniscript) => miniscript.encode().to_p2sh(),
            Descriptor::Wsh(ref miniscript) => miniscript.encode().to_v0_p2wsh(),
            Descriptor::ShWsh(ref miniscript) => miniscript.encode().to_v0_p2wsh().to_p2sh(),
        }
    }

    /// Computes the scriptSig that will be in place for an unsigned
    /// input spending an output with this descriptor. For pre-segwit
    /// descriptors, which use the scriptSig for signatures, this
    /// returns the empty script.
    ///
    /// This is used in Segwit transactions to produce an unsigned
    /// transaction whose txid will not change during signing (since
    /// only the witness data will change).
    pub fn unsigned_script_sig(&self) -> Script {
        match *self {
            // non-segwit
            Descriptor::Bare(..)
            | Descriptor::Pk(..)
            | Descriptor::Pkh(..)
            | Descriptor::Sh(..) => Script::new(),
            // pure segwit, empty scriptSig
            Descriptor::Wsh(..) | Descriptor::Wpkh(..) => Script::new(),
            // segwit+p2sh
            Descriptor::ShWpkh(ref pk) => {
                let addr = bitcoin::Address::p2wpkh(&pk.to_public_key(), bitcoin::Network::Bitcoin);
                let redeem_script = addr.script_pubkey();
                script::Builder::new()
                    .push_slice(&redeem_script[..])
                    .into_script()
            }
            Descriptor::ShWsh(ref d) => {
                let witness_script = d.encode();
                script::Builder::new()
                    .push_slice(&witness_script.to_v0_p2wsh()[..])
                    .into_script()
            }
        }
    }

    /// Computes the "witness script" of the descriptor, i.e. the underlying
    /// script before any hashing is done. For `Bare`, `Pkh` and `Wpkh` this
    /// is the scriptPubkey; for `ShWpkh` and `Sh` this is the redeemScript;
    /// for the others it is the witness script.
    pub fn witness_script(&self) -> Script {
        match *self {
            Descriptor::Bare(..)
            | Descriptor::Pk(..)
            | Descriptor::Pkh(..)
            | Descriptor::Wpkh(..) => self.script_pubkey(),
            Descriptor::ShWpkh(ref pk) => {
                let addr = bitcoin::Address::p2wpkh(&pk.to_public_key(), bitcoin::Network::Bitcoin);
                addr.script_pubkey()
            }
            Descriptor::Sh(ref d) => d.encode(),
            Descriptor::Wsh(ref d) | Descriptor::ShWsh(ref d) => d.encode(),
        }
    }

    /// Attempts to produce a satisfying witness and scriptSig to spend an
    /// output controlled by the given descriptor; add the data to a given
    /// `TxIn` output.
    pub fn satisfy<S: Satisfier<Pk>>(
        &self,
        txin: &mut bitcoin::TxIn,
        satisfier: S,
    ) -> Result<(), Error> {
        fn witness_to_scriptsig(witness: &[Vec<u8>]) -> Script {
            let mut b = script::Builder::new();
            for wit in witness {
                if let Ok(n) = script::read_scriptint(wit) {
                    b = b.push_int(n);
                } else {
                    b = b.push_slice(wit);
                }
            }
            b.into_script()
        }

        match *self {
            Descriptor::Bare(ref d) => {
                let wit = match d.satisfy(satisfier) {
                    Some(wit) => wit,
                    None => return Err(Error::CouldNotSatisfy),
                };
                txin.script_sig = witness_to_scriptsig(&wit);
                txin.witness = vec![];
                Ok(())
            }
            Descriptor::Pk(ref pk) => {
                if let Some(sig) = satisfier.lookup_sig(pk) {
                    let mut sig_vec = sig.0.serialize_der().to_vec();
                    sig_vec.push(sig.1.as_u32() as u8);
                    txin.script_sig = script::Builder::new()
                        .push_slice(&sig_vec[..])
                        .into_script();
                    txin.witness = vec![];
                    Ok(())
                } else {
                    Err(Error::MissingSig(pk.to_public_key()))
                }
            }
            Descriptor::Pkh(ref pk) => {
                if let Some(sig) = satisfier.lookup_sig(pk) {
                    let mut sig_vec = sig.0.serialize_der().to_vec();
                    sig_vec.push(sig.1.as_u32() as u8);
                    txin.script_sig = script::Builder::new()
                        .push_slice(&sig_vec[..])
                        .push_key(&pk.to_public_key())
                        .into_script();
                    txin.witness = vec![];
                    Ok(())
                } else {
                    Err(Error::MissingSig(pk.to_public_key()))
                }
            }
            Descriptor::Wpkh(ref pk) => {
                if let Some(sig) = satisfier.lookup_sig(pk) {
                    let mut sig_vec = sig.0.serialize_der().to_vec();
                    sig_vec.push(sig.1.as_u32() as u8);
                    txin.script_sig = Script::new();
                    txin.witness = vec![sig_vec, pk.to_public_key().to_bytes()];
                    Ok(())
                } else {
                    Err(Error::MissingSig(pk.to_public_key()))
                }
            }
            Descriptor::ShWpkh(ref pk) => {
                if let Some(sig) = satisfier.lookup_sig(pk) {
                    let mut sig_vec = sig.0.serialize_der().to_vec();
                    sig_vec.push(sig.1.as_u32() as u8);
                    let addr =
                        bitcoin::Address::p2wpkh(&pk.to_public_key(), bitcoin::Network::Bitcoin);
                    let redeem_script = addr.script_pubkey();

                    txin.script_sig = script::Builder::new()
                        .push_slice(&redeem_script[..])
                        .into_script();
                    txin.witness = vec![sig_vec, pk.to_public_key().to_bytes()];
                    Ok(())
                } else {
                    Err(Error::MissingSig(pk.to_public_key()))
                }
            }
            Descriptor::Sh(ref d) => {
                let mut witness = match d.satisfy(satisfier) {
                    Some(wit) => wit,
                    None => return Err(Error::CouldNotSatisfy),
                };
                witness.push(d.encode().into_bytes());
                txin.script_sig = witness_to_scriptsig(&witness);
                txin.witness = vec![];
                Ok(())
            }
            Descriptor::Wsh(ref d) => {
                let mut witness = match d.satisfy(satisfier) {
                    Some(wit) => wit,
                    None => return Err(Error::CouldNotSatisfy),
                };
                witness.push(d.encode().into_bytes());
                txin.script_sig = Script::new();
                txin.witness = witness;
                Ok(())
            }
            Descriptor::ShWsh(ref d) => {
                let witness_script = d.encode();
                txin.script_sig = script::Builder::new()
                    .push_slice(&witness_script.to_v0_p2wsh()[..])
                    .into_script();

                let mut witness = match d.satisfy(satisfier) {
                    Some(wit) => wit,
                    None => return Err(Error::CouldNotSatisfy),
                };
                witness.push(witness_script.into_bytes());
                txin.witness = witness;
                Ok(())
            }
        }
    }

    /// Computes an upper bound on the weight of a satisfying witness to the
    /// transaction. Assumes all signatures are 73 bytes, including push opcode
    /// and sighash suffix. Includes the weight of the VarInts encoding the
    /// scriptSig and witness stack length.
    pub fn max_satisfaction_weight(&self) -> usize {
        fn varint_len(n: usize) -> usize {
            bitcoin::VarInt(n as u64).len()
        }

        match *self {
            Descriptor::Bare(ref ms) => {
                let scriptsig_len = ms.max_satisfaction_size(1);
                4 * (varint_len(scriptsig_len) + scriptsig_len)
            }
            Descriptor::Pk(..) => 4 * (1 + 73),
            Descriptor::Pkh(ref pk) => 4 * (1 + 73 + pk.serialized_len()),
            Descriptor::Wpkh(ref pk) => 4 + 1 + 73 + pk.serialized_len(),
            Descriptor::ShWpkh(ref pk) => 4 * 24 + 1 + 73 + pk.serialized_len(),
            Descriptor::Sh(ref ms) => {
                let ss = ms.script_size();
                let push_size = if ss < 76 {
                    1
                } else if ss < 0x100 {
                    2
                } else if ss < 0x10000 {
                    3
                } else {
                    5
                };

                let scriptsig_len = push_size + ss + ms.max_satisfaction_size(1);
                4 * (varint_len(scriptsig_len) + scriptsig_len)
            }
            Descriptor::Wsh(ref ms) => {
                let script_size = ms.script_size();
                4 +  // scriptSig length byte
                    varint_len(script_size) +
                    script_size +
                    varint_len(ms.max_satisfaction_witness_elements()) +
                    ms.max_satisfaction_size(2)
            }
            Descriptor::ShWsh(ref ms) => {
                let script_size = ms.script_size();
                4 * 36
                    + varint_len(script_size)
                    + script_size
                    + varint_len(ms.max_satisfaction_witness_elements())
                    + ms.max_satisfaction_size(2)
            }
        }
    }
}

impl<Pk> expression::FromTree for Descriptor<Pk>
where
    Pk: MiniscriptKey,
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as str::FromStr>::Err: ToString,
{
    /// Parse an expression tree into a descriptor
    fn from_tree(top: &expression::Tree) -> Result<Descriptor<Pk>, Error> {
        match (top.name, top.args.len() as u32) {
            ("pk", 1) => {
                expression::terminal(&top.args[0], |pk| Pk::from_str(pk).map(Descriptor::Pk))
            }
            ("pkh", 1) => {
                expression::terminal(&top.args[0], |pk| Pk::from_str(pk).map(Descriptor::Pkh))
            }
            ("wpkh", 1) => {
                let wpkh = expression::terminal(&top.args[0], |pk| Pk::from_str(pk))?;
                if wpkh.is_uncompressed() {
                    Err(Error::ContextError(ScriptContextError::CompressedOnly))
                } else {
                    Ok(Descriptor::Wpkh(wpkh))
                }
            }
            ("sh", 1) => {
                let newtop = &top.args[0];
                match (newtop.name, newtop.args.len()) {
                    ("wsh", 1) => {
                        let sub = Miniscript::from_tree(&newtop.args[0])?;
                        if sub.ty.corr.base != miniscript::types::Base::B {
                            Err(Error::NonTopLevel(format!("{:?}", sub)))
                        } else {
                            Ok(Descriptor::ShWsh(sub))
                        }
                    }
                    ("wpkh", 1) => {
                        let wpkh = expression::terminal(&newtop.args[0], |pk| Pk::from_str(pk))?;
                        if wpkh.is_uncompressed() {
                            Err(Error::ContextError(ScriptContextError::CompressedOnly))
                        } else {
                            Ok(Descriptor::ShWpkh(wpkh))
                        }
                    }
                    _ => {
                        let sub = Miniscript::from_tree(&top.args[0])?;
                        if sub.ty.corr.base != miniscript::types::Base::B {
                            Err(Error::NonTopLevel(format!("{:?}", sub)))
                        } else {
                            Ok(Descriptor::Sh(sub))
                        }
                    }
                }
            }
            ("wsh", 1) => {
                let sub = Miniscript::from_tree(&top.args[0])?;
                if sub.ty.corr.base != miniscript::types::Base::B {
                    Err(Error::NonTopLevel(format!("{:?}", sub)))
                } else {
                    Ok(Descriptor::Wsh(sub))
                }
            }
            _ => {
                let sub = Miniscript::from_tree(&top)?;
                if sub.ty.corr.base != miniscript::types::Base::B {
                    Err(Error::NonTopLevel(format!("{:?}", sub)))
                } else {
                    Ok(Descriptor::Bare(sub))
                }
            }
        }
    }
}

impl<Pk> FromStr for Descriptor<Pk>
where
    Pk: MiniscriptKey,
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as str::FromStr>::Err: ToString,
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Descriptor<Pk>, Error> {
        for ch in s.as_bytes() {
            if *ch < 20 || *ch > 127 {
                return Err(Error::Unprintable(*ch));
            }
        }

        let top = expression::Tree::from_str(s)?;
        expression::FromTree::from_tree(&top)
    }
}

impl<Pk: MiniscriptKey> fmt::Debug for Descriptor<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Descriptor::Bare(ref sub) => write!(f, "{:?}", sub),
            Descriptor::Pk(ref p) => write!(f, "pk({:?})", p),
            Descriptor::Pkh(ref p) => write!(f, "pkh({:?})", p),
            Descriptor::Wpkh(ref p) => write!(f, "wpkh({:?})", p),
            Descriptor::ShWpkh(ref p) => write!(f, "sh(wpkh({:?}))", p),
            Descriptor::Sh(ref sub) => write!(f, "sh({:?})", sub),
            Descriptor::Wsh(ref sub) => write!(f, "wsh({:?})", sub),
            Descriptor::ShWsh(ref sub) => write!(f, "sh(wsh({:?}))", sub),
        }
    }
}

impl<Pk: MiniscriptKey> fmt::Display for Descriptor<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Descriptor::Bare(ref sub) => write!(f, "{}", sub),
            Descriptor::Pk(ref p) => write!(f, "pk({})", p),
            Descriptor::Pkh(ref p) => write!(f, "pkh({})", p),
            Descriptor::Wpkh(ref p) => write!(f, "wpkh({})", p),
            Descriptor::ShWpkh(ref p) => write!(f, "sh(wpkh({}))", p),
            Descriptor::Sh(ref sub) => write!(f, "sh({})", sub),
            Descriptor::Wsh(ref sub) => write!(f, "wsh({})", sub),
            Descriptor::ShWsh(ref sub) => write!(f, "sh(wsh({}))", sub),
        }
    }
}

serde_string_impl_pk!(Descriptor, "a script descriptor");

#[cfg(test)]
mod tests {
    use bitcoin::blockdata::opcodes::all::{OP_CLTV, OP_CSV};
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::blockdata::{opcodes, script};
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::hashes::{hash160, sha256};
    use bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPubKey};
    use bitcoin::{self, secp256k1, PublicKey};
    use descriptor::{DescriptorKey, DescriptorXPub};
    use miniscript::satisfy::BitcoinSig;
    use std::collections::HashMap;
    use std::str::FromStr;
    use {Descriptor, DummyKey, Miniscript, Satisfier};

    type StdDescriptor = Descriptor<PublicKey>;
    const TEST_PK: &'static str =
        "pk(020000000000000000000000000000000000000000000000000000000000000002)";

    fn roundtrip_descriptor(s: &str) {
        let desc = Descriptor::<DummyKey>::from_str(&s).unwrap();
        let output = desc.to_string();
        let normalize_aliases = s.replace("c:pk_k(", "pk(").replace("c:pk_h(", "pkh(");
        assert_eq!(normalize_aliases, output);
    }

    #[test]
    fn desc_rtt_tests() {
        roundtrip_descriptor("c:pk_k()");
        roundtrip_descriptor("wsh(pk())");
        roundtrip_descriptor("wsh(c:pk_k())");
        roundtrip_descriptor("c:pk_h()");
    }
    #[test]
    fn parse_descriptor() {
        StdDescriptor::from_str("(").unwrap_err();
        StdDescriptor::from_str("(x()").unwrap_err();
        StdDescriptor::from_str("(\u{7f}()3").unwrap_err();
        StdDescriptor::from_str("pk()").unwrap_err();
        StdDescriptor::from_str("nl:0").unwrap_err(); //issue 63

        StdDescriptor::from_str(TEST_PK).unwrap();

        let uncompressed_pk =
        "0414fc03b8df87cd7b872996810db8458d61da8448e531569c8517b469a119d267be5645686309c6e6736dbd93940707cc9143d3cf29f1b877ff340e2cb2d259cf";

        // Context tests
        StdDescriptor::from_str(&format!("pk({})", uncompressed_pk)).unwrap();
        StdDescriptor::from_str(&format!("pkh({})", uncompressed_pk)).unwrap();
        StdDescriptor::from_str(&format!("sh(pk({}))", uncompressed_pk)).unwrap();
        StdDescriptor::from_str(&format!("wpkh({})", uncompressed_pk)).unwrap_err();
        StdDescriptor::from_str(&format!("sh(wpkh({}))", uncompressed_pk)).unwrap_err();
        StdDescriptor::from_str(&format!("wsh(pk{})", uncompressed_pk)).unwrap_err();
        StdDescriptor::from_str(&format!("sh(wsh(pk{}))", uncompressed_pk)).unwrap_err();
    }

    #[test]
    pub fn script_pubkey() {
        let bare = StdDescriptor::from_str("older(1000)").unwrap();
        assert_eq!(
            bare.script_pubkey(),
            bitcoin::Script::from(vec![0x02, 0xe8, 0x03, 0xb2])
        );
        assert_eq!(bare.address(bitcoin::Network::Bitcoin), None);

        let pk = StdDescriptor::from_str(TEST_PK).unwrap();
        assert_eq!(
            pk.script_pubkey(),
            bitcoin::Script::from(vec![
                0x21, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xac,
            ])
        );

        let pkh = StdDescriptor::from_str(
            "pkh(\
             020000000000000000000000000000000000000000000000000000000000000002\
             )",
        )
        .unwrap();
        assert_eq!(
            pkh.script_pubkey(),
            script::Builder::new()
                .push_opcode(opcodes::all::OP_DUP)
                .push_opcode(opcodes::all::OP_HASH160)
                .push_slice(
                    &hash160::Hash::from_hex("84e9ed95a38613f0527ff685a9928abe2d4754d4",).unwrap()
                        [..]
                )
                .push_opcode(opcodes::all::OP_EQUALVERIFY)
                .push_opcode(opcodes::all::OP_CHECKSIG)
                .into_script()
        );
        assert_eq!(
            pkh.address(bitcoin::Network::Bitcoin).unwrap().to_string(),
            "1D7nRvrRgzCg9kYBwhPH3j3Gs6SmsRg3Wq"
        );

        let wpkh = StdDescriptor::from_str(
            "wpkh(\
             020000000000000000000000000000000000000000000000000000000000000002\
             )",
        )
        .unwrap();
        assert_eq!(
            wpkh.script_pubkey(),
            script::Builder::new()
                .push_opcode(opcodes::all::OP_PUSHBYTES_0)
                .push_slice(
                    &hash160::Hash::from_hex("84e9ed95a38613f0527ff685a9928abe2d4754d4",).unwrap()
                        [..]
                )
                .into_script()
        );
        assert_eq!(
            wpkh.address(bitcoin::Network::Bitcoin).unwrap().to_string(),
            "bc1qsn57m9drscflq5nl76z6ny52hck5w4x5wqd9yt"
        );

        let shwpkh = StdDescriptor::from_str(
            "sh(wpkh(\
             020000000000000000000000000000000000000000000000000000000000000002\
             ))",
        )
        .unwrap();
        assert_eq!(
            shwpkh.script_pubkey(),
            script::Builder::new()
                .push_opcode(opcodes::all::OP_HASH160)
                .push_slice(
                    &hash160::Hash::from_hex("f1c3b9a431134cb90a500ec06e0067cfa9b8bba7",).unwrap()
                        [..]
                )
                .push_opcode(opcodes::all::OP_EQUAL)
                .into_script()
        );
        assert_eq!(
            shwpkh
                .address(bitcoin::Network::Bitcoin)
                .unwrap()
                .to_string(),
            "3PjMEzoveVbvajcnDDuxcJhsuqPHgydQXq"
        );

        let sh = StdDescriptor::from_str(
            "sh(c:pk_k(\
             020000000000000000000000000000000000000000000000000000000000000002\
             ))",
        )
        .unwrap();
        assert_eq!(
            sh.script_pubkey(),
            script::Builder::new()
                .push_opcode(opcodes::all::OP_HASH160)
                .push_slice(
                    &hash160::Hash::from_hex("aa5282151694d3f2f32ace7d00ad38f927a33ac8",).unwrap()
                        [..]
                )
                .push_opcode(opcodes::all::OP_EQUAL)
                .into_script()
        );
        assert_eq!(
            sh.address(bitcoin::Network::Bitcoin).unwrap().to_string(),
            "3HDbdvM9CQ6ASnQFUkWw6Z4t3qNwMesJE9"
        );

        let wsh = StdDescriptor::from_str(
            "wsh(c:pk_k(\
             020000000000000000000000000000000000000000000000000000000000000002\
             ))",
        )
        .unwrap();
        assert_eq!(
            wsh.script_pubkey(),
            script::Builder::new()
                .push_opcode(opcodes::all::OP_PUSHBYTES_0)
                .push_slice(
                    &sha256::Hash::from_hex(
                        "\
                         f9379edc8983152dc781747830075bd5\
                         3896e4b0ce5bff73777fd77d124ba085\
                         "
                    )
                    .unwrap()[..]
                )
                .into_script()
        );
        assert_eq!(
            wsh.address(bitcoin::Network::Bitcoin).unwrap().to_string(),
            "bc1qlymeahyfsv2jm3upw3urqp6m65ufde9seedl7umh0lth6yjt5zzsk33tv6"
        );

        let shwsh = StdDescriptor::from_str(
            "sh(wsh(c:pk_k(\
             020000000000000000000000000000000000000000000000000000000000000002\
             )))",
        )
        .unwrap();
        assert_eq!(
            shwsh.script_pubkey(),
            script::Builder::new()
                .push_opcode(opcodes::all::OP_HASH160)
                .push_slice(
                    &hash160::Hash::from_hex("4bec5d7feeed99e1d0a23fe32a4afe126a7ff07e",).unwrap()
                        [..]
                )
                .push_opcode(opcodes::all::OP_EQUAL)
                .into_script()
        );
        assert_eq!(
            shwsh
                .address(bitcoin::Network::Bitcoin)
                .unwrap()
                .to_string(),
            "38cTksiyPT2b1uGRVbVqHdDhW9vKs84N6Z"
        );
    }

    #[test]
    fn satisfy() {
        let secp = secp256k1::Secp256k1::new();
        let sk =
            secp256k1::SecretKey::from_slice(&b"sally was a secret key, she said"[..]).unwrap();
        let pk = bitcoin::PublicKey {
            key: secp256k1::PublicKey::from_secret_key(&secp, &sk),
            compressed: true,
        };
        let msg = secp256k1::Message::from_slice(&b"michael was a message, amusingly"[..])
            .expect("32 bytes");
        let sig = secp.sign(&msg, &sk);
        let mut sigser = sig.serialize_der().to_vec();
        sigser.push(0x01); // sighash_all

        struct SimpleSat {
            sig: secp256k1::Signature,
            pk: bitcoin::PublicKey,
        };

        impl Satisfier<bitcoin::PublicKey> for SimpleSat {
            fn lookup_sig(&self, pk: &bitcoin::PublicKey) -> Option<BitcoinSig> {
                if *pk == self.pk {
                    Some((self.sig, bitcoin::SigHashType::All))
                } else {
                    None
                }
            }
        }

        let satisfier = SimpleSat { sig, pk };
        let ms = ms_str!("c:pk_k({})", pk);

        let mut txin = bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::default(),
            script_sig: bitcoin::Script::new(),
            sequence: 100,
            witness: vec![],
        };
        let bare = Descriptor::Bare(ms.clone());

        bare.satisfy(&mut txin, &satisfier).expect("satisfaction");
        assert_eq!(
            txin,
            bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::default(),
                script_sig: script::Builder::new().push_slice(&sigser[..]).into_script(),
                sequence: 100,
                witness: vec![],
            }
        );
        assert_eq!(bare.unsigned_script_sig(), bitcoin::Script::new());

        let pkh = Descriptor::Pkh(pk);
        pkh.satisfy(&mut txin, &satisfier).expect("satisfaction");
        assert_eq!(
            txin,
            bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::default(),
                script_sig: script::Builder::new()
                    .push_slice(&sigser[..])
                    .push_key(&pk)
                    .into_script(),
                sequence: 100,
                witness: vec![],
            }
        );
        assert_eq!(pkh.unsigned_script_sig(), bitcoin::Script::new());

        let wpkh = Descriptor::Wpkh(pk);
        wpkh.satisfy(&mut txin, &satisfier).expect("satisfaction");
        assert_eq!(
            txin,
            bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::default(),
                script_sig: bitcoin::Script::new(),
                sequence: 100,
                witness: vec![sigser.clone(), pk.to_bytes(),],
            }
        );
        assert_eq!(wpkh.unsigned_script_sig(), bitcoin::Script::new());

        let shwpkh = Descriptor::ShWpkh(pk);
        shwpkh.satisfy(&mut txin, &satisfier).expect("satisfaction");
        let redeem_script = script::Builder::new()
            .push_opcode(opcodes::all::OP_PUSHBYTES_0)
            .push_slice(
                &hash160::Hash::from_hex("d1b2a1faf62e73460af885c687dee3b7189cd8ab").unwrap()[..],
            )
            .into_script();
        assert_eq!(
            txin,
            bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::default(),
                script_sig: script::Builder::new()
                    .push_slice(&redeem_script[..])
                    .into_script(),
                sequence: 100,
                witness: vec![sigser.clone(), pk.to_bytes(),],
            }
        );
        assert_eq!(
            shwpkh.unsigned_script_sig(),
            script::Builder::new()
                .push_slice(&redeem_script[..])
                .into_script()
        );

        let sh = Descriptor::Sh(ms.clone());
        sh.satisfy(&mut txin, &satisfier).expect("satisfaction");
        assert_eq!(
            txin,
            bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::default(),
                script_sig: script::Builder::new()
                    .push_slice(&sigser[..])
                    .push_slice(&ms.encode()[..])
                    .into_script(),
                sequence: 100,
                witness: vec![],
            }
        );
        assert_eq!(sh.unsigned_script_sig(), bitcoin::Script::new());

        let ms = ms_str!("c:pk_k({})", pk);

        let wsh = Descriptor::Wsh(ms.clone());
        wsh.satisfy(&mut txin, &satisfier).expect("satisfaction");
        assert_eq!(
            txin,
            bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::default(),
                script_sig: bitcoin::Script::new(),
                sequence: 100,
                witness: vec![sigser.clone(), ms.encode().into_bytes(),],
            }
        );
        assert_eq!(wsh.unsigned_script_sig(), bitcoin::Script::new());

        let shwsh = Descriptor::ShWsh(ms.clone());
        shwsh.satisfy(&mut txin, &satisfier).expect("satisfaction");
        assert_eq!(
            txin,
            bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::default(),
                script_sig: script::Builder::new()
                    .push_slice(&ms.encode().to_v0_p2wsh()[..])
                    .into_script(),
                sequence: 100,
                witness: vec![sigser.clone(), ms.encode().into_bytes(),],
            }
        );
        assert_eq!(
            shwsh.unsigned_script_sig(),
            script::Builder::new()
                .push_slice(&ms.encode().to_v0_p2wsh()[..])
                .into_script()
        );
    }

    #[test]
    fn after_is_cltv() {
        let descriptor = Descriptor::<bitcoin::PublicKey>::from_str("wsh(after(1000))").unwrap();
        let script = descriptor.witness_script();

        let actual_instructions: Vec<_> = script.iter(false).collect();
        let check = actual_instructions.last().unwrap();

        assert_eq!(check, &Instruction::Op(OP_CLTV))
    }

    #[test]
    fn older_is_csv() {
        let descriptor = Descriptor::<bitcoin::PublicKey>::from_str("wsh(older(1000))").unwrap();
        let script = descriptor.witness_script();

        let actual_instructions: Vec<_> = script.iter(false).collect();
        let check = actual_instructions.last().unwrap();

        assert_eq!(check, &Instruction::Op(OP_CSV))
    }

    #[test]
    fn roundtrip_tests() {
        let descriptor = Descriptor::<bitcoin::PublicKey>::from_str("multi");
        assert_eq!(
            descriptor.unwrap_err().to_string(),
            "unexpected «no arguments given»"
        )
    }

    #[test]
    fn empty_thresh() {
        let descriptor = Descriptor::<bitcoin::PublicKey>::from_str("thresh");
        assert_eq!(
            descriptor.unwrap_err().to_string(),
            "unexpected «no arguments given»"
        )
    }

    #[test]
    fn witness_stack_for_andv_is_arranged_in_correct_order() {
        // arrange
        let a = bitcoin::PublicKey::from_str(
            "02937402303919b3a2ee5edd5009f4236f069bf75667b8e6ecf8e5464e20116a0e",
        )
        .unwrap();
        let sig_a = secp256k1::Signature::from_str("3045022100a7acc3719e9559a59d60d7b2837f9842df30e7edcd754e63227e6168cec72c5d022066c2feba4671c3d99ea75d9976b4da6c86968dbf3bab47b1061e7a1966b1778c").unwrap();

        let b = bitcoin::PublicKey::from_str(
            "02eb64639a17f7334bb5a1a3aad857d6fec65faef439db3de72f85c88bc2906ad3",
        )
        .unwrap();
        let sig_b = secp256k1::Signature::from_str("3044022075b7b65a7e6cd386132c5883c9db15f9a849a0f32bc680e9986398879a57c276022056d94d12255a4424f51c700ac75122cb354895c9f2f88f0cbb47ba05c9c589ba").unwrap();

        let descriptor = Descriptor::<bitcoin::PublicKey>::from_str(&format!(
            "wsh(and_v(v:pk({A}),pk({B})))",
            A = a,
            B = b
        ))
        .unwrap();

        let mut txin = bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::default(),
            script_sig: bitcoin::Script::new(),
            sequence: 0,
            witness: vec![],
        };
        let satisfier = {
            let mut satisfier = HashMap::with_capacity(2);

            satisfier.insert(a, (sig_a.clone(), ::bitcoin::SigHashType::All));
            satisfier.insert(b, (sig_b.clone(), ::bitcoin::SigHashType::All));

            satisfier
        };

        // act
        descriptor.satisfy(&mut txin, &satisfier).unwrap();

        // assert
        let witness0 = &txin.witness[0];
        let witness1 = &txin.witness[1];

        let sig0 = secp256k1::Signature::from_der(&witness0[..witness0.len() - 1]).unwrap();
        let sig1 = secp256k1::Signature::from_der(&witness1[..witness1.len() - 1]).unwrap();

        // why are we asserting this way?
        // The witness stack is evaluated from top to bottom. Given an `and` instruction, the left arm of the and is going to evaluate first,
        // meaning the next witness element (on a three element stack, that is the middle one) needs to be the signature for the left side of the `and`.
        // The left side of the `and` performs a CHECKSIG against public key `a` so `sig1` needs to be `sig_a` and `sig0` needs to be `sig_b`.
        assert_eq!(sig1, sig_a);
        assert_eq!(sig0, sig_b);
    }

    #[test]
    fn parse_descriptor_key() {
        let key = "[d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*";
        let expected = DescriptorKey::XPub(DescriptorXPub {
            source: Some((
                [0xd3, 0x4d, 0xb3, 0x3f],
                (&[
                    ChildNumber::from_hardened_idx(44).unwrap(),
                    ChildNumber::from_hardened_idx(0).unwrap(),
                    ChildNumber::from_hardened_idx(0).unwrap(),
                ][..])
                .into(),
            )),
            xpub: ExtendedPubKey::from_str("xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL").unwrap(),
            derivation_path: (&[ChildNumber::from_normal_idx(1).unwrap()][..]).into(),
            is_wildcard: true,
        });
        assert_eq!(expected, key.parse().unwrap());
        assert_eq!(format!("{}", expected), key);

        let key = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1";
        let expected = DescriptorKey::XPub(DescriptorXPub {
            source: None,
            xpub: ExtendedPubKey::from_str("xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL").unwrap(),
            derivation_path: (&[ChildNumber::from_normal_idx(1).unwrap()][..]).into(),
            is_wildcard: false,
        });
        assert_eq!(expected, key.parse().unwrap());
        assert_eq!(format!("{}", expected), key);

        let key = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL";
        let expected = DescriptorKey::XPub(DescriptorXPub {
            source: None,
            xpub: ExtendedPubKey::from_str("xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL").unwrap(),
            derivation_path: DerivationPath::from(&[][..]),
            is_wildcard: false,
        });
        assert_eq!(expected, key.parse().unwrap());
        assert_eq!(format!("{}", expected), key);

        let key = "03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8";
        let expected = DescriptorKey::PukKey(
            bitcoin::PublicKey::from_str(
                "03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8",
            )
            .unwrap(),
        );
        assert_eq!(expected, key.parse().unwrap());
        assert_eq!(format!("{}", expected), key);
    }
}
