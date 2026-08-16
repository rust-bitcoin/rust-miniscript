// SPDX-License-Identifier: CC0-1.0

use core::fmt::{self, Display};
use core::str::FromStr;

use bitcoin::bip32;

use super::key_expression::{KeyExpression, KeyIndex};
use super::{to_key_info, KeyInfo, WalletPolicyError};
use crate::descriptor::{DerivPaths, DescriptorMultiXKey, Wildcard};
use crate::{BTreeSet, Descriptor, DescriptorPublicKey, ToString, Translator, Vec};

/// Checks that the key information items are pairwise distinct: BIP-388 requires
/// the deserialized public keys to be so. Only the compressed public key is
/// compared, since two xpubs sharing one are never legitimate.
fn check_keys_distinct(key_info: &[KeyInfo]) -> Result<(), WalletPolicyError> {
    let mut seen = BTreeSet::new();
    for key in key_info {
        if !seen.insert(key.xkey.public_key) {
            return Err(WalletPolicyError::KeyInfoDuplicateKey(key.to_string()));
        }
    }
    Ok(())
}

/// Checks that a key placeholder is followed by `/**` or `/<NUM;NUM>/*` for two
/// distinct unhardened NUMs, the only derivations BIP-388 allows. Both the
/// template parser and `from_descriptor` build placeholders that must satisfy it.
fn check_placeholder_deriv(key: &KeyExpression) -> Result<(), WalletPolicyError> {
    let paths = key.derivation_paths.paths();
    let step = |p: &bip32::DerivationPath| match p.as_ref() {
        [cn] if cn.is_normal() => Some(*cn),
        _ => None,
    };
    if key.wildcard == Wildcard::Unhardened
        && paths.len() == 2
        && matches!((step(&paths[0]), step(&paths[1])), (Some(a), Some(b)) if a != b)
    {
        Ok(())
    } else {
        Err(WalletPolicyError::TemplateValidationInvalidPlaceholderDeriv)
    }
}

struct WalletPolicyTranslator {
    key_info: Vec<KeyInfo>,
}

impl Translator<KeyExpression> for WalletPolicyTranslator {
    type TargetPk = DescriptorPublicKey;
    type Error = WalletPolicyError;

    fn pk(&mut self, pk: &KeyExpression) -> Result<Self::TargetPk, Self::Error> {
        let idx = pk.index.0 as usize;
        let KeyInfo { origin, xkey } = self
            .key_info
            .get(idx)
            .cloned()
            .ok_or(WalletPolicyError::KeyInfoInvalidKeyIndex(idx))?;
        // The derivation path appended will come from the placeholder that refers to it.
        // `validate` (via `check_placeholder_deriv`) guarantees every placeholder carries
        // exactly two paths, so the materialized key is always a multipath one.
        Ok(DescriptorPublicKey::MultiXPub(DescriptorMultiXKey {
            origin,
            xkey,
            derivation_paths: pk.derivation_paths.clone(),
            wildcard: pk.wildcard,
        }))
    }

    // Both key types use the concrete `Hash` types for hash terminals.
    translate_hash_clone!(KeyExpression);
}

impl Translator<DescriptorPublicKey> for WalletPolicyTranslator {
    type TargetPk = KeyExpression;
    type Error = WalletPolicyError;

    fn pk(&mut self, pk: &DescriptorPublicKey) -> Result<Self::TargetPk, Self::Error> {
        // One extraction serves both the index lookup and the placeholder.
        let (origin, xkey, derivation_paths, wildcard) = match pk {
            DescriptorPublicKey::XPub(x) => {
                (&x.origin, &x.xkey, DerivPaths::single(x.derivation_path.clone()), x.wildcard)
            }
            DescriptorPublicKey::MultiXPub(x) => {
                (&x.origin, &x.xkey, x.derivation_paths.clone(), x.wildcard)
            }
            DescriptorPublicKey::Single(_) => return Err(WalletPolicyError::KeyInfoNotExtendedKey),
        };
        // Pre-populated by the only caller in textual order, so the lookup always hits.
        let index = self
            .key_info
            .iter()
            .position(|k| k.origin == *origin && k.xkey == *xkey)
            .ok_or(WalletPolicyError::WalletPolicyInvalidKeyInfo)?;
        Ok(KeyExpression { index: KeyIndex(index as u32), derivation_paths, wildcard })
    }

    // Both key types use the concrete `Hash` types for hash terminals.
    translate_hash_clone!(DescriptorPublicKey);
}

/// A wallet policy as described in BIP-388
///
///```rust
/// use std::str::FromStr;
/// use miniscript::{Descriptor, DescriptorPublicKey};
/// use miniscript::descriptor::{KeyInfo, WalletPolicy};
///
/// // Convert from a `Descriptor<DescriptorPublicKey>`:
/// let desc_str = "pkh([6738736c/44'/0'/0']xpub6Br37sWxruYfT8ASpCjVHKGwgdnYFEn98DwiN76i2oyY6fgH1LAPmmDcF46xjxJr22gw4jmVjTE2E3URMnRPEPYyo1zoPSUba563ESMXCeb/<0;1>/*)";
/// let descriptor = Descriptor::<DescriptorPublicKey>::from_str(desc_str).unwrap();
/// let policy1: WalletPolicy = (&descriptor).try_into().unwrap();
///
/// // Convert from a Descriptor<DescriptorPublicKey> string:
/// let policy2 = WalletPolicy::from_str(desc_str).unwrap();
/// assert_eq!(policy1, policy2);
///
/// // Convert from/to a wallet policy template string:
/// let mut from_template = WalletPolicy::from_str("pkh(@0/**)").unwrap();
/// assert_eq!(from_template.to_string(), "pkh(@0/**)");
/// assert_eq!(from_template.n_keys(), 1);
///
/// // Cannot go back into descriptor if you created from template:
/// assert!(from_template.clone().into_descriptor().is_err());
///
/// // Convert into a full descriptor:
/// assert_eq!(policy1.into_descriptor().unwrap(), descriptor);
///
/// // A template needs its key information items first. These are bare keys;
/// // the derivation comes from the template's placeholders:
/// let key = KeyInfo::from_str("[6738736c/44'/0'/0']xpub6Br37sWxruYfT8ASpCjVHKGwgdnYFEn98DwiN76i2oyY6fgH1LAPmmDcF46xjxJr22gw4jmVjTE2E3URMnRPEPYyo1zoPSUba563ESMXCeb").unwrap();
/// from_template.set_key_info(vec![key]).unwrap();
/// assert_eq!(from_template.key_info().len(), 1);
/// assert_eq!(from_template.into_descriptor().unwrap(), descriptor);
///```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletPolicy {
    /// Wallet descriptor template
    template: Descriptor<KeyExpression>,
    /// Vector of key information items
    key_info: Vec<KeyInfo>,
}

impl WalletPolicy {
    /// Creates a `WalletPolicy` from a `Descriptor<DescriptorPublicKey>`.
    pub fn from_descriptor(
        descriptor: &Descriptor<DescriptorPublicKey>,
    ) -> Result<Self, WalletPolicyError> {
        // One entry per distinct key, numbered in textual order. Must use
        // `iter_pk` here; `translate_pk` walks the descriptor right-to-left.
        let mut key_info: Vec<KeyInfo> = vec![];
        for pk in descriptor.iter_pk() {
            let key = to_key_info(&pk)?;
            if !key_info.contains(&key) {
                key_info.push(key);
            }
        }
        let mut translator = WalletPolicyTranslator { key_info };
        let template = descriptor.translate_pk(&mut translator).map_err(|e| {
            e.expect_translator_err("converting descriptor to wallet policy template")
        })?;
        Self { template, key_info: translator.key_info }.validate()
    }

    /// Convert a `WalletPolicy` into a `Descriptor<DescriptorPublicKey>` using
    /// the underlying template and key information.
    pub fn into_descriptor(self) -> Result<Descriptor<DescriptorPublicKey>, WalletPolicyError> {
        self.template
            .translate_pk(&mut WalletPolicyTranslator { key_info: self.key_info })
            .map_err(|e| e.expect_translator_err("converting to full descriptor"))
    }

    /// The key information items, where `key_info()[i]` fills placeholder `@i`.
    pub fn key_info(&self) -> &[KeyInfo] { &self.key_info }

    /// Counts the distinct key placeholders in the template, which is how many
    /// key information items `WalletPolicy::set_key_info` requires.
    pub fn n_keys(&self) -> usize {
        self.template
            .iter_pk()
            .fold(0, |n, k| n.max(k.index.0 as usize + 1))
    }

    /// Sets the key information so that `WalletPolicy::into_descriptor` can be
    /// called successfully. Errors unless the number of keys matches the number
    /// of placeholders and the keys are pairwise distinct. `keys[i]` fills
    /// placeholder `@i`.
    pub fn set_key_info(&mut self, keys: Vec<KeyInfo>) -> Result<(), WalletPolicyError> {
        if keys.len() != self.n_keys() {
            return Err(WalletPolicyError::WalletPolicyInvalidKeyInfo);
        }
        check_keys_distinct(&keys)?;
        self.key_info = keys;
        Ok(())
    }

    /// Creates a `WalletPolicy` from a template, with no key information items
    /// yet. The only way to build one from a bare template, so that every
    /// construction path is validated.
    fn from_template(template: Descriptor<KeyExpression>) -> Result<Self, WalletPolicyError> {
        Self { template, key_info: vec![] }.validate()
    }

    /// Validates the wallet policy template and its key information items.
    fn validate(self) -> Result<Self, WalletPolicyError> {
        // BIP-388's DESCRIPTOR_TEMPLATE grammar only produces sh, wsh, pkh,
        // wpkh and tr at the top level.
        if matches!(self.template, Descriptor::Bare(_)) {
            return Err(WalletPolicyError::TemplateValidationBareTopLevel);
        }
        // The child numbers placeholder @i has used so far. Indexes are dense,
        // since @i is only accepted once @0..@i-1 have appeared.
        let mut used: Vec<BTreeSet<_>> = vec![];
        for key in self.template.iter_pk() {
            check_placeholder_deriv(&key)?;
            let paths: BTreeSet<_> = key
                .derivation_paths
                .paths()
                .iter()
                .flat_map(|p| p.into_iter().copied())
                .collect();
            let i = key.index.0 as usize;
            if i == used.len() {
                used.push(paths);
            } else if let Some(prev) = used.get_mut(i) {
                // A placeholder may be reused, but not over a path it already covers.
                if !prev.is_disjoint(&paths) {
                    return Err(WalletPolicyError::TemplateValidationNonDisjointPaths);
                }
                prev.extend(paths);
            } else {
                return Err(WalletPolicyError::TemplateValidationKeyIndexOutOfOrder);
            }
        }
        if used.is_empty() {
            return Err(WalletPolicyError::TemplateValidationNoKeyPlaceholder);
        }
        check_keys_distinct(&self.key_info)?;
        Ok(self)
    }
}

impl Display for WalletPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{:#}", self.template) }
}

impl TryFrom<&Descriptor<DescriptorPublicKey>> for WalletPolicy {
    type Error = WalletPolicyError;

    fn try_from(desc: &Descriptor<DescriptorPublicKey>) -> Result<Self, Self::Error> {
        Self::from_descriptor(desc)
    }
}

impl TryFrom<&str> for WalletPolicy {
    type Error = WalletPolicyError;

    fn try_from(desc: &str) -> Result<Self, Self::Error> {
        match Descriptor::<KeyExpression>::from_str(desc) {
            Ok(template) => Ok(Self::from_template(template)?),
            Err(err1) => match Descriptor::<DescriptorPublicKey>::from_str(desc) {
                Ok(desc) => Ok(Self::from_descriptor(&desc)?),
                Err(err2) => Err(WalletPolicyError::WalletPolicyParseFromString(format!(
                    "Couldn't parse as a wallet policy template [{err1}], or as a descriptor [{err2}]"
                ))),
            },
        }
    }
}

impl FromStr for WalletPolicy {
    type Err = WalletPolicyError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { s.try_into() }
}
