// SPDX-License-Identifier: CC0-1.0

use bitcoin::bip32;

use super::key_expression::KeyExpression;
use super::{KeyInfo, WalletPolicyError};
use crate::descriptor::Wildcard;
use crate::{BTreeSet, Descriptor, ToString, Vec};

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
    /// Creates a `WalletPolicy` from a template, with no key information items
    /// yet.
    pub(super) fn from_template(
        template: Descriptor<KeyExpression>,
    ) -> Result<Self, WalletPolicyError> {
        check_policy(&template, &[])?;
        Ok(Self { template, key_info: vec![] })
    }

    pub(super) fn as_template(&self) -> &Descriptor<KeyExpression> { &self.template }

    pub(super) fn into_template(self) -> Descriptor<KeyExpression> { self.template }

    /// The key information items, where `key_info()[i]` fills placeholder `@i`.
    pub fn key_info(&self) -> &[KeyInfo] { &self.key_info }

    /// Sets the key information so that `WalletPolicy::into_descriptor` can be
    /// called successfully. Errors unless the number of keys matches the number
    /// of placeholders and the keys are pairwise distinct. `keys[i]` fills
    /// placeholder `@i`.
    pub fn set_key_info(&mut self, keys: Vec<KeyInfo>) -> Result<(), WalletPolicyError> {
        // An empty vector is a valid *state* (a template-only policy) but never
        // a valid argument here: this method exists to supply the keys.
        if keys.is_empty() {
            return Err(WalletPolicyError::WalletPolicyInvalidKeyInfo);
        }
        check_policy(&self.template, &keys)?;
        self.key_info = keys;
        Ok(())
    }
}

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

/// Checks every BIP-388 wallet policy invariant: the template's top-level and
/// placeholder rules, and that `key_info` is either empty (no key information
/// supplied yet) or exactly one pairwise-distinct item per placeholder. Every
/// construction and mutation of a `WalletPolicy` goes through this.
fn check_policy(
    template: &Descriptor<KeyExpression>,
    key_info: &[KeyInfo],
) -> Result<(), WalletPolicyError> {
    // BIP-388's DESCRIPTOR_TEMPLATE grammar only produces sh, wsh, pkh,
    // wpkh and tr at the top level.
    if matches!(template, Descriptor::Bare(_)) {
        return Err(WalletPolicyError::TemplateValidationBareTopLevel);
    }
    // The child numbers placeholder @i has used so far. Indexes are dense,
    // since @i is only accepted once @0..@i-1 have appeared.
    let mut used: Vec<BTreeSet<_>> = vec![];
    for key in template.iter_pk() {
        check_placeholder_deriv(&key)?;
        let paths = key.derivation_paths.paths();
        let paths: BTreeSet<_> = paths.iter().flatten().copied().collect();
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
    // Key information is all-or-nothing: absent for a bare template, or
    // exactly one item per distinct placeholder.
    if !key_info.is_empty() && key_info.len() != used.len() {
        return Err(WalletPolicyError::WalletPolicyInvalidKeyInfo);
    }
    check_keys_distinct(key_info)
}
