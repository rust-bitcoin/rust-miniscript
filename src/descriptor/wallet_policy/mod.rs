// SPDX-License-Identifier: CC0-1.0

use core::fmt::{self, Display};
use core::str::FromStr;

use bitcoin::bip32;
use bitcoin::hashes::{hash160, ripemd160, sha256};

use super::key::{maybe_fmt_master_id, XKeyParseError};
use super::{DerivPaths, DescriptorKeyParseError, DescriptorMultiXKey, DescriptorXKey, Wildcard};
use crate::{BTreeSet, Descriptor, DescriptorPublicKey, String, ToString, Translator, Vec};

mod key_expression;

use key_expression::{KeyExpression, KeyIndex};

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

/// A BIP-388 key information item: an extended public key with an optional key
/// origin, and no derivation path or wildcard of its own. The derivation comes
/// from the key placeholders in the wallet policy template.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyInfo {
    /// Origin information
    pub origin: Option<(bip32::Fingerprint, bip32::DerivationPath)>,
    /// The extended public key
    pub xkey: bip32::Xpub,
}

impl TryFrom<DescriptorPublicKey> for KeyInfo {
    type Error = WalletPolicyError;

    /// Rejects rather than strips, since dropping a derivation the caller wrote
    /// would silently use a different key than they asked for.
    fn try_from(pk: DescriptorPublicKey) -> Result<Self, Self::Error> {
        match pk {
            DescriptorPublicKey::XPub(xpub)
                if xpub.derivation_path.is_empty() && xpub.wildcard == Wildcard::None =>
            {
                Ok(Self { origin: xpub.origin, xkey: xpub.xkey })
            }
            DescriptorPublicKey::XPub(_) | DescriptorPublicKey::MultiXPub(_) => {
                Err(WalletPolicyError::KeyInfoUnexpectedDerivation(pk.to_string()))
            }
            DescriptorPublicKey::Single(_) => Err(WalletPolicyError::KeyInfoNotExtendedKey),
        }
    }
}

impl From<KeyInfo> for DescriptorPublicKey {
    fn from(key: KeyInfo) -> Self {
        Self::XPub(DescriptorXKey {
            origin: key.origin,
            xkey: key.xkey,
            derivation_path: bip32::DerivationPath::from(vec![]),
            wildcard: Wildcard::None,
        })
    }
}

impl FromStr for KeyInfo {
    type Err = DescriptorKeyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(DescriptorPublicKey::from_str(s)?).map_err(Into::into)
    }
}

impl Display for KeyInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        maybe_fmt_master_id(f, &self.origin)?;
        self.xkey.fmt(f)
    }
}

/// Checks that the key information items are pairwise distinct: BIP-388 requires
/// the deserialized public keys to be so. Only the compressed public key is
/// compared, since two xpubs sharing one are never legitimate.
fn check_keys_distinct(key_info: &[KeyInfo]) -> Result<(), WalletPolicyError> {
    let same_pubkey = |a: &KeyInfo, b: &KeyInfo| a.xkey.public_key == b.xkey.public_key;
    for (i, key) in key_info.iter().enumerate() {
        if key_info[..i].iter().any(|other| same_pubkey(other, key)) {
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

/// Reduces a descriptor key to its key information item form. Unlike the public
/// `TryFrom`, drops any derivation: the template captures it instead.
fn to_key_info(pk: &DescriptorPublicKey) -> Result<KeyInfo, WalletPolicyError> {
    let (origin, xkey) = match pk {
        DescriptorPublicKey::XPub(xpub) => (xpub.origin.clone(), xpub.xkey),
        DescriptorPublicKey::MultiXPub(xpub) => (xpub.origin.clone(), xpub.xkey),
        DescriptorPublicKey::Single(_) => return Err(WalletPolicyError::KeyInfoNotExtendedKey),
    };
    Ok(KeyInfo { origin, xkey })
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

    // Hash terminals: KeyExpression stores hashes as hex `String` (for
    // template round-tripping), DescriptorPublicKey uses the concrete
    // `bitcoin::hashes::*::Hash` types. Parse the hex string into the
    // binary form during materialization.

    fn sha256(&mut self, s: &String) -> Result<sha256::Hash, Self::Error> {
        s.parse::<sha256::Hash>()
            .map_err(|_| WalletPolicyError::TranslatorInvalidHashHex("sha256", s.clone()))
    }

    fn hash256(&mut self, s: &String) -> Result<crate::hash256::Hash, Self::Error> {
        s.parse::<crate::hash256::Hash>()
            .map_err(|_| WalletPolicyError::TranslatorInvalidHashHex("hash256", s.clone()))
    }

    fn ripemd160(&mut self, s: &String) -> Result<ripemd160::Hash, Self::Error> {
        s.parse::<ripemd160::Hash>()
            .map_err(|_| WalletPolicyError::TranslatorInvalidHashHex("ripemd160", s.clone()))
    }

    fn hash160(&mut self, s: &String) -> Result<hash160::Hash, Self::Error> {
        s.parse::<hash160::Hash>()
            .map_err(|_| WalletPolicyError::TranslatorInvalidHashHex("hash160", s.clone()))
    }
}

impl Translator<DescriptorPublicKey> for WalletPolicyTranslator {
    type TargetPk = KeyExpression;
    type Error = WalletPolicyError;

    fn pk(&mut self, pk: &DescriptorPublicKey) -> Result<Self::TargetPk, Self::Error> {
        // Pre-populated by the only caller in textual order, so the lookup always hits.
        let key = to_key_info(pk)?;
        let index = self
            .key_info
            .iter()
            .position(|p| *p == key)
            .ok_or(WalletPolicyError::WalletPolicyInvalidKeyInfo)?;
        let ke = KeyExpression {
            index: KeyIndex(index as u32),
            derivation_paths: DerivPaths::new(pk.derivation_paths())
                .ok_or(WalletPolicyError::TranslatorEmptyDerivationPaths)?,
            wildcard: pk
                .wildcard()
                .ok_or(WalletPolicyError::TranslatorMissingWildcard)?,
        };
        Ok(ke)
    }

    // Hash terminals: DescriptorPublicKey uses concrete Hash types,
    // KeyExpression stores them as hex `String`. Render to lowercase hex
    // (the `Display` impl on `bitcoin::hashes::*::Hash`) so the resulting
    // template prints hashes in their canonical form.

    fn sha256(&mut self, h: &sha256::Hash) -> Result<String, Self::Error> { Ok(h.to_string()) }

    fn hash256(&mut self, h: &crate::hash256::Hash) -> Result<String, Self::Error> {
        Ok(h.to_string())
    }

    fn ripemd160(&mut self, h: &ripemd160::Hash) -> Result<String, Self::Error> {
        Ok(h.to_string())
    }

    fn hash160(&mut self, h: &hash160::Hash) -> Result<String, Self::Error> { Ok(h.to_string()) }
}

impl WalletPolicy {
    /// Create a new `WalletPolicy` from a
    /// `Descriptor<DescriptorPublicKey>`. Does not validate the underlying
    /// template.
    pub fn from_descriptor_unchecked(
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
        Ok(Self {
            template: descriptor.translate_pk(&mut translator).map_err(|e| {
                e.expect_translator_err("converting descriptor to wallet policy template")
            })?,
            key_info: translator.key_info,
        })
    }

    /// Create a new `WalletPolicy` from a `Descriptor<DescriptorPublicKey>` and
    /// validates the underyling template.
    pub fn from_descriptor(
        descriptor: &Descriptor<DescriptorPublicKey>,
    ) -> Result<Self, WalletPolicyError> {
        Self::from_descriptor_unchecked(descriptor).and_then(Self::validate)
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

    /// Sets the key information so that `WalletPolicy::into_descriptor` can be
    /// called successfully. Errors when there are not enough keys for the
    /// template, or when the keys are not pairwise distinct. `keys[i]` fills
    /// placeholder `@i`.
    pub fn set_key_info(&mut self, keys: Vec<KeyInfo>) -> Result<(), WalletPolicyError> {
        let unique_placeholders: BTreeSet<u32> =
            self.template.iter_pk().map(|k| k.index.0).collect();
        if keys.len() != unique_placeholders.len() {
            return Err(WalletPolicyError::WalletPolicyInvalidKeyInfo);
        }
        check_keys_distinct(&keys)?;
        self.key_info = keys;
        Ok(())
    }

    /// Validates the wallet policy template and its key information items.
    #[must_use = "Wallet policy won't be considered valid until this is called"]
    fn validate(self) -> Result<Self, WalletPolicyError> {
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
            Ok(template) => Ok(Self { template, key_info: vec![] }.validate()?),
            Err(err1) => match Descriptor::<DescriptorPublicKey>::from_str(desc) {
                Ok(desc) => Ok(Self::from_descriptor(&desc)?),
                Err(err2) => Err(WalletPolicyError::WalletPolicyParseFromString(format!(
                    "Couldn't parse from descriptor [{err1}], or wallet policy template: [{err2}]"
                ))),
            },
        }
    }
}

impl FromStr for WalletPolicy {
    type Err = WalletPolicyError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { s.try_into() }
}

/// WalletPolicy errors
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum WalletPolicyError {
    /// A derivation path must be present when parsing a KeyExpression
    KeyExpressionParseMustHaveDerivPath,
    /// The KeyIndex is missing an '@' sign
    KeyIndexParseExpectedAtSign(char),
    /// The key index after '@' is not a decimal number with no leading zeros
    KeyIndexParseInvalidIndex(String),
    /// The key info is not found for the given index
    KeyInfoInvalidKeyIndex(usize),
    /// A key information item is not an extended key
    KeyInfoNotExtendedKey,
    /// The same key appears twice in the key information items
    KeyInfoDuplicateKey(String),
    /// A key information item has a derivation path or wildcard of its own
    KeyInfoUnexpectedDerivation(String),
    /// The key indexes in the template are out of order
    TemplateValidationKeyIndexOutOfOrder,
    /// The key indexes in the template are the same but the paths are non-disjoint
    TemplateValidationNonDisjointPaths,
    /// A key placeholder is not followed by "/**" or "/<NUM;NUM>/*" with two
    /// distinct canonical unhardened NUMs
    TemplateValidationInvalidPlaceholderDeriv,
    /// There must be at least one derivation path for a xpub
    TranslatorEmptyDerivationPaths,
    /// Missing wildcard on xpub
    TranslatorMissingWildcard,
    /// Couldn't parse wallet policy from string
    WalletPolicyParseFromString(String),
    /// Couldn't set key info on WalletPolicy
    WalletPolicyInvalidKeyInfo,
    /// Hash terminal in template had invalid hex (kind, raw input)
    TranslatorInvalidHashHex(&'static str, String),
}

impl From<WalletPolicyError> for DescriptorKeyParseError {
    fn from(err: WalletPolicyError) -> Self { Self::XKeyParseError(XKeyParseError::Bip388(err)) }
}

#[cfg(feature = "std")]
impl std::error::Error for WalletPolicyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

impl Display for WalletPolicyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::KeyExpressionParseMustHaveDerivPath => {
                write!(f, "Key expression placeholder must have a derivation path after it")
            }
            Self::KeyIndexParseInvalidIndex(index_str) => {
                write!(
                    f,
                    "Key index must be a decimal number with no leading zeros, got {index_str}"
                )
            }
            Self::KeyIndexParseExpectedAtSign(ch) => {
                write!(f, "Expected KeyIndex '@' sign, got {ch}")
            }
            Self::KeyInfoInvalidKeyIndex(idx) => {
                write!(f, "Invalid index [{idx}] into key info for wallet policy")
            }
            Self::KeyInfoNotExtendedKey => {
                write!(f, "Key information items must be extended keys")
            }
            Self::KeyInfoDuplicateKey(key) => {
                write!(f, "Key information items must be pairwise distinct, got {key} twice")
            }
            Self::KeyInfoUnexpectedDerivation(key) => {
                write!(
                    f,
                    "Key information items must not have a derivation path or wildcard, got {key}"
                )
            }
            Self::TemplateValidationKeyIndexOutOfOrder => {
                write!(f, "The template has indexes that are out of order")
            }
            Self::TemplateValidationNonDisjointPaths => {
                write!(f, "The template has identical indexes but the paths are non-disjoint")
            }
            Self::TemplateValidationInvalidPlaceholderDeriv => {
                write!(
                    f,
                    "Key placeholders must be followed by \"/**\" or \"/<NUM;NUM>/*\" \
                     with two distinct unhardened NUMs"
                )
            }
            Self::TranslatorEmptyDerivationPaths => {
                write!(f, "Expected derivation paths when translating into KeyExpression")
            }
            Self::TranslatorMissingWildcard => {
                write!(f, "Missing wildcard. Not an xpub?")
            }
            Self::WalletPolicyParseFromString(msg) => msg.fmt(f),
            Self::WalletPolicyInvalidKeyInfo => {
                write!(f, "Invalid key information for WalletPolicy template")
            }
            Self::TranslatorInvalidHashHex(kind, raw) => {
                write!(f, "Invalid hex for {kind} hash terminal: {raw}")
            }
        }
    }
}

impl From<WalletPolicyError> for XKeyParseError {
    fn from(err: WalletPolicyError) -> Self { Self::Bip388(err) }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::Descriptor;

    const XPUB: &str = "xpub6Bex1CHWGXNNwGVKHLqNC7kcV348FxkCxpZXyCWp1k27kin8sRPayjZUKDjyQeZzGUdyeAj2emoW5zStFFUAHRgd5w8iVVbLgZ7PmjAKAm9";

    const VALID_TEMPLATES: &[(&str, &str)] = &[
    (
        "pkh(@0/**)",
        "pkh([6738736c/44'/0'/0']xpub6Br37sWxruYfT8ASpCjVHKGwgdnYFEn98DwiN76i2oyY6fgH1LAPmmDcF46xjxJr22gw4jmVjTE2E3URMnRPEPYyo1zoPSUba563ESMXCeb/<0;1>/*)"
    ),
    (
        "sh(wpkh(@0/**))",
        "sh(wpkh([6738736c/49'/0'/1']xpub6Bex1CHWGXNNwGVKHLqNC7kcV348FxkCxpZXyCWp1k27kin8sRPayjZUKDjyQeZzGUdyeAj2emoW5zStFFUAHRgd5w8iVVbLgZ7PmjAKAm9/<0;1>/*))"
    ),
    (
        "wpkh(@0/**)",
        "wpkh([6738736c/84'/0'/2']xpub6CRQzb8u9dmMcq5XAwwRn9gcoYCjndJkhKgD11WKzbVGd932UmrExWFxCAvRnDN3ez6ZujLmMvmLBaSWdfWVn75L83Qxu1qSX4fJNrJg2Gt/<0;1>/*)"
    ),
    (
        "tr(@0/**)",
        "tr([6738736c/86'/0'/0']xpub6CryUDWPS28eR2cDyojB8G354izmx294BdjeSvH469Ty3o2E6Tq5VjBJCn8rWBgesvTJnyXNAJ3QpLFGuNwqFXNt3gn612raffLWfdHNkYL/<0;1>/*)"
    ),
    (
        "wsh(sortedmulti(2,@0/**,@1/**))",
        "wsh(sortedmulti(2,[6738736c/48'/0'/0'/2']xpub6FC1fXFP1GXLX5TKtcjHGT4q89SDRehkQLtbKJ2PzWcvbBHtyDsJPLtpLtkGqYNYZdVVAjRQ5kug9CsapegmmeRutpP7PW4u4wVF9JfkDhw/<0;1>/*,[b2b1f0cf/48'/0'/0'/2']xpub6EWhjpPa6FqrcaPBuGBZRJVjzGJ1ZsMygRF26RwN932Vfkn1gyCiTbECVitBjRCkexEvetLdiqzTcYimmzYxyR1BZ79KNevgt61PDcukmC7/<0;1>/*))"
    ),
    (
        "wsh(thresh(3,pk(@0/**),s:pk(@1/**),s:pk(@2/**),sln:older(12960)))",
        "wsh(thresh(3,pk([6738736c/48'/0'/0'/100']xpub6FC1fXFP1GXQpyRFfSE1vzzySqs3Vg63bzimYLeqtNUYbzA87kMNTcuy9ubr7MmavGRjW2FRYHP4WGKjwutbf1ghgkUW9H7e3ceaPLRcVwa/<0;1>/*),s:pk([b2b1f0cf/44'/0'/0'/100']xpub6EYajCJHe2CK53RLVXrN14uWoEttZgrRSaRztujsXg7yRhGtHmLBt9ot9Pd5ugfwWEu6eWyJYKSshyvZFKDXiNbBcoK42KRZbxwjRQpm5Js/<0;1>/*),s:pk([a666a867/44'/0'/0'/100']xpub6Dgsze3ujLi1EiHoCtHFMS9VLS1UheVqxrHGfP7sBJ2DBfChEUHV4MDwmxAXR2ayeytpwm3zJEU3H3pjCR6q6U5sP2p2qzAD71x9z5QShK2/<0;1>/*),sln:older(12960)))"
    ),
    (
        "wsh(or_d(pk(@0/**),and_v(v:multi(2,@1/**,@2/**,@3/**),older(65535))))",
        "wsh(or_d(pk([6738736c/48'/0'/0'/100']xpub6FC1fXFP1GXQpyRFfSE1vzzySqs3Vg63bzimYLeqtNUYbzA87kMNTcuy9ubr7MmavGRjW2FRYHP4WGKjwutbf1ghgkUW9H7e3ceaPLRcVwa/<0;1>/*),and_v(v:multi(2,[b2b1f0cf/44'/0'/0'/100']xpub6EYajCJHe2CK53RLVXrN14uWoEttZgrRSaRztujsXg7yRhGtHmLBt9ot9Pd5ugfwWEu6eWyJYKSshyvZFKDXiNbBcoK42KRZbxwjRQpm5Js/<0;1>/*,[a666a867/44'/0'/0'/100']xpub6Dgsze3ujLi1EiHoCtHFMS9VLS1UheVqxrHGfP7sBJ2DBfChEUHV4MDwmxAXR2ayeytpwm3zJEU3H3pjCR6q6U5sP2p2qzAD71x9z5QShK2/<0;1>/*,[bb641298/44'/0'/0'/100']xpub6Dz8PHFmXkYkykQ83ySkruky567XtJb9N69uXScJZqweYiQn6FyieajdiyjCvWzRZ2GoLHMRE1cwDfuJZ6461YvNRGVBJNnLA35cZrQKSRJ/<0;1>/*),older(65535))))"
    ),
    (
       "sh(multi(1,@0/**,@0/<2;3>/*))",
       "sh(multi(1,xpub6Bex1CHWGXNNwGVKHLqNC7kcV348FxkCxpZXyCWp1k27kin8sRPayjZUKDjyQeZzGUdyeAj2emoW5zStFFUAHRgd5w8iVVbLgZ7PmjAKAm9/<0;1>/*,xpub6Bex1CHWGXNNwGVKHLqNC7kcV348FxkCxpZXyCWp1k27kin8sRPayjZUKDjyQeZzGUdyeAj2emoW5zStFFUAHRgd5w8iVVbLgZ7PmjAKAm9/<2;3>/*))"
    ),
    // Only the first occurrence of a placeholder has to be in order, so a
    // placeholder other than @0 may be reused, and reuses need not be adjacent.
    (
       "wsh(multi(2,@0/**,@1/**,@1/<2;3>/*))",
       "wsh(multi(2,xpub6Bex1CHWGXNNwGVKHLqNC7kcV348FxkCxpZXyCWp1k27kin8sRPayjZUKDjyQeZzGUdyeAj2emoW5zStFFUAHRgd5w8iVVbLgZ7PmjAKAm9/<0;1>/*,xpub6EWhjpPa6FqrcaPBuGBZRJVjzGJ1ZsMygRF26RwN932Vfkn1gyCiTbECVitBjRCkexEvetLdiqzTcYimmzYxyR1BZ79KNevgt61PDcukmC7/<0;1>/*,xpub6EWhjpPa6FqrcaPBuGBZRJVjzGJ1ZsMygRF26RwN932Vfkn1gyCiTbECVitBjRCkexEvetLdiqzTcYimmzYxyR1BZ79KNevgt61PDcukmC7/<2;3>/*))"
    ),
    (
       "wsh(multi(2,@0/**,@1/**,@0/<2;3>/*))",
       "wsh(multi(2,xpub6Bex1CHWGXNNwGVKHLqNC7kcV348FxkCxpZXyCWp1k27kin8sRPayjZUKDjyQeZzGUdyeAj2emoW5zStFFUAHRgd5w8iVVbLgZ7PmjAKAm9/<0;1>/*,xpub6EWhjpPa6FqrcaPBuGBZRJVjzGJ1ZsMygRF26RwN932Vfkn1gyCiTbECVitBjRCkexEvetLdiqzTcYimmzYxyR1BZ79KNevgt61PDcukmC7/<0;1>/*,xpub6Bex1CHWGXNNwGVKHLqNC7kcV348FxkCxpZXyCWp1k27kin8sRPayjZUKDjyQeZzGUdyeAj2emoW5zStFFUAHRgd5w8iVVbLgZ7PmjAKAm9/<2;3>/*))"
    ),
    (
        "tr(@0/**,{sortedmulti_a(1,@0/<2;3>/*,@1/**),or_b(pk(@2/**),s:pk(@3/**))})",
        "tr([6738736c/48'/0'/0'/100']xpub6FC1fXFP1GXQpyRFfSE1vzzySqs3Vg63bzimYLeqtNUYbzA87kMNTcuy9ubr7MmavGRjW2FRYHP4WGKjwutbf1ghgkUW9H7e3ceaPLRcVwa/<0;1>/*,{sortedmulti_a(1,[6738736c/48'/0'/0'/100']xpub6FC1fXFP1GXQpyRFfSE1vzzySqs3Vg63bzimYLeqtNUYbzA87kMNTcuy9ubr7MmavGRjW2FRYHP4WGKjwutbf1ghgkUW9H7e3ceaPLRcVwa/<2;3>/*,xpub6Fc2TRaCWNgfT49nRGG2G78d1dPnjhW66gEXi7oYZML7qEFN8e21b2DLDipTZZnfV6V7ivrMkvh4VbnHY2ChHTS9qM3XVLJiAgcfagYQk6K/<0;1>/*),or_b(pk(xpub6GxHB9kRdFfTqYka8tgtX9Gh3Td3A9XS8uakUGVcJ9NGZ1uLrGZrRVr67DjpMNCHprZmVmceFTY4X4wWfksy8nVwPiNvzJ5pjLxzPtpnfEM/<0;1>/*),s:pk(xpub6GjFUVVYewLj5no5uoNKCWuyWhQ1rKGvV8DgXBG9Uc6DvAKxt2dhrj1EZFrTNB5qxAoBkVW3wF8uCS3q1ri9fueAa6y7heFTcf27Q4gyeh6/<0;1>/*))})"
    ),
    // BIP-388 requires the two NUMs of a `/<NUM;NUM>/*` placeholder to be distinct, not ascending.
    (
        "wpkh(@0/<1;0>/*)",
        "wpkh(xpub6Bex1CHWGXNNwGVKHLqNC7kcV348FxkCxpZXyCWp1k27kin8sRPayjZUKDjyQeZzGUdyeAj2emoW5zStFFUAHRgd5w8iVVbLgZ7PmjAKAm9/<1;0>/*)"
    ),
    // TODO: uncomment if BIP-390 is ever supported
    // (
    //     "tr(musig(@0,@1,@2)/**,{and_v(v:pk(musig(@0,@1)/**),older(12960)),{and_v(v:pk(musig(@0,@2)/**),older(12960)),and_v(v:pk(musig(@1,@2)/**),older(12960))}})",
    //     "tr(musig([6738736c/48'/0'/0'/100']xpub6FC1fXFP1GXQpyRFfSE1vzzySqs3Vg63bzimYLeqtNUYbzA87kMNTcuy9ubr7MmavGRjW2FRYHP4WGKjwutbf1ghgkUW9H7e3ceaPLRcVwa,[b2b1f0cf/44'/0'/0'/100']xpub6EYajCJHe2CK53RLVXrN14uWoEttZgrRSaRztujsXg7yRhGtHmLBt9ot9Pd5ugfwWEu6eWyJYKSshyvZFKDXiNbBcoK42KRZbxwjRQpm5Js,[a666a867/44'/0'/0'/100']xpub6Dgsze3ujLi1EiHoCtHFMS9VLS1UheVqxrHGfP7sBJ2DBfChEUHV4MDwmxAXR2ayeytpwm3zJEU3H3pjCR6q6U5sP2p2qzAD71x9z5QShK2)/<0;1>/*,{and_v(v:pk(musig([6738736c/48'/0'/0'/100']xpub6FC1fXFP1GXQpyRFfSE1vzzySqs3Vg63bzimYLeqtNUYbzA87kMNTcuy9ubr7MmavGRjW2FRYHP4WGKjwutbf1ghgkUW9H7e3ceaPLRcVwa,[b2b1f0cf/44'/0'/0'/100']xpub6EYajCJHe2CK53RLVXrN14uWoEttZgrRSaRztujsXg7yRhGtHmLBt9ot9Pd5ugfwWEu6eWyJYKSshyvZFKDXiNbBcoK42KRZbxwjRQpm5Js)/<0;1>/*),older(12960)),{and_v(v:pk(musig([6738736c/48'/0'/0'/100']xpub6FC1fXFP1GXQpyRFfSE1vzzySqs3Vg63bzimYLeqtNUYbzA87kMNTcuy9ubr7MmavGRjW2FRYHP4WGKjwutbf1ghgkUW9H7e3ceaPLRcVwa,[a666a867/44'/0'/0'/100']xpub6Dgsze3ujLi1EiHoCtHFMS9VLS1UheVqxrHGfP7sBJ2DBfChEUHV4MDwmxAXR2ayeytpwm3zJEU3H3pjCR6q6U5sP2p2qzAD71x9z5QShK2)/<0;1>/*),older(12960)),and_v(v:pk(musig([b2b1f0cf/44'/0'/0'/100']xpub6EYajCJHe2CK53RLVXrN14uWoEttZgrRSaRztujsXg7yRhGtHmLBt9ot9Pd5ugfwWEu6eWyJYKSshyvZFKDXiNbBcoK42KRZbxwjRQpm5Js,[a666a867/44'/0'/0'/100']xpub6Dgsze3ujLi1EiHoCtHFMS9VLS1UheVqxrHGfP7sBJ2DBfChEUHV4MDwmxAXR2ayeytpwm3zJEU3H3pjCR6q6U5sP2p2qzAD71x9z5QShK2)/<0;1>/*),older(12960))}})"
    // ),
    ];

    const INVALID_TEMPLATES: &[&str] = &[
    // Key placeholder with no path following it
    "pkh(@0)",

    // Key placeholder with an explicit path present
    "pkh(@0/0/**)",

    // Key placeholders out of order
    "sh(multi(1,@1/**,@0/**))",

    // Skipped key placeholder @1
    "sh(multi(1,@0/**,@2/**))",

    // Repeated keys with the same path expression
    "sh(multi(1,@0/**,@0/**))",

    // Non-disjoint multipath expressions (@0/1/* appears twice)
    "sh(multi(1,@0/<0;1>/*,@0/<1;2>/*))",

    // Expression with a non-KP key present
    "sh(multi(1,@0/**,xpub6AHA9hZDN11k2ijHMeS5QqHx2KP9aMBRhTDqANMnwVtdyw2TDYRmF8PjpvwUFcL1Et8Hj59S3gTSMcUQ5gAqTz3Wd8EsMTmF3DChhqPQBnU/<0;1>/*))",

    // Allowed cardinality > 2
    "pkh(@0/<0;1;2>/*)",

    // Key placeholder index with a leading zero, or with trailing garbage
    "pkh(@00/**)",
    "pkh(@0abc/**)",

    // Non-canonical NUMs (leading zero or sign) in a placeholder derivation,
    // a repeated NUM, and a "**" that is not a whole path step
    "pkh(@0/<00;1>/*)",
    "pkh(@0/<0;01>/*)",
    "pkh(@0/<+0;1>/*)",
    "pkh(@0/<0;0>/*)",
    "pkh(@0/1**)",

    // Derivation before aggregation is not allowed in wallet policies (despite
        // being allowed in BIP-390)
        // TODO: uncomment if BIP-390 is ever supported
    // "tr(musig(@0/**,@1/**))",
];

    #[test]
    fn can_parse_valid_wallet_policy_templates() {
        for (t, desc) in VALID_TEMPLATES {
            let descriptor = Descriptor::<DescriptorPublicKey>::from_str(desc).unwrap();
            let policy = WalletPolicy::from_str(desc).expect("invalid descriptor");
            let template = WalletPolicy::from_str(t).expect("invalid template");
            assert_eq!(format!("{:#}", template.template), *t);
            // The round trip below is satisfied by any self-consistent
            // numbering, so check the template text too.
            assert_eq!(format!("{:#}", policy.template), *t);
            assert_eq!(policy.into_descriptor().unwrap(), descriptor);
        }
    }

    #[test]
    fn can_error_on_invalid_wallet_policy_templates() {
        for t in INVALID_TEMPLATES {
            assert!(WalletPolicy::from_str(t).is_err());
        }
        // Descriptor keys whose derivation is not a valid key placeholder path.
        // These parse as descriptors, so they reach the template only through
        // `from_descriptor`, which used to accept them.
        for suffix in ["", "/0/*", "/0h/*h", "/<0;1>/2/*"] {
            assert!(WalletPolicy::from_str(&format!("wpkh({XPUB}{suffix})")).is_err(), "{suffix}");
        }
        // The same xpub under two origins is still one key, so the key
        // information items would not be pairwise distinct.
        let dup = format!(
            "wsh(multi(2,[6738736c/48'/0'/0'/2']{XPUB}/<0;1>/*,[b2b1f0cf/48'/0'/0'/2']{XPUB}/<2;3>/*))"
        );
        assert!(matches!(
            WalletPolicy::from_str(&dup),
            Err(WalletPolicyError::KeyInfoDuplicateKey(_))
        ));
    }

    // Hash-terminal round-trip tests. Before this fix the translator used
    // `translate_hash_fail!` and `into_descriptor` returned an error on any
    // hash terminal; BIP 388 places no restriction on them.

    // BIP 84 mainnet origin; same xpub as VALID_TEMPLATES.
    const TEST_XPUB: &str = "[6738736c/84'/0'/0']xpub6CRQzb8u9dmMcq5XAwwRn9gcoYCjndJkhKgD11WKzbVGd932UmrExWFxCAvRnDN3ez6ZujLmMvmLBaSWdfWVn75L83Qxu1qSX4fJNrJg2Gt/<0;1>/*";

    // (kind, lowercase-hex of correct byte length).
    const HASH_VECTORS: &[(&str, &str)] = &[
        ("sha256", "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"),
        ("hash256", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        ("ripemd160", "1234567890abcdef1234567890abcdef12345678"),
        ("hash160", "fedcba0987654321fedcba0987654321fedcba09"),
    ];

    #[test]
    fn hash_terminals_round_trip() {
        for &(kind, hex) in HASH_VECTORS {
            let s = format!("wsh(and_v(v:pk({TEST_XPUB}),{kind}({hex})))");
            let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&s).unwrap();
            let policy = WalletPolicy::from_str(&s).unwrap();
            assert_eq!(policy.into_descriptor().unwrap(), descriptor);
        }
    }

    #[test]
    fn mixed_hash_terminals_round_trip() {
        // All distinct pairs of hash kinds in one policy. Catches cross-type
        // dispatch errors, including byte-order quirks specific to hash256.
        for (i, &(a_kind, a_hex)) in HASH_VECTORS.iter().enumerate() {
            for &(b_kind, b_hex) in HASH_VECTORS.iter().skip(i + 1) {
                let s = format!(
                    "wsh(and_v(v:and_v(v:pk({TEST_XPUB}),{a_kind}({a_hex})),{b_kind}({b_hex})))"
                );
                let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&s).unwrap();
                let policy = WalletPolicy::from_str(&s).unwrap();
                assert_eq!(policy.into_descriptor().unwrap(), descriptor);
            }
        }
    }

    // A key information item is a bare KEY expression, so anything carrying its
    // own derivation, or not an extended key at all, fails to convert rather
    // than silently overriding the template.
    #[test]
    fn key_info_rejects_non_bare_keys() {
        for suffix in ["/<0;1>/*", "/0/*", "/44'/0'", "/<0;1>"] {
            let s = format!("{XPUB}{suffix}");
            let pk: DescriptorPublicKey = s.parse().unwrap();
            assert!(
                matches!(
                    KeyInfo::try_from(pk),
                    Err(WalletPolicyError::KeyInfoUnexpectedDerivation(_))
                ),
                "accepted key info with a derivation: {suffix}"
            );
            assert!(KeyInfo::from_str(&s).is_err(), "{suffix}");
        }

        let single: DescriptorPublicKey =
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
                .parse()
                .unwrap();
        assert_eq!(KeyInfo::try_from(single), Err(WalletPolicyError::KeyInfoNotExtendedKey));
    }

    // `Display` emits the BIP-388 serialization, so it round trips via `FromStr`
    // and matches what the key prints as inside a descriptor.
    #[test]
    fn key_info_round_trips_through_string() {
        for s in [XPUB, "[6738736c/48'/0'/0'/2']xpub6FC1fXFP1GXLX5TKtcjHGT4q89SDRehkQLtbKJ2PzWcvbBHtyDsJPLtpLtkGqYNYZdVVAjRQ5kug9CsapegmmeRutpP7PW4u4wVF9JfkDhw"] {
            let key = KeyInfo::from_str(s).unwrap();
            assert_eq!(key.to_string(), s);
            assert_eq!(DescriptorPublicKey::from(key.clone()).to_string(), s);
            assert_eq!(KeyInfo::from_str(&key.to_string()).unwrap(), key);
        }
    }

    #[test]
    fn set_key_info_rejects_duplicate_keys() {
        // The same key cannot fill two placeholders: `wsh(multi(2,K,K))` is a
        // 2-of-2 that one keyholder can satisfy alone.
        let key = KeyInfo::from_str(XPUB).unwrap();
        let mut two_keys = WalletPolicy::from_str("wsh(multi(2,@0/**,@1/**))").unwrap();
        assert!(matches!(
            two_keys.set_key_info(vec![key.clone(), key.clone()]),
            Err(WalletPolicyError::KeyInfoDuplicateKey(_))
        ));

        // A differing chain code does not make it a second key: the public keys
        // still collide, which is what BIP-388 requires to be pairwise distinct.
        let other = KeyInfo::from_str("[b2b1f0cf/48'/0'/0'/2']xpub6EWhjpPa6FqrcaPBuGBZRJVjzGJ1ZsMygRF26RwN932Vfkn1gyCiTbECVitBjRCkexEvetLdiqzTcYimmzYxyR1BZ79KNevgt61PDcukmC7").unwrap();
        let mutant = KeyInfo {
            origin: None,
            xkey: bip32::Xpub { chain_code: other.xkey.chain_code, ..key.xkey },
        };
        assert!(matches!(
            two_keys.set_key_info(vec![key, mutant]),
            Err(WalletPolicyError::KeyInfoDuplicateKey(_))
        ));
    }

    // The public parser validates hex length up-front, so invalid hex
    // never reaches the translator through `from_str`. This drives the
    // translator directly to pin the defensive `TranslatorInvalidHashHex`
    // variant.
    #[test]
    fn translator_invalid_hash_hex_errors() {
        let mut t = WalletPolicyTranslator { key_info: Vec::new() };
        let bad = String::from("not_hex");

        macro_rules! assert_bad {
            ($method:ident, $kind:literal) => {{
                let err = Translator::<KeyExpression>::$method(&mut t, &bad).unwrap_err();
                assert!(matches!(err, WalletPolicyError::TranslatorInvalidHashHex($kind, _)));
            }};
        }
        assert_bad!(sha256, "sha256");
        assert_bad!(hash256, "hash256");
        assert_bad!(ripemd160, "ripemd160");
        assert_bad!(hash160, "hash160");
    }

    #[test]
    fn can_set_key_info() {
        let mut template_only =
            WalletPolicy::from_str("wsh(sortedmulti(2,@0/**,@1/**))").expect("invalid template");
        assert!(template_only.clone().into_descriptor().is_err());
        let keys = ["[6738736c/48'/0'/0'/2']xpub6FC1fXFP1GXLX5TKtcjHGT4q89SDRehkQLtbKJ2PzWcvbBHtyDsJPLtpLtkGqYNYZdVVAjRQ5kug9CsapegmmeRutpP7PW4u4wVF9JfkDhw", "[b2b1f0cf/48'/0'/0'/2']xpub6EWhjpPa6FqrcaPBuGBZRJVjzGJ1ZsMygRF26RwN932Vfkn1gyCiTbECVitBjRCkexEvetLdiqzTcYimmzYxyR1BZ79KNevgt61PDcukmC7"]
            .into_iter()
            .map(KeyInfo::from_str)
            .collect::<Result<Vec<KeyInfo>, _>>()
            .unwrap();
        template_only.set_key_info(keys).unwrap();
        assert_eq!(
            format!("{:#}", template_only.into_descriptor().unwrap()),
            "wsh(sortedmulti(2,[6738736c/48'/0'/0'/2']xpub6FC1fXFP1GXLX5TKtcjHGT4q89SDRehkQLtbKJ2PzWcvbBHtyDsJPLtpLtkGqYNYZdVVAjRQ5kug9CsapegmmeRutpP7PW4u4wVF9JfkDhw/<0;1>/*,[b2b1f0cf/48'/0'/0'/2']xpub6EWhjpPa6FqrcaPBuGBZRJVjzGJ1ZsMygRF26RwN932Vfkn1gyCiTbECVitBjRCkexEvetLdiqzTcYimmzYxyR1BZ79KNevgt61PDcukmC7/<0;1>/*))"
        );
    }

    // Regression test for a bug where set_key_info() counted key-expression
    // occurrences instead of unique placeholder indices. A template reusing @0
    // with disjoint paths (e.g. @0/**,@0/<2;3>/*) has 2 occurrences but only 1
    // unique placeholder. The old code accepted 2 keys, silently dropping the
    // second one during descriptor translation since both @0 resolve to
    // key_info[0].
    // Reported by jm@squareup.com
    #[test]
    fn set_key_info_rejects_extra_keys_for_repeated_placeholder() {
        let mut policy = WalletPolicy::from_str("wsh(sortedmulti(2,@0/**,@0/<2;3>/*))").unwrap();
        let attacker_key = KeyInfo::from_str("[6738736c/48'/0'/0'/2']xpub6FC1fXFP1GXLX5TKtcjHGT4q89SDRehkQLtbKJ2PzWcvbBHtyDsJPLtpLtkGqYNYZdVVAjRQ5kug9CsapegmmeRutpP7PW4u4wVF9JfkDhw").unwrap();
        let victim_key = KeyInfo::from_str("[b2b1f0cf/48'/0'/0'/2']xpub6EWhjpPa6FqrcaPBuGBZRJVjzGJ1ZsMygRF26RwN932Vfkn1gyCiTbECVitBjRCkexEvetLdiqzTcYimmzYxyR1BZ79KNevgt61PDcukmC7").unwrap();

        // Must reject: 2 keys provided but only 1 unique placeholder (@0)
        assert_eq!(
            policy.set_key_info(vec![attacker_key.clone(), victim_key]),
            Err(WalletPolicyError::WalletPolicyInvalidKeyInfo),
        );

        // Must accept: 1 key for 1 unique placeholder, filling both @0
        // occurrences with the derivation each placeholder carries.
        policy.set_key_info(vec![attacker_key]).unwrap();
        assert_eq!(
            format!("{:#}", policy.into_descriptor().unwrap()),
            "wsh(sortedmulti(2,[6738736c/48'/0'/0'/2']xpub6FC1fXFP1GXLX5TKtcjHGT4q89SDRehkQLtbKJ2PzWcvbBHtyDsJPLtpLtkGqYNYZdVVAjRQ5kug9CsapegmmeRutpP7PW4u4wVF9JfkDhw/<0;1>/*,[6738736c/48'/0'/0'/2']xpub6FC1fXFP1GXLX5TKtcjHGT4q89SDRehkQLtbKJ2PzWcvbBHtyDsJPLtpLtkGqYNYZdVVAjRQ5kug9CsapegmmeRutpP7PW4u4wVF9JfkDhw/<2;3>/*))"
        );
    }
}
