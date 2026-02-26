// SPDX-License-Identifier: CC0-1.0

use core::fmt::{self, Display};
use core::str::FromStr;

use super::key::XKeyParseError;
use super::{DerivPaths, DescriptorKeyParseError, Wildcard};
use crate::{Descriptor, DescriptorPublicKey, String, Translator, Vec};

mod key_expression;

use key_expression::{KeyExpression, KeyIndex};

/// A wallet policy as described in BIP-388
///
///```rust
/// use std::str::FromStr;
/// use miniscript::{Descriptor, DescriptorPublicKey};
/// use miniscript::descriptor::WalletPolicy;
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
/// let from_template = WalletPolicy::from_str("pkh(@0/**)").unwrap();
/// assert_eq!(from_template.to_string(), "pkh(@0/**)");
///
/// // Cannot go back into descriptor if you created from template:
/// assert!(from_template.into_descriptor().is_err());
///
/// // Convert into a full descriptor:
/// assert_eq!(policy1.into_descriptor().unwrap(), descriptor);
///```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletPolicy {
    /// Wallet descriptor template
    template: Descriptor<KeyExpression>,
    /// Vector of key information items
    key_info: Vec<DescriptorPublicKey>,
}

struct WalletPolicyTranslator {
    key_info: Vec<DescriptorPublicKey>,
}

impl Translator<KeyExpression> for WalletPolicyTranslator {
    type TargetPk = DescriptorPublicKey;
    type Error = WalletPolicyError;

    fn pk(&mut self, pk: &KeyExpression) -> Result<Self::TargetPk, Self::Error> {
        let idx = pk.index.0 as usize;
        self.key_info
            .get(idx)
            .cloned()
            .ok_or(WalletPolicyError::KeyInfoInvalidKeyIndex(idx))
    }

    translate_hash_fail!(KeyExpression, DescriptorPublicKey, Self::Error);
}

impl Translator<DescriptorPublicKey> for WalletPolicyTranslator {
    type TargetPk = KeyExpression;
    type Error = WalletPolicyError;

    fn pk(&mut self, pk: &DescriptorPublicKey) -> Result<Self::TargetPk, Self::Error> {
        let ke = KeyExpression {
            // FIXME: use a BTreeSet here? maybe doesn't really matter
            index: KeyIndex(self.key_info.iter().position(|p| p == pk).unwrap() as u32),
            derivation_paths: DerivPaths::new(pk.derivation_paths())
                .ok_or(WalletPolicyError::TranslatorEmptyDerivationPaths)?,
            wildcard: pk
                .wildcard()
                .ok_or(WalletPolicyError::TranslatorMissingWildcard)?,
        };
        Ok(ke)
    }

    translate_hash_fail!(DescriptorPublicKey, KeyExpression, Self::Error);
}

impl WalletPolicy {
    /// Create a new `WalletPolicy` from a
    /// `Descriptor<DescriptorPublicKey>`. Does not validate the underlying
    /// template.
    pub fn from_descriptor_unchecked(
        descriptor: &Descriptor<DescriptorPublicKey>,
    ) -> Result<WalletPolicy, WalletPolicyError> {
        let mut translator = WalletPolicyTranslator { key_info: descriptor.iter_pk().collect() };
        Ok(WalletPolicy {
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
    ) -> Result<WalletPolicy, WalletPolicyError> {
        WalletPolicy::from_descriptor_unchecked(descriptor).and_then(WalletPolicy::validate)
    }

    /// Convert a `WalletPolicy` into a `Descriptor<DescriptorPublicKey>` using
    /// the underlying template and key information.
    pub fn into_descriptor(self) -> Result<Descriptor<DescriptorPublicKey>, WalletPolicyError> {
        self.template
            .translate_pk(&mut WalletPolicyTranslator { key_info: self.key_info })
            .map_err(|e| e.expect_translator_err("converting to full descriptor"))
    }

    /// Sets the key information so that `WalletPolicy::into_descriptor` can be
    /// called successfully. Errors when there are not enough keys for the template.
    pub fn set_key_info(&mut self, keys: &[DescriptorPublicKey]) -> Result<(), WalletPolicyError> {
        if keys.len() != self.template.iter_pk().count() {
            return Err(WalletPolicyError::WalletPolicyInvalidKeyInfo);
        }
        self.key_info = keys.to_vec();
        Ok(())
    }

    /// Validates the wallet policy template.
    #[must_use = "Wallet policy won't be considered valid until this is called"]
    fn validate(self) -> Result<WalletPolicy, WalletPolicyError> {
        // HACK: don't know how else to prevent the following invalid cases from
        // the test vectors while still using the current Descriptor parsing:
        // skipped or out of order placeholders, repeated placeholds,
        // non-disjoin multipath expressions
        let mut prev: Option<KeyExpression> = None;
        for key in self.template.iter_pk() {
            if let (Some(prev), curr) = (&prev, &key) {
                if prev.index.0 > curr.index.0 || prev.index.0 != curr.index.0.saturating_sub(1) {
                    return Err(WalletPolicyError::TemplateValidationKeyIndexOutOfOrder);
                } else if prev.index.0 == curr.index.0 && !prev.is_disjoint(curr) {
                    return Err(WalletPolicyError::TemplateValidationNonDisjointPaths);
                }
            }
            prev = Some(key);
        }
        Ok(self)
    }
}

impl Display for WalletPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{:#}", self.template) }
}

impl TryFrom<&Descriptor<DescriptorPublicKey>> for WalletPolicy {
    type Error = WalletPolicyError;

    fn try_from(desc: &Descriptor<DescriptorPublicKey>) -> Result<Self, Self::Error> {
        WalletPolicy::from_descriptor(desc)
    }
}

impl TryFrom<&str> for WalletPolicy {
    type Error = WalletPolicyError;

    fn try_from(desc: &str) -> Result<Self, Self::Error> {
        match Descriptor::<KeyExpression>::from_str(desc) {
            Ok(template) => Ok(WalletPolicy { template, key_info: vec![] }.validate()?),
            Err(err1) => match Descriptor::<DescriptorPublicKey>::from_str(desc) {
                Ok(desc) => Ok(WalletPolicy::from_descriptor(&desc)?),
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
    /// The derivation path for a KeyExpression is invalid
    KeyExpressionParseInvalidDerivPath,
    /// The KeyIndex is missing an '@' sign
    KeyIndexParseExpectedAtSign(char),
    /// The KeyIndex is not a valid unsigned integer
    KeyIndexParseInvalidIndex(String),
    /// The key info is not found for the given index
    KeyInfoInvalidKeyIndex(usize),
    /// The key indexes in the template are out of order
    TemplateValidationKeyIndexOutOfOrder,
    /// The key indexes in the template are the same but the paths are non-disjoint
    TemplateValidationNonDisjointPaths,
    /// There must be at least one derivation path for a xpub
    TranslatorEmptyDerivationPaths,
    /// Missing wildcard on xpub
    TranslatorMissingWildcard,
    /// Couldn't parse wallet policy from string
    WalletPolicyParseFromString(String),
    /// Couldn't set key info on WalletPolicy
    WalletPolicyInvalidKeyInfo,
}

impl From<WalletPolicyError> for DescriptorKeyParseError {
    fn from(err: WalletPolicyError) -> Self {
        DescriptorKeyParseError::XKeyParseError(XKeyParseError::Bip388(err))
    }
}

#[cfg(feature = "std")]
impl std::error::Error for WalletPolicyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

impl Display for WalletPolicyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WalletPolicyError::KeyExpressionParseMustHaveDerivPath => {
                write!(f, "Key expression placeholder must have a derivation path after it")
            }
            WalletPolicyError::KeyExpressionParseInvalidDerivPath => {
                write!(
                    f,
                    "Key expression placeholder must be of the format \"/**\" or \"/<NUM;NUM>/*\""
                )
            }
            WalletPolicyError::KeyIndexParseInvalidIndex(index_str) => {
                write!(f, "Couldn't parse index, got {index_str}")
            }
            WalletPolicyError::KeyIndexParseExpectedAtSign(ch) => {
                write!(f, "Expected KeyIndex '@' sign, got {ch}")
            }
            WalletPolicyError::KeyInfoInvalidKeyIndex(idx) => {
                write!(f, "Invalid index [{idx}] into key info for wallet policy")
            }
            WalletPolicyError::TemplateValidationKeyIndexOutOfOrder => {
                write!(f, "The template has indexes that are out of order")
            }
            WalletPolicyError::TemplateValidationNonDisjointPaths => {
                write!(f, "The template has identical indexes but the paths are non-disjoint")
            }
            WalletPolicyError::TranslatorEmptyDerivationPaths => {
                write!(f, "Expected derivation paths when translating into KeyExpression")
            }
            WalletPolicyError::TranslatorMissingWildcard => {
                write!(f, "Missing wildcard. Not an xpub?")
            }
            WalletPolicyError::WalletPolicyParseFromString(msg) => msg.fmt(f),
            WalletPolicyError::WalletPolicyInvalidKeyInfo => {
                write!(f, "Invalid key information for WalletPolicy template")
            }
        }
    }
}

impl From<WalletPolicyError> for XKeyParseError {
    fn from(err: WalletPolicyError) -> Self { XKeyParseError::Bip388(err) }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::Descriptor;

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
    // TODO: uncomment if BIP-390 is ever supported
    // (
    //     "tr(@0/**,{sortedmulti_a(1,@0/<2;3>/*,@1/**),or_b(pk(@2/**),s:pk(@3/**))})",
    //     "tr([6738736c/48'/0'/0'/100']xpub6FC1fXFP1GXQpyRFfSE1vzzySqs3Vg63bzimYLeqtNUYbzA87kMNTcuy9ubr7MmavGRjW2FRYHP4WGKjwutbf1ghgkUW9H7e3ceaPLRcVwa/<0;1>/*,{sortedmulti_a(1,[6738736c/48'/0'/0'/100']xpub6FC1fXFP1GXQpyRFfSE1vzzySqs3Vg63bzimYLeqtNUYbzA87kMNTcuy9ubr7MmavGRjW2FRYHP4WGKjwutbf1ghgkUW9H7e3ceaPLRcVwa/<2;3>/*,xpub6Fc2TRaCWNgfT49nRGG2G78d1dPnjhW66gEXi7oYZML7qEFN8e21b2DLDipTZZnfV6V7ivrMkvh4VbnHY2ChHTS9qM3XVLJiAgcfagYQk6K/<0;1>/*),or_b(pk(xpub6GxHB9kRdFfTqYka8tgtX9Gh3Td3A9XS8uakUGVcJ9NGZ1uLrGZrRVr67DjpMNCHprZmVmceFTY4X4wWfksy8nVwPiNvzJ5pjLxzPtpnfEM/<0;1>/*),s:pk(xpub6GjFUVVYewLj5no5uoNKCWuyWhQ1rKGvV8DgXBG9Uc6DvAKxt2dhrj1EZFrTNB5qxAoBkVW3wF8uCS3q1ri9fueAa6y7heFTcf27Q4gyeh6/<0;1>/*))})"
    // ),
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
            assert_eq!(policy.into_descriptor().unwrap(), descriptor);
        }
    }

    #[test]
    fn can_error_on_invalid_wallet_policy_templates() {
        for t in INVALID_TEMPLATES {
            assert!(WalletPolicy::from_str(t).is_err());
        }
    }

    #[test]
    fn can_set_key_info() {
        let mut template_only =
            WalletPolicy::from_str("wsh(sortedmulti(2,@0/**,@1/**))").expect("invalid template");
        assert!(template_only.clone().into_descriptor().is_err());
        let keys = ["[6738736c/48'/0'/0'/2']xpub6FC1fXFP1GXLX5TKtcjHGT4q89SDRehkQLtbKJ2PzWcvbBHtyDsJPLtpLtkGqYNYZdVVAjRQ5kug9CsapegmmeRutpP7PW4u4wVF9JfkDhw", "[b2b1f0cf/48'/0'/0'/2']xpub6EWhjpPa6FqrcaPBuGBZRJVjzGJ1ZsMygRF26RwN932Vfkn1gyCiTbECVitBjRCkexEvetLdiqzTcYimmzYxyR1BZ79KNevgt61PDcukmC7"]
            .into_iter()
            .map(FromStr::from_str)
            .collect::<Result<Vec<DescriptorPublicKey>, _>>()
            .unwrap();
        template_only.set_key_info(&keys).unwrap();
        assert!(template_only.clone().into_descriptor().is_ok());
    }
}
