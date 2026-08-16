// SPDX-License-Identifier: CC0-1.0

use core::fmt::{self, Display};
use core::str::FromStr;

use bitcoin::bip32;

use super::WalletPolicyError;
use crate::descriptor::key::maybe_fmt_master_id;
use crate::descriptor::{DescriptorKeyParseError, DescriptorXKey, Wildcard};
use crate::{DescriptorPublicKey, ToString};

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
        match &pk {
            DescriptorPublicKey::XPub(xpub)
                if xpub.derivation_path.is_empty() && xpub.wildcard == Wildcard::None =>
            {
                to_key_info(&pk)
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
            derivation_path: bip32::DerivationPath::master(),
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

/// Reduces a descriptor key to its key information item form. Unlike the public
/// `TryFrom`, drops any derivation: the template captures it instead.
pub(super) fn to_key_info(pk: &DescriptorPublicKey) -> Result<KeyInfo, WalletPolicyError> {
    let (origin, xkey) = match pk {
        DescriptorPublicKey::XPub(xpub) => (xpub.origin.clone(), xpub.xkey),
        DescriptorPublicKey::MultiXPub(xpub) => (xpub.origin.clone(), xpub.xkey),
        DescriptorPublicKey::Single(_) => return Err(WalletPolicyError::KeyInfoNotExtendedKey),
    };
    Ok(KeyInfo { origin, xkey })
}
