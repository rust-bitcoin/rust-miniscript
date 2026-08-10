// SPDX-License-Identifier: CC0-1.0

use core::fmt::{self, Display, Write};
use core::str::FromStr;

use bitcoin::bip32;

use super::{DerivPaths, DescriptorKeyParseError, Wildcard};
use crate::descriptor::key::fmt_derivation_paths;
use crate::descriptor::WalletPolicyError;
use crate::{MiniscriptKey, String};

const RECEIVE_CHANGE_SHORTHAND: &str = "**";
const RECEIVE_CHANGE_PATH: &str = "<0;1>/*";

/// A key expression type based off of the description of KEY and KP in BIP-388.
/// Used as a `Pk` in `Descriptor<Pk>`
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct KeyExpression {
    /// The numeric part of key index (KI)
    pub index: KeyIndex,
    /// The derivation paths of this key
    pub derivation_paths: DerivPaths,
    /// The wildcard value
    pub wildcard: Wildcard,
}

#[derive(Debug, Clone, Copy, Hash, PartialOrd, Ord, PartialEq, Eq)]
pub struct KeyIndex(pub u32);

impl TryFrom<&str> for KeyExpression {
    type Error = DescriptorKeyParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        // BIP-388 only admits `@N/**` and `@N/<NUM;NUM>/*`, so parse that
        // grammar directly rather than through the generic key parser, which
        // is laxer about NUM canonicality than the spec.
        let (index, deriv) = s
            .split_once('/')
            .ok_or(WalletPolicyError::KeyExpressionParseMustHaveDerivPath)?;
        let index = KeyIndex::from_str(index)?;
        let (receive, change) = if deriv == RECEIVE_CHANGE_SHORTHAND {
            (0, 1)
        } else {
            deriv
                .strip_prefix('<')
                .and_then(|d| d.strip_suffix(">/*"))
                .and_then(|nums| nums.split_once(';'))
                .and_then(|(a, b)| Some((parse_canonical_num(a)?, parse_canonical_num(b)?)))
                .filter(|(a, b)| a != b)
                .ok_or(WalletPolicyError::TemplateValidationInvalidPlaceholderDeriv)?
        };
        let path = |num| {
            bip32::ChildNumber::from_normal_idx(num)
                .map(|cn| bip32::DerivationPath::from(vec![cn]))
                .map_err(|_| WalletPolicyError::TemplateValidationInvalidPlaceholderDeriv)
        };
        Ok(Self {
            index,
            derivation_paths: DerivPaths::new(vec![path(receive)?, path(change)?])
                .expect("always two paths"),
            wildcard: Wildcard::Unhardened,
        })
    }
}

impl FromStr for KeyExpression {
    type Err = DescriptorKeyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> { s.try_into() }
}

impl Display for KeyExpression {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.index.fmt(f)?;
        let mut path = String::new();
        fmt_derivation_paths(&mut path, self.derivation_paths.paths())?;
        write!(&mut path, "{}", self.wildcard)?;
        // Only a whole `/<0;1>/*` derivation collapses to the `/**` shorthand.
        if path.strip_prefix('/') == Some(RECEIVE_CHANGE_PATH) {
            write!(f, "/{}", RECEIVE_CHANGE_SHORTHAND)
        } else {
            f.write_str(&path)
        }
    }
}

impl MiniscriptKey for KeyExpression {
    type Sha256 = String;
    type Hash256 = String;
    type Ripemd160 = String;
    type Hash160 = String;

    fn is_x_only_key(&self) -> bool { false }
    fn num_der_paths(&self) -> usize { self.derivation_paths.paths().len() }
}

/// Parses a decimal number the way BIP-388 writes NUM and key index digits:
/// decimal digits only, with no sign and no leading zeros (except 0 itself).
fn parse_canonical_num(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return None;
    }
    s.parse().ok()
}

impl FromStr for KeyIndex {
    type Err = WalletPolicyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut chars = s.chars();
        match chars.next() {
            Some('@') => parse_canonical_num(chars.as_str())
                .map(Self)
                .ok_or_else(|| WalletPolicyError::KeyIndexParseInvalidIndex(chars.as_str().into())),
            Some(ch) => Err(WalletPolicyError::KeyIndexParseExpectedAtSign(ch)),
            None => Err(WalletPolicyError::KeyIndexParseInvalidIndex(s.into())),
        }
    }
}

impl Display for KeyIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "@{}", self.0) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_index_rejects_non_canonical_indexes() {
        for s in ["@", "@00", "@01", "@0abc", "@1 ", "@-1", "@4294967296"] {
            assert!(KeyIndex::from_str(s).is_err(), "{s}");
        }
        assert_eq!(KeyIndex::from_str("@0").unwrap(), KeyIndex(0));
        assert_eq!(KeyIndex::from_str("@10").unwrap(), KeyIndex(10));
    }
}
