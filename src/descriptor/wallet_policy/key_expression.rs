// SPDX-License-Identifier: CC0-1.0

use core::fmt::{self, Display, Write};
use core::str::FromStr;

use super::{DerivPaths, DescriptorKeyParseError, Wildcard};
use crate::descriptor::key::{fmt_derivation_paths, parse_xkey_deriv};
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
        let (index, derivation_paths, wildcard) =
            parse_xkey_deriv(&s.replace(RECEIVE_CHANGE_SHORTHAND, RECEIVE_CHANGE_PATH))?;
        let key = Self {
            index,
            derivation_paths: DerivPaths::new(derivation_paths)
                .ok_or(WalletPolicyError::KeyExpressionParseMustHaveDerivPath)?,
            wildcard,
        };
        super::check_placeholder_deriv(&key)?;
        Ok(key)
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
        write!(f, "{}", path.replace(RECEIVE_CHANGE_PATH, RECEIVE_CHANGE_SHORTHAND))
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

impl FromStr for KeyIndex {
    type Err = WalletPolicyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut chars = s.chars();
        match chars.next() {
            Some('@') => {
                let index_str = chars.take_while(char::is_ascii_digit).collect::<String>();
                let index = index_str
                    .parse()
                    .map_err(|_| WalletPolicyError::KeyIndexParseInvalidIndex(index_str))?;
                Ok(KeyIndex(index))
            }
            Some(ch) => Err(WalletPolicyError::KeyIndexParseExpectedAtSign(ch)),
            None => Err(WalletPolicyError::KeyIndexParseInvalidIndex(s.into())),
        }
    }
}

impl Display for KeyIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "@{}", self.0) }
}
