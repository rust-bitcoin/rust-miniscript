use core::fmt;
use core::str::FromStr;
#[cfg(feature = "std")]
use std::error;

use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::{hash160, ripemd160, sha256, Hash, HashEngine};
use bitcoin::secp256k1::{Secp256k1, Signing, Verification};
use bitcoin::util::bip32;
use bitcoin::{self, XOnlyPublicKey, XpubIdentifier};

use crate::prelude::*;
use crate::{hash256, MiniscriptKey, ToPublicKey};

/// The descriptor pubkey, either a single pubkey or an xpub.
#[derive(Debug, Eq, PartialEq, Clone, Ord, PartialOrd, Hash)]
pub enum DescriptorPublicKey {
    /// Single public key.
    Single(SinglePub),
    /// Extended public key (xpub).
    XPub(DescriptorXKey<bip32::ExtendedPubKey>),
}

/// The descriptor secret key, either a single private key or an xprv.
#[derive(Debug)]
pub enum DescriptorSecretKey {
    /// Single private key.
    Single(SinglePriv),
    /// Extended private key (xpriv).
    XPrv(DescriptorXKey<bip32::ExtendedPrivKey>),
}

/// A descriptor [`SinglePubKey`] with optional origin information.
#[derive(Debug, Eq, PartialEq, Clone, Ord, PartialOrd, Hash)]
pub struct SinglePub {
    /// Origin information (fingerprint and derivation path).
    pub origin: Option<(bip32::Fingerprint, bip32::DerivationPath)>,
    /// The public key.
    pub key: SinglePubKey,
}

/// A descriptor [`bitcoin::PrivateKey`] with optional origin information.
#[derive(Debug)]
pub struct SinglePriv {
    /// Origin information (fingerprint and derivation path).
    pub origin: Option<(bip32::Fingerprint, bip32::DerivationPath)>,
    /// The private key.
    pub key: bitcoin::PrivateKey,
}

/// An extended key with origin, derivation path, and wildcard.
#[derive(Debug, Eq, PartialEq, Clone, Ord, PartialOrd, Hash)]
pub struct DescriptorXKey<K: InnerXKey> {
    /// Origin information
    pub origin: Option<(bip32::Fingerprint, bip32::DerivationPath)>,
    /// The extended key
    pub xkey: K,
    /// The derivation path
    pub derivation_path: bip32::DerivationPath,
    /// Whether the descriptor is wildcard
    pub wildcard: Wildcard,
}

/// Single public key without any origin or range information.
#[derive(Debug, Eq, PartialEq, Clone, Ord, PartialOrd, Hash)]
pub enum SinglePubKey {
    /// A bitcoin public key (compressed or uncompressed).
    FullKey(bitcoin::PublicKey),
    /// An xonly public key.
    XOnly(XOnlyPublicKey),
}

/// A [`DescriptorPublicKey`] without any wildcards.
#[derive(Debug, Eq, PartialEq, Clone, Ord, PartialOrd, Hash)]
pub struct DefiniteDescriptorKey(DescriptorPublicKey);

impl fmt::Display for DescriptorSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DescriptorSecretKey::Single(ref sk) => {
                maybe_fmt_master_id(f, &sk.origin)?;
                sk.key.fmt(f)?;
                Ok(())
            }
            DescriptorSecretKey::XPrv(ref xprv) => {
                maybe_fmt_master_id(f, &xprv.origin)?;
                xprv.xkey.fmt(f)?;
                fmt_derivation_path(f, &xprv.derivation_path)?;
                match xprv.wildcard {
                    Wildcard::None => {}
                    Wildcard::Unhardened => write!(f, "/*")?,
                    Wildcard::Hardened => write!(f, "/*h")?,
                }
                Ok(())
            }
        }
    }
}

/// Trait for "extended key" types like `xpub` and `xprv`. Used internally to generalize parsing and
/// handling of `bip32::ExtendedPubKey` and `bip32::ExtendedPrivKey`.
pub trait InnerXKey: fmt::Display + FromStr {
    /// Returns the fingerprint of the key
    fn xkey_fingerprint<C: Signing>(&self, secp: &Secp256k1<C>) -> bip32::Fingerprint;

    /// Returns whether hardened steps can be derived on the key
    ///
    /// `true` for `bip32::ExtendedPrivKey` and `false` for `bip32::ExtendedPubKey`.
    fn can_derive_hardened() -> bool;
}

impl InnerXKey for bip32::ExtendedPubKey {
    fn xkey_fingerprint<C: Signing>(&self, _secp: &Secp256k1<C>) -> bip32::Fingerprint {
        self.fingerprint()
    }

    fn can_derive_hardened() -> bool {
        false
    }
}

impl InnerXKey for bip32::ExtendedPrivKey {
    fn xkey_fingerprint<C: Signing>(&self, secp: &Secp256k1<C>) -> bip32::Fingerprint {
        self.fingerprint(secp)
    }

    fn can_derive_hardened() -> bool {
        true
    }
}

/// Whether a descriptor has a wildcard in it
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Wildcard {
    /// No wildcard
    None,
    /// Unhardened wildcard, e.g. *
    Unhardened,
    /// Unhardened wildcard, e.g. *h
    Hardened,
}

impl SinglePriv {
    /// Returns the public key of this key.
    fn to_public<C: Signing>(&self, secp: &Secp256k1<C>) -> SinglePub {
        let pub_key = self.key.public_key(secp);

        SinglePub {
            origin: self.origin.clone(),
            key: SinglePubKey::FullKey(pub_key),
        }
    }
}

impl DescriptorXKey<bip32::ExtendedPrivKey> {
    /// Returns the public version of this key, applying all the hardened derivation steps on the
    /// private key before turning it into a public key.
    ///
    /// If the key already has an origin, the derivation steps applied will be appended to the path
    /// already present, otherwise this key will be treated as a master key and an origin will be
    /// added with this key's fingerprint and the derivation steps applied.
    fn to_public<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
    ) -> Result<DescriptorXKey<bip32::ExtendedPubKey>, DescriptorKeyParseError> {
        let unhardened = self
            .derivation_path
            .into_iter()
            .rev()
            .take_while(|c| c.is_normal())
            .count();
        let last_hardened_idx = self.derivation_path.len() - unhardened;

        let hardened_path = &self.derivation_path[..last_hardened_idx];
        let unhardened_path = &self.derivation_path[last_hardened_idx..];

        let xprv = self
            .xkey
            .derive_priv(secp, &hardened_path)
            .map_err(|_| DescriptorKeyParseError("Unable to derive the hardened steps"))?;
        let xpub = bip32::ExtendedPubKey::from_priv(secp, &xprv);

        let origin = match &self.origin {
            Some((fingerprint, path)) => Some((
                *fingerprint,
                path.into_iter()
                    .chain(hardened_path.iter())
                    .cloned()
                    .collect(),
            )),
            None => {
                if hardened_path.is_empty() {
                    None
                } else {
                    Some((self.xkey.fingerprint(secp), hardened_path.into()))
                }
            }
        };

        Ok(DescriptorXKey {
            origin,
            xkey: xpub,
            derivation_path: unhardened_path.into(),
            wildcard: self.wildcard,
        })
    }
}

/// Descriptor Key parsing errors
// FIXME: replace with error enums
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct DescriptorKeyParseError(&'static str);

impl fmt::Display for DescriptorKeyParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.0)
    }
}

#[cfg(feature = "std")]
impl error::Error for DescriptorKeyParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl fmt::Display for DescriptorPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DescriptorPublicKey::Single(ref pk) => {
                maybe_fmt_master_id(f, &pk.origin)?;
                match pk.key {
                    SinglePubKey::FullKey(full_key) => full_key.fmt(f),
                    SinglePubKey::XOnly(x_only_key) => x_only_key.fmt(f),
                }?;
                Ok(())
            }
            DescriptorPublicKey::XPub(ref xpub) => {
                maybe_fmt_master_id(f, &xpub.origin)?;
                xpub.xkey.fmt(f)?;
                fmt_derivation_path(f, &xpub.derivation_path)?;
                match xpub.wildcard {
                    Wildcard::None => {}
                    Wildcard::Unhardened => write!(f, "/*")?,
                    Wildcard::Hardened => write!(f, "/*h")?,
                }
                Ok(())
            }
        }
    }
}

impl DescriptorSecretKey {
    /// Returns the public version of this key.
    ///
    /// If the key is an "XPrv", the hardened derivation steps will be applied
    /// before converting it to a public key.
    pub fn to_public<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
    ) -> Result<DescriptorPublicKey, DescriptorKeyParseError> {
        let pk = match self {
            DescriptorSecretKey::Single(prv) => DescriptorPublicKey::Single(prv.to_public(secp)),
            DescriptorSecretKey::XPrv(xprv) => DescriptorPublicKey::XPub(xprv.to_public(secp)?),
        };

        Ok(pk)
    }
}

/// Writes the fingerprint of the origin, if there is one.
fn maybe_fmt_master_id(
    f: &mut fmt::Formatter,
    origin: &Option<(bip32::Fingerprint, bip32::DerivationPath)>,
) -> fmt::Result {
    if let Some((ref master_id, ref master_deriv)) = *origin {
        fmt::Formatter::write_str(f, "[")?;
        for byte in master_id.into_bytes().iter() {
            write!(f, "{:02x}", byte)?;
        }
        fmt_derivation_path(f, master_deriv)?;
        fmt::Formatter::write_str(f, "]")?;
    }

    Ok(())
}

/// Writes a derivation path to the formatter, no leading 'm'
fn fmt_derivation_path(f: &mut fmt::Formatter, path: &bip32::DerivationPath) -> fmt::Result {
    for child in path {
        write!(f, "/{}", child)?;
    }
    Ok(())
}

impl FromStr for DescriptorPublicKey {
    type Err = DescriptorKeyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // A "raw" public key without any origin is the least we accept.
        if s.len() < 64 {
            return Err(DescriptorKeyParseError(
                "Key too short (<66 char), doesn't match any format",
            ));
        }

        let (key_part, origin) = DescriptorXKey::<bip32::ExtendedPubKey>::parse_xkey_origin(s)?;

        if key_part.contains("pub") {
            let (xpub, derivation_path, wildcard) =
                DescriptorXKey::<bip32::ExtendedPubKey>::parse_xkey_deriv(key_part)?;

            Ok(DescriptorPublicKey::XPub(DescriptorXKey {
                origin,
                xkey: xpub,
                derivation_path,
                wildcard,
            }))
        } else {
            let key = match key_part.len() {
                64 => {
                    let x_only_key = XOnlyPublicKey::from_str(key_part).map_err(|_| {
                        DescriptorKeyParseError("Error while parsing simple xonly key")
                    })?;
                    SinglePubKey::XOnly(x_only_key)
                }
                66 | 130 => {
                    if !(&key_part[0..2] == "02"
                        || &key_part[0..2] == "03"
                        || &key_part[0..2] == "04")
                    {
                        return Err(DescriptorKeyParseError(
                            "Only publickeys with prefixes 02/03/04 are allowed",
                        ));
                    }
                    let key = bitcoin::PublicKey::from_str(key_part).map_err(|_| {
                        DescriptorKeyParseError("Error while parsing simple public key")
                    })?;
                    SinglePubKey::FullKey(key)
                }
                _ => {
                    return Err(DescriptorKeyParseError(
                        "Public keys must be 64/66/130 characters in size",
                    ))
                }
            };
            Ok(DescriptorPublicKey::Single(SinglePub { key, origin }))
        }
    }
}

/// Descriptor key conversion error
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum ConversionError {
    /// Attempted to convert a key with hardened derivations to a bitcoin public key
    HardenedChild,
}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            ConversionError::HardenedChild => "hardened child step in bip32 path",
        })
    }
}

#[cfg(feature = "std")]
impl error::Error for ConversionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::ConversionError::*;

        match self {
            HardenedChild => None,
        }
    }
}

impl DescriptorPublicKey {
    /// The fingerprint of the master key associated with this key, `0x00000000` if none.
    pub fn master_fingerprint(&self) -> bip32::Fingerprint {
        match *self {
            DescriptorPublicKey::XPub(ref xpub) => {
                if let Some((fingerprint, _)) = xpub.origin {
                    fingerprint
                } else {
                    xpub.xkey.fingerprint()
                }
            }
            DescriptorPublicKey::Single(ref single) => {
                if let Some((fingerprint, _)) = single.origin {
                    fingerprint
                } else {
                    let mut engine = XpubIdentifier::engine();
                    match single.key {
                        SinglePubKey::FullKey(pk) => {
                            pk.write_into(&mut engine).expect("engines don't error")
                        }
                        SinglePubKey::XOnly(x_only_pk) => engine.input(&x_only_pk.serialize()),
                    };
                    bip32::Fingerprint::from(&XpubIdentifier::from_engine(engine)[..4])
                }
            }
        }
    }

    /// Full path, from the master key
    ///
    /// For wildcard keys this will return the path up to the wildcard, so you
    /// can get full paths by appending one additional derivation step, according
    /// to the wildcard type (hardened or normal)
    pub fn full_derivation_path(&self) -> bip32::DerivationPath {
        match *self {
            DescriptorPublicKey::XPub(ref xpub) => {
                let origin_path = if let Some((_, ref path)) = xpub.origin {
                    path.clone()
                } else {
                    bip32::DerivationPath::from(vec![])
                };
                origin_path.extend(&xpub.derivation_path)
            }
            DescriptorPublicKey::Single(ref single) => {
                if let Some((_, ref path)) = single.origin {
                    path.clone()
                } else {
                    bip32::DerivationPath::from(vec![])
                }
            }
        }
    }

    /// Whether or not the key has a wildcard
    #[deprecated(note = "use has_wildcard instead")]
    pub fn is_deriveable(&self) -> bool {
        self.has_wildcard()
    }

    /// Whether or not the key has a wildcard
    pub fn has_wildcard(&self) -> bool {
        match *self {
            DescriptorPublicKey::Single(..) => false,
            DescriptorPublicKey::XPub(ref xpub) => xpub.wildcard != Wildcard::None,
        }
    }

    #[deprecated(note = "use at_derivation_index instead")]
    /// Deprecated name of [`at_derivation_index`].
    pub fn derive(self, index: u32) -> DefiniteDescriptorKey {
        self.at_derivation_index(index)
    }

    /// Replaces any wildcard (i.e. `/*`) in the key with a particular derivation index, turning it into a
    /// *definite* key (i.e. one where all the derivation paths are set).
    ///
    /// # Returns
    ///
    /// - If this key is not an xpub, returns `self`.
    /// - If this key is an xpub but does not have a wildcard, returns `self`.
    /// - Otherwise, returns the xpub at derivation `index` (removing the wildcard).
    ///
    /// # Panics
    ///
    /// If `index` ≥ 2^31
    pub fn at_derivation_index(self, index: u32) -> DefiniteDescriptorKey {
        let definite = match self {
            DescriptorPublicKey::Single(_) => self,
            DescriptorPublicKey::XPub(xpub) => {
                let derivation_path = match xpub.wildcard {
                    Wildcard::None => xpub.derivation_path,
                    Wildcard::Unhardened => xpub.derivation_path.into_child(
                        bip32::ChildNumber::from_normal_idx(index).expect("index must < 2^31"),
                    ),
                    Wildcard::Hardened => xpub.derivation_path.into_child(
                        bip32::ChildNumber::from_hardened_idx(index).expect("index must < 2^31"),
                    ),
                };
                DescriptorPublicKey::XPub(DescriptorXKey {
                    origin: xpub.origin,
                    xkey: xpub.xkey,
                    derivation_path,
                    wildcard: Wildcard::None,
                })
            }
        };

        DefiniteDescriptorKey::new(definite)
            .expect("The key should not contain any wildcards at this point")
    }
}

impl FromStr for DescriptorSecretKey {
    type Err = DescriptorKeyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (key_part, origin) = DescriptorXKey::<bip32::ExtendedPubKey>::parse_xkey_origin(s)?;

        if key_part.len() <= 52 {
            let sk = bitcoin::PrivateKey::from_str(key_part)
                .map_err(|_| DescriptorKeyParseError("Error while parsing a WIF private key"))?;
            Ok(DescriptorSecretKey::Single(SinglePriv {
                key: sk,
                origin: None,
            }))
        } else {
            let (xprv, derivation_path, wildcard) =
                DescriptorXKey::<bip32::ExtendedPrivKey>::parse_xkey_deriv(key_part)?;
            Ok(DescriptorSecretKey::XPrv(DescriptorXKey {
                origin,
                xkey: xprv,
                derivation_path,
                wildcard,
            }))
        }
    }
}

impl<K: InnerXKey> DescriptorXKey<K> {
    fn parse_xkey_origin(
        s: &str,
    ) -> Result<(&str, Option<bip32::KeySource>), DescriptorKeyParseError> {
        for ch in s.as_bytes() {
            if *ch < 20 || *ch > 127 {
                return Err(DescriptorKeyParseError(
                    "Encountered an unprintable character",
                ));
            }
        }

        if s.is_empty() {
            return Err(DescriptorKeyParseError("Empty key"));
        }
        let mut parts = s[1..].split(']');

        if let Some('[') = s.chars().next() {
            let mut raw_origin = parts
                .next()
                .ok_or(DescriptorKeyParseError("Unclosed '['"))?
                .split('/');

            let origin_id_hex = raw_origin.next().ok_or(DescriptorKeyParseError(
                "No master fingerprint found after '['",
            ))?;

            if origin_id_hex.len() != 8 {
                return Err(DescriptorKeyParseError(
                    "Master fingerprint should be 8 characters long",
                ));
            }
            let parent_fingerprint = bip32::Fingerprint::from_hex(origin_id_hex).map_err(|_| {
                DescriptorKeyParseError("Malformed master fingerprint, expected 8 hex chars")
            })?;
            let origin_path = raw_origin
                .map(bip32::ChildNumber::from_str)
                .collect::<Result<bip32::DerivationPath, bip32::Error>>()
                .map_err(|_| {
                    DescriptorKeyParseError("Error while parsing master derivation path")
                })?;

            let key = parts
                .next()
                .ok_or(DescriptorKeyParseError("No key after origin."))?;

            if parts.next().is_some() {
                Err(DescriptorKeyParseError(
                    "Multiple ']' in Descriptor Public Key",
                ))
            } else {
                Ok((key, Some((parent_fingerprint, origin_path))))
            }
        } else {
            Ok((s, None))
        }
    }

    /// Parse an extended key concatenated to a derivation path.
    fn parse_xkey_deriv(
        key_deriv: &str,
    ) -> Result<(K, bip32::DerivationPath, Wildcard), DescriptorKeyParseError> {
        let mut key_deriv = key_deriv.split('/');
        let xkey_str = key_deriv.next().ok_or(DescriptorKeyParseError(
            "No key found after origin description",
        ))?;
        let xkey = K::from_str(xkey_str)
            .map_err(|_| DescriptorKeyParseError("Error while parsing xkey."))?;

        let mut wildcard = Wildcard::None;
        let derivation_path = key_deriv
            .filter_map(|p| {
                if wildcard == Wildcard::None && p == "*" {
                    wildcard = Wildcard::Unhardened;
                    None
                } else if wildcard == Wildcard::None && (p == "*'" || p == "*h") {
                    wildcard = Wildcard::Hardened;
                    None
                } else if wildcard != Wildcard::None {
                    Some(Err(DescriptorKeyParseError(
                        "'*' may only appear as last element in a derivation path.",
                    )))
                } else {
                    Some(bip32::ChildNumber::from_str(p).map_err(|_| {
                        DescriptorKeyParseError("Error while parsing key derivation path")
                    }))
                }
            })
            .collect::<Result<bip32::DerivationPath, _>>()?;

        Ok((xkey, derivation_path, wildcard))
    }

    /// Compares this key with a `keysource` and returns the matching derivation path, if any.
    ///
    /// For keys that have an origin, the `keysource`'s fingerprint will be compared
    /// with the origin's fingerprint, and the `keysource`'s path will be compared with the concatenation of the
    /// origin's and key's paths.
    ///
    /// If the key `wildcard`, the last item of the `keysource`'s path will be ignored,
    ///
    /// ## Examples
    ///
    /// ```
    /// # use std::str::FromStr;
    /// # fn body() -> Result<(), ()> {
    /// use miniscript::bitcoin::util::bip32;
    /// use miniscript::descriptor::DescriptorPublicKey;
    ///
    /// let ctx = miniscript::bitcoin::secp256k1::Secp256k1::signing_only();
    ///
    /// let key = DescriptorPublicKey::from_str("[d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*").or(Err(()))?;
    /// let xpub = match key {
    ///     DescriptorPublicKey::XPub(xpub) => xpub,
    ///     _ => panic!("Parsing Error"),
    /// };
    ///
    /// assert_eq!(
    ///     xpub.matches(&(
    ///         bip32::Fingerprint::from_str("d34db33f").or(Err(()))?,
    ///         bip32::DerivationPath::from_str("m/44'/0'/0'/1/42").or(Err(()))?
    ///     ), &ctx),
    ///     Some(bip32::DerivationPath::from_str("m/44'/0'/0'/1").or(Err(()))?)
    /// );
    /// assert_eq!(
    ///     xpub.matches(&(
    ///         bip32::Fingerprint::from_str("ffffffff").or(Err(()))?,
    ///         bip32::DerivationPath::from_str("m/44'/0'/0'/1/42").or(Err(()))?
    ///     ), &ctx),
    ///     None
    /// );
    /// assert_eq!(
    ///     xpub.matches(&(
    ///         bip32::Fingerprint::from_str("d34db33f").or(Err(()))?,
    ///         bip32::DerivationPath::from_str("m/44'/0'/0'/100/0").or(Err(()))?
    ///     ), &ctx),
    ///     None
    /// );
    /// # Ok(())
    /// # }
    /// # body().unwrap()
    /// ```
    pub fn matches<C: Signing>(
        &self,
        keysource: &bip32::KeySource,
        secp: &Secp256k1<C>,
    ) -> Option<bip32::DerivationPath> {
        let (fingerprint, path) = keysource;

        let (compare_fingerprint, compare_path) = match self.origin {
            Some((fingerprint, ref path)) => (
                fingerprint,
                path.into_iter()
                    .chain(self.derivation_path.into_iter())
                    .collect(),
            ),
            None => (
                self.xkey.xkey_fingerprint(secp),
                self.derivation_path.into_iter().collect::<Vec<_>>(),
            ),
        };

        let path_excluding_wildcard = if self.wildcard != Wildcard::None && !path.is_empty() {
            path.into_iter()
                .take(path.as_ref().len() - 1)
                .cloned()
                .collect()
        } else {
            path.clone()
        };

        if &compare_fingerprint == fingerprint
            && compare_path
                .into_iter()
                .eq(path_excluding_wildcard.into_iter())
        {
            Some(path_excluding_wildcard)
        } else {
            None
        }
    }
}

impl MiniscriptKey for DescriptorPublicKey {
    type Sha256 = sha256::Hash;
    type Hash256 = hash256::Hash;
    type Ripemd160 = ripemd160::Hash;
    type Hash160 = hash160::Hash;

    fn is_uncompressed(&self) -> bool {
        match self {
            DescriptorPublicKey::Single(SinglePub {
                key: SinglePubKey::FullKey(ref key),
                ..
            }) => key.is_uncompressed(),
            _ => false,
        }
    }

    fn is_x_only_key(&self) -> bool {
        match self {
            DescriptorPublicKey::Single(SinglePub {
                key: SinglePubKey::XOnly(ref _key),
                ..
            }) => true,
            _ => false,
        }
    }
}

impl DefiniteDescriptorKey {
    /// Computes the public key corresponding to this descriptor key.
    /// When deriving from an XOnlyPublicKey, it adds the default 0x02 y-coordinate
    /// and returns the obtained full [`bitcoin::PublicKey`]. All BIP32 derivations
    /// always return a compressed key
    ///
    /// Will return an error if the descriptor key has any hardened derivation steps in its path. To
    /// avoid this error you should replace any such public keys first with [`translate_pk`].
    ///
    /// [`translate_pk`]: crate::TranslatePk::translate_pk
    pub fn derive_public_key<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
    ) -> Result<bitcoin::PublicKey, ConversionError> {
        match self.0 {
            DescriptorPublicKey::Single(ref pk) => match pk.key {
                SinglePubKey::FullKey(pk) => Ok(pk),
                SinglePubKey::XOnly(xpk) => Ok(xpk.to_public_key()),
            },
            DescriptorPublicKey::XPub(ref xpk) => match xpk.wildcard {
                Wildcard::Unhardened | Wildcard::Hardened => {
                    unreachable!("we've excluded this error case")
                }
                Wildcard::None => match xpk.xkey.derive_pub(secp, &xpk.derivation_path.as_ref()) {
                    Ok(xpub) => Ok(bitcoin::PublicKey::new(xpub.public_key)),
                    Err(bip32::Error::CannotDeriveFromHardenedKey) => {
                        Err(ConversionError::HardenedChild)
                    }
                    Err(e) => unreachable!("cryptographically unreachable: {}", e),
                },
            },
        }
    }

    /// Construct an instance from a descriptor key and a derivation index
    ///
    /// Returns `None` if the key contains a wildcard
    fn new(key: DescriptorPublicKey) -> Option<Self> {
        if key.has_wildcard() {
            None
        } else {
            Some(Self(key))
        }
    }

    /// The fingerprint of the master key associated with this key, `0x00000000` if none.
    pub fn master_fingerprint(&self) -> bip32::Fingerprint {
        self.0.master_fingerprint()
    }

    /// Full path, from the master key
    pub fn full_derivation_path(&self) -> bip32::DerivationPath {
        self.0.full_derivation_path()
    }
}

impl FromStr for DefiniteDescriptorKey {
    type Err = DescriptorKeyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let inner = DescriptorPublicKey::from_str(s)?;
        Ok(
            DefiniteDescriptorKey::new(inner).ok_or(DescriptorKeyParseError(
                "cannot parse key with a wilcard as a DerivedDescriptorKey",
            ))?,
        )
    }
}

impl fmt::Display for DefiniteDescriptorKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl MiniscriptKey for DefiniteDescriptorKey {
    type Sha256 = sha256::Hash;
    type Hash256 = hash256::Hash;
    type Ripemd160 = ripemd160::Hash;
    type Hash160 = hash160::Hash;

    fn is_uncompressed(&self) -> bool {
        self.0.is_uncompressed()
    }

    fn is_x_only_key(&self) -> bool {
        self.0.is_x_only_key()
    }
}

impl ToPublicKey for DefiniteDescriptorKey {
    fn to_public_key(&self) -> bitcoin::PublicKey {
        let secp = Secp256k1::verification_only();
        self.derive_public_key(&secp).unwrap()
    }

    fn to_sha256(hash: &sha256::Hash) -> sha256::Hash {
        *hash
    }

    fn to_hash256(hash: &hash256::Hash) -> hash256::Hash {
        *hash
    }

    fn to_ripemd160(hash: &ripemd160::Hash) -> ripemd160::Hash {
        *hash
    }

    fn to_hash160(hash: &hash160::Hash) -> hash160::Hash {
        *hash
    }
}

impl From<DefiniteDescriptorKey> for DescriptorPublicKey {
    fn from(d: DefiniteDescriptorKey) -> Self {
        d.0
    }
}

#[cfg(test)]
mod test {
    use core::str::FromStr;

    use bitcoin::secp256k1;

    use super::{DescriptorKeyParseError, DescriptorPublicKey, DescriptorSecretKey};
    use crate::prelude::*;

    #[test]
    fn parse_descriptor_key_errors() {
        // And ones with misplaced wildcard
        let desc = "[78412e3a/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*/44";
        assert_eq!(
            DescriptorPublicKey::from_str(desc),
            Err(DescriptorKeyParseError(
                "\'*\' may only appear as last element in a derivation path."
            ))
        );

        // And ones with invalid fingerprints
        let desc = "[NonHexor]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*";
        assert_eq!(
            DescriptorPublicKey::from_str(desc),
            Err(DescriptorKeyParseError(
                "Malformed master fingerprint, expected 8 hex chars"
            ))
        );

        // And ones with invalid xpubs..
        let desc = "[78412e3a]xpub1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaLcgJvLJuZZvRcEL/1/*";
        assert_eq!(
            DescriptorPublicKey::from_str(desc),
            Err(DescriptorKeyParseError("Error while parsing xkey."))
        );

        // ..or invalid raw keys
        let desc = "[78412e3a]0208a117f3897c3a13c9384b8695eed98dc31bc2500feb19a1af424cd47a5d83/1/*";
        assert_eq!(
            DescriptorPublicKey::from_str(desc),
            Err(DescriptorKeyParseError(
                "Public keys must be 64/66/130 characters in size"
            ))
        );

        // ..or invalid separators
        let desc = "[78412e3a]]03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8";
        assert_eq!(
            DescriptorPublicKey::from_str(desc),
            Err(DescriptorKeyParseError(
                "Multiple \']\' in Descriptor Public Key"
            ))
        );

        // fuzzer errors
        let desc = "[11111f11]033333333333333333333333333333323333333333333333333333333433333333]]333]]3]]101333333333333433333]]]10]333333mmmm";
        assert_eq!(
            DescriptorPublicKey::from_str(desc),
            Err(DescriptorKeyParseError(
                "Multiple \']\' in Descriptor Public Key"
            ))
        );

        // fuzz failure, hybrid keys
        let desc = "0777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777";
        assert_eq!(
            DescriptorPublicKey::from_str(desc),
            Err(DescriptorKeyParseError(
                "Only publickeys with prefixes 02/03/04 are allowed"
            ))
        );
    }

    #[test]
    fn parse_descriptor_secret_key_error() {
        // Xpubs are invalid
        let secret_key = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL";
        assert_eq!(
            DescriptorSecretKey::from_str(secret_key),
            Err(DescriptorKeyParseError("Error while parsing xkey."))
        );

        // And ones with invalid fingerprints
        let desc = "[NonHexor]tprv8ZgxMBicQKsPcwcD4gSnMti126ZiETsuX7qwrtMypr6FBwAP65puFn4v6c3jrN9VwtMRMph6nyT63NrfUL4C3nBzPcduzVSuHD7zbX2JKVc/1/*";
        assert_eq!(
            DescriptorSecretKey::from_str(desc),
            Err(DescriptorKeyParseError(
                "Malformed master fingerprint, expected 8 hex chars"
            ))
        );

        // ..or invalid raw keys
        let desc = "[78412e3a]L32jTfVLei6BYTPUpwpJSkrHx8iL9GZzeErVS8y4Y/1/*";
        assert_eq!(
            DescriptorSecretKey::from_str(desc),
            Err(DescriptorKeyParseError(
                "Error while parsing a WIF private key"
            ))
        );
    }

    #[test]
    fn test_wildcard() {
        let public_key = DescriptorPublicKey::from_str("[abcdef00/0'/1']tpubDBrgjcxBxnXyL575sHdkpKohWu5qHKoQ7TJXKNrYznh5fVEGBv89hA8ENW7A8MFVpFUSvgLqc4Nj1WZcpePX6rrxviVtPowvMuGF5rdT2Vi/2").unwrap();
        assert_eq!(public_key.master_fingerprint().to_string(), "abcdef00");
        assert_eq!(public_key.full_derivation_path().to_string(), "m/0'/1'/2");
        assert_eq!(public_key.has_wildcard(), false);

        let public_key = DescriptorPublicKey::from_str("[abcdef00/0'/1']tpubDBrgjcxBxnXyL575sHdkpKohWu5qHKoQ7TJXKNrYznh5fVEGBv89hA8ENW7A8MFVpFUSvgLqc4Nj1WZcpePX6rrxviVtPowvMuGF5rdT2Vi/*").unwrap();
        assert_eq!(public_key.master_fingerprint().to_string(), "abcdef00");
        assert_eq!(public_key.full_derivation_path().to_string(), "m/0'/1'");
        assert_eq!(public_key.has_wildcard(), true);

        let public_key = DescriptorPublicKey::from_str("[abcdef00/0'/1']tpubDBrgjcxBxnXyL575sHdkpKohWu5qHKoQ7TJXKNrYznh5fVEGBv89hA8ENW7A8MFVpFUSvgLqc4Nj1WZcpePX6rrxviVtPowvMuGF5rdT2Vi/*h").unwrap();
        assert_eq!(public_key.master_fingerprint().to_string(), "abcdef00");
        assert_eq!(public_key.full_derivation_path().to_string(), "m/0'/1'");
        assert_eq!(public_key.has_wildcard(), true);
    }

    #[test]
    fn test_deriv_on_xprv() {
        let secp = secp256k1::Secp256k1::signing_only();

        let secret_key = DescriptorSecretKey::from_str("tprv8ZgxMBicQKsPcwcD4gSnMti126ZiETsuX7qwrtMypr6FBwAP65puFn4v6c3jrN9VwtMRMph6nyT63NrfUL4C3nBzPcduzVSuHD7zbX2JKVc/0'/1'/2").unwrap();
        let public_key = secret_key.to_public(&secp).unwrap();
        assert_eq!(public_key.to_string(), "[2cbe2a6d/0'/1']tpubDBrgjcxBxnXyL575sHdkpKohWu5qHKoQ7TJXKNrYznh5fVEGBv89hA8ENW7A8MFVpFUSvgLqc4Nj1WZcpePX6rrxviVtPowvMuGF5rdT2Vi/2");
        assert_eq!(public_key.master_fingerprint().to_string(), "2cbe2a6d");
        assert_eq!(public_key.full_derivation_path().to_string(), "m/0'/1'/2");
        assert_eq!(public_key.has_wildcard(), false);

        let secret_key = DescriptorSecretKey::from_str("tprv8ZgxMBicQKsPcwcD4gSnMti126ZiETsuX7qwrtMypr6FBwAP65puFn4v6c3jrN9VwtMRMph6nyT63NrfUL4C3nBzPcduzVSuHD7zbX2JKVc/0'/1'/2'").unwrap();
        let public_key = secret_key.to_public(&secp).unwrap();
        assert_eq!(public_key.to_string(), "[2cbe2a6d/0'/1'/2']tpubDDPuH46rv4dbFtmF6FrEtJEy1CvLZonyBoVxF6xsesHdYDdTBrq2mHhm8AbsPh39sUwL2nZyxd6vo4uWNTU9v4t893CwxjqPnwMoUACLvMV");
        assert_eq!(public_key.master_fingerprint().to_string(), "2cbe2a6d");
        assert_eq!(public_key.full_derivation_path().to_string(), "m/0'/1'/2'");

        let secret_key = DescriptorSecretKey::from_str("tprv8ZgxMBicQKsPcwcD4gSnMti126ZiETsuX7qwrtMypr6FBwAP65puFn4v6c3jrN9VwtMRMph6nyT63NrfUL4C3nBzPcduzVSuHD7zbX2JKVc/0/1/2").unwrap();
        let public_key = secret_key.to_public(&secp).unwrap();
        assert_eq!(public_key.to_string(), "tpubD6NzVbkrYhZ4WQdzxL7NmJN7b85ePo4p6RSj9QQHF7te2RR9iUeVSGgnGkoUsB9LBRosgvNbjRv9bcsJgzgBd7QKuxDm23ZewkTRzNSLEDr/0/1/2");
        assert_eq!(public_key.master_fingerprint().to_string(), "2cbe2a6d");
        assert_eq!(public_key.full_derivation_path().to_string(), "m/0/1/2");

        let secret_key = DescriptorSecretKey::from_str("[aabbccdd]tprv8ZgxMBicQKsPcwcD4gSnMti126ZiETsuX7qwrtMypr6FBwAP65puFn4v6c3jrN9VwtMRMph6nyT63NrfUL4C3nBzPcduzVSuHD7zbX2JKVc/0/1/2").unwrap();
        let public_key = secret_key.to_public(&secp).unwrap();
        assert_eq!(public_key.to_string(), "[aabbccdd]tpubD6NzVbkrYhZ4WQdzxL7NmJN7b85ePo4p6RSj9QQHF7te2RR9iUeVSGgnGkoUsB9LBRosgvNbjRv9bcsJgzgBd7QKuxDm23ZewkTRzNSLEDr/0/1/2");
        assert_eq!(public_key.master_fingerprint().to_string(), "aabbccdd");
        assert_eq!(public_key.full_derivation_path().to_string(), "m/0/1/2");

        let secret_key = DescriptorSecretKey::from_str("[aabbccdd/90']tprv8ZgxMBicQKsPcwcD4gSnMti126ZiETsuX7qwrtMypr6FBwAP65puFn4v6c3jrN9VwtMRMph6nyT63NrfUL4C3nBzPcduzVSuHD7zbX2JKVc/0'/1'/2").unwrap();
        let public_key = secret_key.to_public(&secp).unwrap();
        assert_eq!(public_key.to_string(), "[aabbccdd/90'/0'/1']tpubDBrgjcxBxnXyL575sHdkpKohWu5qHKoQ7TJXKNrYznh5fVEGBv89hA8ENW7A8MFVpFUSvgLqc4Nj1WZcpePX6rrxviVtPowvMuGF5rdT2Vi/2");
        assert_eq!(public_key.master_fingerprint().to_string(), "aabbccdd");
        assert_eq!(
            public_key.full_derivation_path().to_string(),
            "m/90'/0'/1'/2"
        );
    }

    #[test]
    fn test_master_fingerprint() {
        assert_eq!(
            DescriptorPublicKey::from_str(
                "02a489e0ea42b56148d212d325b7c67c6460483ff931c303ea311edfef667c8f35",
            )
            .unwrap()
            .master_fingerprint()
            .as_bytes(),
            b"\xb0\x59\x11\x6a"
        );
    }
}
