//! Module of specialized impl blocks for certain MiniscriptKeys.
//! Contains common APIs for specific types of keys like `DescriptorPublicKey`,
//! `DefinitePublicKey` and more.

use core::convert::Infallible;
use core::ops::Range;
use core::str::{self, FromStr};

use bitcoin::hashes::{hash160, ripemd160, sha256};
use bitcoin::{secp256k1, Script};

use super::ConversionError;
use crate::descriptor::DescriptorSecretKey;
use crate::prelude::*;
use crate::{
    hash256, DefiniteDescriptorKey, Descriptor, DescriptorPublicKey, Error, ForEachKey,
    MsDescriptor, MsDescriptorXPubOnly, TranslatePk, Translator, XPubOnly,
};

/// Alias type for a map of public key to secret key
///
/// This map is returned whenever a descriptor that contains secrets is parsed using
/// [`Descriptor::parse_descriptor`], since the descriptor will always only contain
/// public keys. This map allows looking up the corresponding secret key given a
/// public key from the descriptor.
pub type KeyMap = HashMap<DescriptorPublicKey, DescriptorSecretKey>;

impl MsDescriptorXPubOnly {
    /// Whether or not the descriptor has any wildcards i.e. `/*`.
    pub fn has_wildcard(&self) -> bool {
        self.for_any_key(|key| key.has_wildcard())
    }

    /// Replaces all wildcards (i.e. `/*`) in the descriptor with a particular derivation index,
    /// turning it into a *definite* descriptor.
    ///
    /// # Errors
    /// - If index ≥ 2^31
    pub fn at_derivation_index(
        &self,
        index: u32,
    ) -> Result<Descriptor<DefiniteDescriptorKey>, ConversionError> {
        struct Derivator(u32);

        impl Translator<XPubOnly, DefiniteDescriptorKey, ConversionError> for Derivator {
            fn pk(&mut self, pk: &XPubOnly) -> Result<DefiniteDescriptorKey, ConversionError> {
                pk.clone().at_derivation_index(self.0)
            }

            translate_hash_clone!(XPubOnly, XPubOnly, ConversionError);
        }

        self.translate_pk(&mut Derivator(index))
            .map_err(|e| e.expect_translator_err("No Context errors while translating"))
    }

    /// Same as [`Descriptor<DescriptorPublicKey>::derived_descriptor`], but for
    /// descriptors with Extended keys only(xpubs only).
    pub fn derived_descriptor<C: secp256k1::Verification>(
        &self,
        secp: &secp256k1::Secp256k1<C>,
        index: u32,
    ) -> Result<Descriptor<bitcoin::PublicKey>, ConversionError> {
        self.at_derivation_index(index)?.derived_descriptor(secp)
    }

    /// Returns the ms descriptor of this [`MsDescriptorXPubOnly`].
    pub fn ms_descriptor(&self) -> MsDescriptor {
        struct MsDescriptorTranslator;

        impl Translator<XPubOnly, DescriptorPublicKey, Infallible> for MsDescriptorTranslator {
            fn pk(&mut self, pk: &XPubOnly) -> Result<DescriptorPublicKey, Infallible> {
                Ok(DescriptorPublicKey::XPub(pk.clone()))
            }

            translate_hash_clone!(XPubOnly, XPubOnly, Infallible);
        }

        let res = self
            .translate_pk(&mut MsDescriptorTranslator)
            .map_err(|e| e.expect_translator_err("No Context errors while translating"));
        // Indirect way to unwrap the infallible error type
        match res {
            Ok(desc) => desc,
            Err(e) => match e {},
        }
    }

    /// Constructs a new [`MsDescriptorXPubOnly`] from a [`MsDescriptor`].
    ///
    /// # Returns None if:
    ///
    /// - If the descriptor contains any non-xpub keys.
    pub fn from_ms_descriptor(desc: &MsDescriptor) -> Option<Self> {
        struct XOnlyKeyTranslator;

        impl Translator<DescriptorPublicKey, XPubOnly, ()> for XOnlyKeyTranslator {
            fn pk(&mut self, pk: &DescriptorPublicKey) -> Result<XPubOnly, ()> {
                if let DescriptorPublicKey::XPub(xpub) = pk {
                    Ok(xpub.clone())
                } else {
                    Err(())
                }
            }

            translate_hash_clone!(DescriptorPublicKey, XPubOnly, ());
        }

        desc.translate_pk(&mut XOnlyKeyTranslator)
            .map_err(|e| e.expect_translator_err("No Context errors while translating"))
            .ok()
    }
}

impl Descriptor<DescriptorPublicKey> {
    /// Whether or not the descriptor has any wildcards
    #[deprecated(note = "use has_wildcards instead")]
    pub fn is_deriveable(&self) -> bool {
        self.has_wildcard()
    }

    /// Whether or not the descriptor has any wildcards i.e. `/*`.
    pub fn has_wildcard(&self) -> bool {
        self.for_any_key(|key| key.has_wildcard())
    }

    /// Replaces all wildcards (i.e. `/*`) in the descriptor with a particular derivation index,
    /// turning it into a *definite* descriptor.
    ///
    /// # Errors
    /// - If index ≥ 2^31
    pub fn at_derivation_index(
        &self,
        index: u32,
    ) -> Result<Descriptor<DefiniteDescriptorKey>, ConversionError> {
        struct Derivator(u32);

        impl Translator<DescriptorPublicKey, DefiniteDescriptorKey, ConversionError> for Derivator {
            fn pk(
                &mut self,
                pk: &DescriptorPublicKey,
            ) -> Result<DefiniteDescriptorKey, ConversionError> {
                pk.clone().at_derivation_index(self.0)
            }

            translate_hash_clone!(DescriptorPublicKey, DescriptorPublicKey, ConversionError);
        }
        self.translate_pk(&mut Derivator(index))
            .map_err(|e| e.expect_translator_err("No Context errors while translating"))
    }

    #[deprecated(note = "use at_derivation_index instead")]
    /// Deprecated name for [`Self::at_derivation_index`].
    pub fn derive(&self, index: u32) -> Result<Descriptor<DefiniteDescriptorKey>, ConversionError> {
        self.at_derivation_index(index)
    }

    /// Convert all the public keys in the descriptor to [`bitcoin::PublicKey`] by deriving them or
    /// otherwise converting them. All [`bitcoin::secp256k1::XOnlyPublicKey`]s are converted to by adding a
    /// default(0x02) y-coordinate.
    ///
    /// This is a shorthand for:
    ///
    /// ```
    /// # use miniscript::{Descriptor, DescriptorPublicKey, bitcoin::secp256k1::Secp256k1};
    /// # use core::str::FromStr;
    /// # let descriptor = Descriptor::<DescriptorPublicKey>::from_str("tr(xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/0/*)")
    ///     .expect("Valid ranged descriptor");
    /// # let index = 42;
    /// # let secp = Secp256k1::verification_only();
    /// let derived_descriptor = descriptor.at_derivation_index(index).unwrap().derived_descriptor(&secp).unwrap();
    /// # assert_eq!(descriptor.derived_descriptor(&secp, index).unwrap(), derived_descriptor);
    /// ```
    ///
    /// and is only here really here for backwards compatbility.
    /// See [`at_derivation_index`] and `[derived_descriptor`] for more documentation.
    ///
    /// [`at_derivation_index`]: Self::at_derivation_index
    /// [`derived_descriptor`]: crate::DerivedDescriptor::derived_descriptor
    ///
    /// # Errors
    ///
    /// This function will return an error if hardened derivation is attempted.
    pub fn derived_descriptor<C: secp256k1::Verification>(
        &self,
        secp: &secp256k1::Secp256k1<C>,
        index: u32,
    ) -> Result<Descriptor<bitcoin::PublicKey>, ConversionError> {
        self.at_derivation_index(index)?.derived_descriptor(secp)
    }

    /// Parse a descriptor that may contain secret keys
    ///
    /// Internally turns every secret key found into the corresponding public key and then returns a
    /// a descriptor that only contains public keys and a map to lookup the secret key given a public key.
    pub fn parse_descriptor<C: secp256k1::Signing>(
        secp: &secp256k1::Secp256k1<C>,
        s: &str,
    ) -> Result<(Descriptor<DescriptorPublicKey>, KeyMap), Error> {
        fn parse_key<C: secp256k1::Signing>(
            s: &str,
            key_map: &mut KeyMap,
            secp: &secp256k1::Secp256k1<C>,
        ) -> Result<DescriptorPublicKey, Error> {
            let (public_key, secret_key) = match DescriptorSecretKey::from_str(s) {
                Ok(sk) => (
                    sk.to_public(secp)
                        .map_err(|e| Error::Unexpected(e.to_string()))?,
                    Some(sk),
                ),
                Err(_) => (
                    DescriptorPublicKey::from_str(s)
                        .map_err(|e| Error::Unexpected(e.to_string()))?,
                    None,
                ),
            };

            if let Some(secret_key) = secret_key {
                key_map.insert(public_key.clone(), secret_key);
            }

            Ok(public_key)
        }

        let mut keymap_pk = KeyMapWrapper(HashMap::new(), secp);

        struct KeyMapWrapper<'a, C: secp256k1::Signing>(KeyMap, &'a secp256k1::Secp256k1<C>);

        impl<'a, C: secp256k1::Signing> Translator<String, DescriptorPublicKey, Error>
            for KeyMapWrapper<'a, C>
        {
            fn pk(&mut self, pk: &String) -> Result<DescriptorPublicKey, Error> {
                parse_key(pk, &mut self.0, self.1)
            }

            fn sha256(&mut self, sha256: &String) -> Result<sha256::Hash, Error> {
                let hash =
                    sha256::Hash::from_str(sha256).map_err(|e| Error::Unexpected(e.to_string()))?;
                Ok(hash)
            }

            fn hash256(&mut self, hash256: &String) -> Result<hash256::Hash, Error> {
                let hash = hash256::Hash::from_str(hash256)
                    .map_err(|e| Error::Unexpected(e.to_string()))?;
                Ok(hash)
            }

            fn ripemd160(&mut self, ripemd160: &String) -> Result<ripemd160::Hash, Error> {
                let hash = ripemd160::Hash::from_str(ripemd160)
                    .map_err(|e| Error::Unexpected(e.to_string()))?;
                Ok(hash)
            }

            fn hash160(&mut self, hash160: &String) -> Result<hash160::Hash, Error> {
                let hash = hash160::Hash::from_str(hash160)
                    .map_err(|e| Error::Unexpected(e.to_string()))?;
                Ok(hash)
            }
        }

        let descriptor = Descriptor::<String>::from_str(s)?;
        let descriptor = descriptor.translate_pk(&mut keymap_pk).map_err(|e| {
            Error::Unexpected(
                e.expect_translator_err("No Outer context errors")
                    .to_string(),
            )
        })?;

        Ok((descriptor, keymap_pk.0))
    }

    /// Serialize a descriptor to string with its secret keys
    pub fn to_string_with_secret(&self, key_map: &KeyMap) -> String {
        struct KeyMapLookUp<'a>(&'a KeyMap);

        impl<'a> Translator<DescriptorPublicKey, String, ()> for KeyMapLookUp<'a> {
            fn pk(&mut self, pk: &DescriptorPublicKey) -> Result<String, ()> {
                key_to_string(pk, self.0)
            }

            fn sha256(&mut self, sha256: &sha256::Hash) -> Result<String, ()> {
                Ok(sha256.to_string())
            }

            fn hash256(&mut self, hash256: &hash256::Hash) -> Result<String, ()> {
                Ok(hash256.to_string())
            }

            fn ripemd160(&mut self, ripemd160: &ripemd160::Hash) -> Result<String, ()> {
                Ok(ripemd160.to_string())
            }

            fn hash160(&mut self, hash160: &hash160::Hash) -> Result<String, ()> {
                Ok(hash160.to_string())
            }
        }

        fn key_to_string(pk: &DescriptorPublicKey, key_map: &KeyMap) -> Result<String, ()> {
            Ok(match key_map.get(pk) {
                Some(secret) => secret.to_string(),
                None => pk.to_string(),
            })
        }

        let descriptor = self
            .translate_pk(&mut KeyMapLookUp(key_map))
            .expect("Translation to string cannot fail");

        descriptor.to_string()
    }

    /// Utility method for deriving the descriptor at each index in a range to find one matching
    /// `script_pubkey`.
    ///
    /// If it finds a match then it returns the index it was derived at and the concrete
    /// descriptor at that index. If the descriptor is non-derivable then it will simply check the
    /// script pubkey against the descriptor and return it if it matches (in this case the index
    /// returned will be meaningless).
    pub fn find_derivation_index_for_spk<C: secp256k1::Verification>(
        &self,
        secp: &secp256k1::Secp256k1<C>,
        script_pubkey: &Script,
        range: Range<u32>,
    ) -> Result<Option<(u32, Descriptor<bitcoin::PublicKey>)>, ConversionError> {
        let range = if self.has_wildcard() { range } else { 0..1 };

        for i in range {
            let concrete = self.derived_descriptor(secp, i)?;
            if &concrete.script_pubkey() == script_pubkey {
                return Ok(Some((i, concrete)));
            }
        }

        Ok(None)
    }

    /// Whether this descriptor contains a key that has multiple derivation paths.
    pub fn is_multipath(&self) -> bool {
        self.for_any_key(DescriptorPublicKey::is_multipath)
    }

    /// Get as many descriptors as different paths in this descriptor.
    ///
    /// For multipath descriptors it will return as many descriptors as there is
    /// "parallel" paths. For regular descriptors it will just return itself.
    #[allow(clippy::blocks_in_if_conditions)]
    pub fn into_single_descriptors(self) -> Result<Vec<Descriptor<DescriptorPublicKey>>, Error> {
        // All single-path descriptors contained in this descriptor.
        let mut descriptors = Vec::new();
        // We (ab)use `for_any_key` to gather the number of separate descriptors.
        if !self.for_any_key(|key| {
            // All multipath keys must have the same number of indexes at the "multi-index"
            // step. So we can return early if we already populated the vector.
            if !descriptors.is_empty() {
                return true;
            }

            match key {
                DescriptorPublicKey::Single(..) | DescriptorPublicKey::XPub(..) => false,
                DescriptorPublicKey::MultiXPub(xpub) => {
                    for _ in 0..xpub.derivation_paths.paths().len() {
                        descriptors.push(self.clone());
                    }
                    true
                }
            }
        }) {
            // If there is no multipath key, return early.
            return Ok(vec![self]);
        }
        assert!(!descriptors.is_empty());

        // Now, transform the multipath key of each descriptor into a single-key using each index.
        struct IndexChoser(usize);
        impl Translator<DescriptorPublicKey, DescriptorPublicKey, Error> for IndexChoser {
            fn pk(&mut self, pk: &DescriptorPublicKey) -> Result<DescriptorPublicKey, Error> {
                match pk {
                    DescriptorPublicKey::Single(..) | DescriptorPublicKey::XPub(..) => {
                        Ok(pk.clone())
                    }
                    DescriptorPublicKey::MultiXPub(_) => pk
                        .clone()
                        .into_single_keys()
                        .get(self.0)
                        .cloned()
                        .ok_or(Error::MultipathDescLenMismatch),
                }
            }
            translate_hash_clone!(DescriptorPublicKey, DescriptorPublicKey, Error);
        }

        for (i, desc) in descriptors.iter_mut().enumerate() {
            let mut index_choser = IndexChoser(i);
            *desc = desc
                .translate_pk(&mut index_choser)
                .map_err(|e| e.expect_translator_err("No Context errors possible"))?;
        }

        Ok(descriptors)
    }
}

impl Descriptor<DefiniteDescriptorKey> {
    /// Convert all the public keys in the descriptor to [`bitcoin::PublicKey`] by deriving them or
    /// otherwise converting them. All [`bitcoin::secp256k1::XOnlyPublicKey`]s are converted to by adding a
    /// default(0x02) y-coordinate.
    ///
    /// # Examples
    ///
    /// ```
    /// use miniscript::descriptor::{Descriptor, DescriptorPublicKey};
    /// use miniscript::bitcoin::secp256k1;
    /// use std::str::FromStr;
    ///
    /// // test from bip 86
    /// let secp = secp256k1::Secp256k1::verification_only();
    /// let descriptor = Descriptor::<DescriptorPublicKey>::from_str("tr(xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/0/*)")
    ///     .expect("Valid ranged descriptor");
    /// let result = descriptor.at_derivation_index(0).unwrap().derived_descriptor(&secp).expect("Non-hardened derivation");
    /// assert_eq!(result.to_string(), "tr(03cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115)#6qm9h8ym");
    /// ```
    ///
    /// # Errors
    ///
    /// This function will return an error if hardened derivation is attempted.
    pub fn derived_descriptor<C: secp256k1::Verification>(
        &self,
        secp: &secp256k1::Secp256k1<C>,
    ) -> Result<Descriptor<bitcoin::PublicKey>, ConversionError> {
        struct Derivator<'a, C: secp256k1::Verification>(&'a secp256k1::Secp256k1<C>);

        impl<'a, C: secp256k1::Verification>
            Translator<DefiniteDescriptorKey, bitcoin::PublicKey, ConversionError>
            for Derivator<'a, C>
        {
            fn pk(
                &mut self,
                pk: &DefiniteDescriptorKey,
            ) -> Result<bitcoin::PublicKey, ConversionError> {
                pk.derive_public_key(self.0)
            }

            translate_hash_clone!(DefiniteDescriptorKey, bitcoin::PublicKey, ConversionError);
        }

        let derived = self.translate_pk(&mut Derivator(secp));
        match derived {
            Ok(derived) => Ok(derived),
            Err(e) => Err(e.expect_translator_err("No Context errors when deriving keys")),
        }
    }
}
