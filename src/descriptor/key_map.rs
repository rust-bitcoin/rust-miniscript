// SPDX-License-Identifier: CC0-1.0

//! A map of public key to secret key.

use core::iter;

use bitcoin::psbt::{GetKey, GetKeyError, KeyRequest};
use bitcoin::secp256k1::{Secp256k1, Signing};
use bitcoin::PrivateKey;

#[cfg(doc)]
use super::Descriptor;
use super::{DescriptorKeyParseError, DescriptorPublicKey, DescriptorSecretKey};
use crate::prelude::{btree_map, BTreeMap};

/// A structure mapping [`DescriptorPublicKey`] to [`DescriptorSecretKey`].
///
/// It's returned whenever a descriptor that contains secrets is parsed using
/// [`Descriptor::parse_descriptor`], since the descriptor will always only contain
/// public keys. This map allows looking up the corresponding secret key given a
/// public key from the descriptor.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KeyMap {
    map: BTreeMap<DescriptorPublicKey, DescriptorSecretKey>,
}

impl KeyMap {
    /// Creates a new empty `KeyMap`.
    #[inline]
    pub fn new() -> Self { Self { map: BTreeMap::new() } }

    /// Inserts secret key into key map returning the associated public key.
    #[inline]
    pub fn insert<C: Signing>(
        &mut self,
        secp: &Secp256k1<C>,
        sk: DescriptorSecretKey,
    ) -> Result<DescriptorPublicKey, DescriptorKeyParseError> {
        let pk = sk.to_public(secp)?;
        if !self.map.contains_key(&pk) {
            self.map.insert(pk.clone(), sk);
        }
        Ok(pk)
    }

    /// Gets the secret key associated with `pk` if `pk` is in the map.
    #[inline]
    pub fn get(&self, pk: &DescriptorPublicKey) -> Option<&DescriptorSecretKey> { self.map.get(pk) }

    /// Returns the number of items in this map.
    #[inline]
    pub fn len(&self) -> usize { self.map.len() }

    /// Returns true if the map is empty.
    #[inline]
    pub fn is_empty(&self) -> bool { self.map.is_empty() }
}

impl Default for KeyMap {
    fn default() -> Self { Self::new() }
}

impl IntoIterator for KeyMap {
    type Item = (DescriptorPublicKey, DescriptorSecretKey);
    type IntoIter = btree_map::IntoIter<DescriptorPublicKey, DescriptorSecretKey>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter { self.map.into_iter() }
}

impl iter::Extend<(DescriptorPublicKey, DescriptorSecretKey)> for KeyMap {
    #[inline]
    fn extend<T>(&mut self, iter: T)
    where
        T: IntoIterator<Item = (DescriptorPublicKey, DescriptorSecretKey)>,
    {
        self.map.extend(iter)
    }
}

impl GetKey for KeyMap {
    type Error = GetKeyError;

    fn get_key<C: Signing>(
        &self,
        key_request: KeyRequest,
        secp: &Secp256k1<C>,
    ) -> Result<Option<bitcoin::PrivateKey>, Self::Error> {
        Ok(self
            .map
            .iter()
            .find_map(|(_desc_pk, desc_sk)| -> Option<PrivateKey> {
                match desc_sk.get_key(key_request.clone(), secp) {
                    Ok(Some(pk)) => Some(pk),
                    // When looking up keys in a map, we eat errors on individual keys, on
                    // the assumption that some other key in the map might not error.
                    Ok(None) | Err(_) => None,
                }
            }))
    }
}

impl GetKey for DescriptorSecretKey {
    type Error = GetKeyError;

    fn get_key<C: Signing>(
        &self,
        key_request: KeyRequest,
        secp: &Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error> {
        match (self, key_request) {
            (DescriptorSecretKey::Single(single_priv), key_request) => {
                let sk = single_priv.key;
                let pk = sk.public_key(secp);
                let pubkey_map = BTreeMap::from([(pk, sk)]);
                pubkey_map.get_key(key_request, secp)
            }
            (DescriptorSecretKey::XPrv(descriptor_xkey), KeyRequest::Pubkey(public_key)) => {
                let xpriv = descriptor_xkey
                    .xkey
                    .derive_priv(secp, &descriptor_xkey.derivation_path)
                    .map_err(GetKeyError::Bip32)?;
                let pk = xpriv.private_key.public_key(secp);

                if public_key.inner.eq(&pk) {
                    Ok(Some(xpriv.to_priv()))
                } else {
                    Ok(None)
                }
            }
            (
                DescriptorSecretKey::XPrv(descriptor_xkey),
                ref key_request @ KeyRequest::Bip32(ref key_source),
            ) => {
                if let Some(key) = descriptor_xkey.xkey.get_key(key_request.clone(), secp)? {
                    return Ok(Some(key));
                }

                if let Some(matched_path) = descriptor_xkey.matches(key_source, secp) {
                    let (_, full_path) = key_source;

                    let derivation_path = &full_path[matched_path.len()..];

                    return Ok(Some(
                        descriptor_xkey
                            .xkey
                            .derive_priv(secp, &derivation_path)
                            .map_err(GetKeyError::Bip32)?
                            .to_priv(),
                    ));
                }

                Ok(None)
            }
            (DescriptorSecretKey::XPrv(_), KeyRequest::XOnlyPubkey(_)) => {
                Err(GetKeyError::NotSupported)
            }
            (
                desc_multi_sk @ DescriptorSecretKey::MultiXPrv(_descriptor_multi_xkey),
                key_request,
            ) => {
                for desc_sk in &desc_multi_sk.clone().into_single_keys() {
                    // If any key is an error, then all of them will, so here we propagate errors with ?.
                    if let Some(pk) = desc_sk.get_key(key_request.clone(), secp)? {
                        return Ok(Some(pk));
                    }
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use bitcoin::bip32::{ChildNumber, DerivationPath, IntoDerivationPath, Xpriv};

    use super::*;
    use crate::Descriptor;

    #[test]
    fn get_key_single_key() {
        let secp = Secp256k1::new();

        let descriptor_sk_s =
            "[90b6a706/44'/0'/0'/0/0]cMk8gWmj1KpjdYnAWwsEDekodMYhbyYBhG8gMtCCxucJ98JzcNij";

        let single = match descriptor_sk_s.parse::<DescriptorSecretKey>().unwrap() {
            DescriptorSecretKey::Single(single) => single,
            _ => panic!("unexpected DescriptorSecretKey variant"),
        };

        let want_sk = single.key;
        let descriptor_s = format!("wpkh({})", descriptor_sk_s);
        let (_, keymap) = Descriptor::parse_descriptor(&secp, &descriptor_s).unwrap();

        let pk = want_sk.public_key(&secp);
        let request = KeyRequest::Pubkey(pk);
        let got_sk = keymap
            .get_key(request, &secp)
            .expect("get_key call errored")
            .expect("failed to find the key");
        assert_eq!(got_sk, want_sk)
    }

    #[test]
    fn get_key_xpriv_single_key_xpriv() {
        let secp = Secp256k1::new();

        let s = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

        let xpriv = s.parse::<Xpriv>().unwrap();
        let xpriv_fingerprint = xpriv.fingerprint(&secp);

        // Sanity check.
        {
            let descriptor_sk_s = format!("[{}]{}", xpriv_fingerprint, xpriv);
            let descriptor_sk = descriptor_sk_s.parse::<DescriptorSecretKey>().unwrap();
            let got = match descriptor_sk {
                DescriptorSecretKey::XPrv(x) => x.xkey,
                _ => panic!("unexpected DescriptorSecretKey variant"),
            };
            assert_eq!(got, xpriv);
        }

        let want_sk = xpriv.to_priv();
        let descriptor_s = format!("wpkh([{}]{})", xpriv_fingerprint, xpriv);
        let (_, keymap) = Descriptor::parse_descriptor(&secp, &descriptor_s).unwrap();

        let pk = want_sk.public_key(&secp);
        let request = KeyRequest::Pubkey(pk);
        let got_sk = keymap
            .get_key(request, &secp)
            .expect("get_key call errored")
            .expect("failed to find the key");
        assert_eq!(got_sk, want_sk)
    }

    #[test]
    fn get_key_xpriv_child_depth_one() {
        let secp = Secp256k1::new();

        let s = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        let master = s.parse::<Xpriv>().unwrap();
        let master_fingerprint = master.fingerprint(&secp);

        let child_number = ChildNumber::from_hardened_idx(44).unwrap();
        let child = master.derive_priv(&secp, &[child_number]).unwrap();

        // Sanity check.
        {
            let descriptor_sk_s = format!("[{}/44']{}", master_fingerprint, child);
            let descriptor_sk = descriptor_sk_s.parse::<DescriptorSecretKey>().unwrap();
            let got = match descriptor_sk {
                DescriptorSecretKey::XPrv(ref x) => x.xkey,
                _ => panic!("unexpected DescriptorSecretKey variant"),
            };
            assert_eq!(got, child);
        }

        let want_sk = child.to_priv();
        let descriptor_s = format!("wpkh({}/44')", s);
        let (_, keymap) = Descriptor::parse_descriptor(&secp, &descriptor_s).unwrap();

        let pk = want_sk.public_key(&secp);
        let request = KeyRequest::Pubkey(pk);
        let got_sk = keymap
            .get_key(request, &secp)
            .expect("get_key call errored")
            .expect("failed to find the key");
        assert_eq!(got_sk, want_sk)
    }

    #[test]
    fn get_key_xpriv_with_path() {
        let secp = Secp256k1::new();

        let s = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        let master = s.parse::<Xpriv>().unwrap();
        let master_fingerprint = master.fingerprint(&secp);

        let first_external_child = "44'/0'/0'/0/0";
        let derivation_path = first_external_child.into_derivation_path().unwrap();

        let child = master.derive_priv(&secp, &derivation_path).unwrap();

        // Sanity check.
        {
            let descriptor_sk_s =
                format!("[{}/{}]{}", master_fingerprint, first_external_child, child);
            let descriptor_sk = descriptor_sk_s.parse::<DescriptorSecretKey>().unwrap();
            let got = match descriptor_sk {
                DescriptorSecretKey::XPrv(ref x) => x.xkey,
                _ => panic!("unexpected DescriptorSecretKey variant"),
            };
            assert_eq!(got, child);
        }

        let want_sk = child.to_priv();
        let descriptor_s = format!("wpkh({}/44'/0'/0'/0/*)", s);
        let (_, keymap) = Descriptor::parse_descriptor(&secp, &descriptor_s).unwrap();

        let key_source = (master_fingerprint, derivation_path);
        let request = KeyRequest::Bip32(key_source);
        let got_sk = keymap
            .get_key(request, &secp)
            .expect("get_key call errored")
            .expect("failed to find the key");

        assert_eq!(got_sk, want_sk)
    }

    #[test]
    fn get_key_xpriv_with_key_origin() {
        let secp = Secp256k1::new();

        let descriptor_str = "wpkh([d34db33f/84h/1h/0h]tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/*)";
        let (_descriptor_pk, keymap) = Descriptor::parse_descriptor(&secp, descriptor_str).unwrap();

        let descriptor_sk = DescriptorSecretKey::from_str("[d34db33f/84h/1h/0h]tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/*").unwrap();
        let xpriv = match descriptor_sk {
            DescriptorSecretKey::XPrv(descriptor_xkey) => descriptor_xkey,
            _ => unreachable!(),
        };

        let expected_deriv_path: DerivationPath = (&[ChildNumber::Normal { index: 0 }][..]).into();
        let expected_pk = xpriv
            .xkey
            .derive_priv(&secp, &expected_deriv_path)
            .unwrap()
            .to_priv();

        let derivation_path = DerivationPath::from_str("84'/1'/0'/0").unwrap();
        let (fp, _) = xpriv.origin.unwrap();
        let key_request = KeyRequest::Bip32((fp, derivation_path));

        let pk = keymap
            .get_key(key_request, &secp)
            .expect("get_key should not fail")
            .expect("get_key should return a `PrivateKey`");

        assert_eq!(pk, expected_pk);
    }

    #[test]
    fn get_key_keymap_no_match() {
        let secp = Secp256k1::new();

        // Create a keymap with one key
        let descriptor_s = "wpkh(cMk8gWmj1KpjdYnAWwsEDekodMYhbyYBhG8gMtCCxucJ98JzcNij)";
        let (_, keymap) = Descriptor::parse_descriptor(&secp, descriptor_s).unwrap();

        // Request a different public key that doesn't exist in the keymap
        let different_sk =
            PrivateKey::from_str("cNJFgo1driFnPcBdBX8BrJrpxchBWXwXCvNH5SoSkdcF6JXXwHMm").unwrap();
        let different_pk = different_sk.public_key(&secp);
        let request = KeyRequest::Pubkey(different_pk);

        let result = keymap.get_key(request, &secp).unwrap();
        assert!(result.is_none(), "Should return None when no matching key is found");
    }

    #[test]
    fn get_key_descriptor_secret_key_xonly_not_supported() {
        let secp = Secp256k1::new();

        let descriptor_sk = DescriptorSecretKey::from_str("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi").unwrap();

        // Create an x-only public key request
        let sk =
            PrivateKey::from_str("cMk8gWmj1KpjdYnAWwsEDekodMYhbyYBhG8gMtCCxucJ98JzcNij").unwrap();
        let xonly_pk = sk.public_key(&secp).inner.x_only_public_key().0;
        let request = KeyRequest::XOnlyPubkey(xonly_pk);

        let result = descriptor_sk.get_key(request.clone(), &secp);
        assert!(matches!(result, Err(GetKeyError::NotSupported)));

        // Also test with KeyMap
        let descriptor_s = "wpkh(xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi)";
        let (_, keymap) = Descriptor::parse_descriptor(&secp, descriptor_s).unwrap();

        // While requesting an x-only key from an individual xpriv, that's an error.
        // But from a keymap, which might have both x-only keys and regular xprivs,
        // we treat errors as "key not found".
        let result = keymap.get_key(request, &secp);
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn get_key_descriptor_secret_key_xonly_multipath() {
        let secp = Secp256k1::new();

        let descriptor_sk = DescriptorSecretKey::from_str("[d34db33f/84h/0h/0h]tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/<0;1>").unwrap();

        // Request with a different fingerprint
        let different_fingerprint = bitcoin::bip32::Fingerprint::from([0x12, 0x34, 0x56, 0x78]);
        let path = DerivationPath::from_str("84'/1'/0'/0").unwrap();
        let request = KeyRequest::Bip32((different_fingerprint, path));

        let result = descriptor_sk.get_key(request.clone(), &secp).unwrap();
        assert!(result.is_none(), "Should return None when fingerprint doesn't match");

        // Create an x-only public key request -- now we get "not supported".
        let sk =
            PrivateKey::from_str("cMk8gWmj1KpjdYnAWwsEDekodMYhbyYBhG8gMtCCxucJ98JzcNij").unwrap();
        let xonly_pk = sk.public_key(&secp).inner.x_only_public_key().0;
        let request_x = KeyRequest::XOnlyPubkey(xonly_pk);

        let result = descriptor_sk.get_key(request_x.clone(), &secp);
        assert!(matches!(result, Err(GetKeyError::NotSupported)));

        // Also test with KeyMap; as in the previous test, the error turns to None.
        let descriptor_s = "wpkh([d34db33f/84h/1h/0h]tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/<0;1>/*)";
        let (_, keymap) = Descriptor::parse_descriptor(&secp, descriptor_s).unwrap();

        let result = keymap.get_key(request.clone(), &secp).unwrap();
        assert!(result.is_none(), "Should return None when fingerprint doesn't match");
        let result = keymap.get_key(request, &secp).unwrap();
        assert!(result.is_none(), "Should return None when fingerprint doesn't match");
        let result = descriptor_sk.get_key(request_x.clone(), &secp);
        assert!(matches!(result, Err(GetKeyError::NotSupported)));
        let result = keymap.get_key(request_x, &secp).unwrap();
        assert!(result.is_none(), "Should return None even on error");
    }
}
