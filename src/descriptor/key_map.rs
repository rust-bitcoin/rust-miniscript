use bitcoin::psbt::{GetKey, GetKeyError, KeyRequest};
use bitcoin::secp256k1::{Secp256k1, Signing};
use bitcoin::PrivateKey;

use crate::descriptor::{DescriptorSecretKey, KeyMap};
use crate::BTreeMap;

/// A wrapper around KeyMap that implements GetKey for PSBT signing.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KeyMapWrapper {
    map: KeyMap,
}

impl From<KeyMap> for KeyMapWrapper {
    fn from(map: KeyMap) -> Self { KeyMapWrapper { map } }
}

impl GetKey for KeyMapWrapper {
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

                // A successful `matches()` already guarantees the requested key source's fingerprint equals our origin
                // (or, when there is no origin, the xkey's own) fingerprint.
                //
                // `xkey` is anchored at the origin, but the request path is master-relative, either:
                // - origin: strip the origin prefix and use the remaining suffix.
                // - no origin: use the full request path.
                let (_, full_path) = key_source;
                let derivation_path = match descriptor_xkey.matches(key_source, secp) {
                    Some(_) => match &descriptor_xkey.origin {
                        Some((_, origin_path)) => &full_path[origin_path.len()..],
                        None => full_path.as_ref(),
                    },
                    None => return Ok(None),
                };

                Ok(Some(
                    descriptor_xkey
                        .xkey
                        .derive_priv(secp, &derivation_path)?
                        .to_priv(),
                ))
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

    use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, IntoDerivationPath, Xpriv};

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
        let keymap_wrapper = KeyMapWrapper::from(keymap);

        let pk = want_sk.public_key(&secp);
        let request = KeyRequest::Pubkey(pk);
        let got_sk = keymap_wrapper
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
        let keymap_wrapper = KeyMapWrapper::from(keymap);

        let pk = want_sk.public_key(&secp);
        let request = KeyRequest::Pubkey(pk);
        let got_sk = keymap_wrapper
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
        let keymap_wrapper = KeyMapWrapper::from(keymap);

        let pk = want_sk.public_key(&secp);
        let request = KeyRequest::Pubkey(pk);
        let got_sk = keymap_wrapper
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
        let keymap_wrapper = KeyMapWrapper::from(keymap);

        let key_source = (master_fingerprint, derivation_path);
        let request = KeyRequest::Bip32(key_source);
        let got_sk = keymap_wrapper
            .get_key(request, &secp)
            .expect("get_key call errored")
            .expect("failed to find the key");

        assert_eq!(got_sk, want_sk)
    }

    #[test]
    fn get_key_keymap_no_match() {
        let secp = Secp256k1::new();

        // Create a keymap with one key
        let descriptor_s = "wpkh(cMk8gWmj1KpjdYnAWwsEDekodMYhbyYBhG8gMtCCxucJ98JzcNij)";
        let (_, keymap) = Descriptor::parse_descriptor(&secp, descriptor_s).unwrap();
        let keymap_wrapper = KeyMapWrapper::from(keymap);

        // Request a different public key that doesn't exist in the keymap
        let different_sk =
            PrivateKey::from_str("cNJFgo1driFnPcBdBX8BrJrpxchBWXwXCvNH5SoSkdcF6JXXwHMm").unwrap();
        let different_pk = different_sk.public_key(&secp);
        let request = KeyRequest::Pubkey(different_pk);

        let result = keymap_wrapper.get_key(request, &secp).unwrap();
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
        let keymap_wrapper = KeyMapWrapper::from(keymap);

        // While requesting an x-only key from an individual xpriv, that's an error.
        // But from a keymap, which might have both x-only keys and regular xprivs,
        // we treat errors as "key not found".
        let result = keymap_wrapper.get_key(request, &secp);
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
        let descriptor_s = "wpkh([d34db33f/84h/1h/0h]tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/*)";
        let (_, keymap) = Descriptor::parse_descriptor(&secp, descriptor_s).unwrap();
        let keymap_wrapper = KeyMapWrapper::from(keymap);

        let result = keymap_wrapper.get_key(request, &secp).unwrap();
        assert!(result.is_none(), "Should return None when fingerprint doesn't match");
        let result = keymap_wrapper.get_key(request_x, &secp).unwrap();
        assert!(result.is_none(), "Should return None even on error");
    }

    #[test]
    fn get_key_xpriv_with_key_origin() {
        // `get_key` should match the request against the key origin, strip the origin prefix
        // from the requested path, and derive the rest from the extended key.
        struct TestCase {
            /// Scenario description.
            name: &'static str,
            /// The descriptor under test.
            descriptor: &'static str,
            /// Requested key source: `(master fingerprint, path from the master)`.
            key_request: (&'static str, &'static str),
            /// Expected steps from the extended key (requested path minus the key origin).
            exp_derivation_path: &'static str,
        }

        let cases = [
            TestCase {
                name: "bare wildcard",
                descriptor: "wpkh([d34db33f/84h/1h/0h]tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/*)",
                key_request: ("d34db33f", "84'/1'/0'/0"),
                exp_derivation_path: "0",
            },
            TestCase {
                name: "single fixed step",
                descriptor: "wpkh([d34db33f/84h/1h/0h]tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/0)",
                key_request: ("d34db33f", "84'/1'/0'/0"),
                exp_derivation_path: "0",
            },
            TestCase {
                name: "fixed step then wildcard",
                descriptor: "wpkh([d34db33f/84h/1h/0h]tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/0/*)",
                key_request: ("d34db33f", "84'/1'/0'/0/5"),
                exp_derivation_path: "0/5",
            },
        ];

        let secp = Secp256k1::new();
        let xpriv = Xpriv::from_str("tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS").unwrap();
        for test_case in &cases {
            let exp_derivation_path =
                DerivationPath::from_str(test_case.exp_derivation_path).unwrap();
            let exp_private_key = xpriv
                .derive_priv(&secp, &exp_derivation_path)
                .unwrap()
                .to_priv();

            let (_, keymap) = Descriptor::parse_descriptor(&secp, test_case.descriptor).unwrap();
            let keymap_wrapper = KeyMapWrapper::from(keymap);

            let (fingerprint, derivation_path) = test_case.key_request;
            let key_request = KeyRequest::Bip32((
                Fingerprint::from_str(fingerprint).unwrap(),
                DerivationPath::from_str(derivation_path).unwrap(),
            ));

            let private_key = keymap_wrapper
                .get_key(key_request, &secp)
                .expect("get_key SHOULD NOT fail")
                .expect("get_key SHOULD get a `PrivateKey`");

            assert_eq!(private_key, exp_private_key, "{}", test_case.name);
        }
    }

    #[test]
    fn get_key_xpriv_with_key_origin_and_non_matching_path() {
        let secp = Secp256k1::new();

        // descriptor with a fixed derivation index of `0`.
        let descriptor = "wpkh([d34db33f/84h/1h/0h]tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/0)";
        let (_, keymap) = Descriptor::parse_descriptor(&secp, descriptor).unwrap();
        let keymap_wrapper = KeyMapWrapper::from(keymap);

        // the key_request has the correct `key_origin`, but the requested derivation index (`5`) does not match the
        // descriptor's fixed derivation index (`0`), so the descriptor does not own this key.
        let key_request = KeyRequest::Bip32((
            Fingerprint::from_str("d34db33f").unwrap(),
            DerivationPath::from_str("84'/1'/0'/5").unwrap(),
        ));

        let private_key = keymap_wrapper
            .get_key(key_request, &secp)
            .expect("get_key SHOULD NOT fail!");

        assert!(
            private_key.is_none(),
            "SHOULD get NO private key when the requested path does not match the descriptor"
        );
    }
}
