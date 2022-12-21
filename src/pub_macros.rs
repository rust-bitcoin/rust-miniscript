// SPDX-License-Identifier: CC0-1.0

//! Macros exported by the miniscript crate
//!

/// Macro for failing translation for other associated types.
/// Handy for testing String -> concrete keys as we don't want to specify these
/// functions repeatedly.
///
/// This macro is handy when dealing with scripts that are only contain keys.
/// See also [`crate::translate_hash_clone`]
/// ```rust
/// use miniscript::{bitcoin::PublicKey, policy::concrete::Policy, Translator, hash256};
/// use std::str::FromStr;
/// use miniscript::translate_hash_fail;
/// use std::collections::HashMap;
/// use miniscript::bitcoin::hashes::{sha256, hash160, ripemd160};
/// let alice_key = "0270cf3c71f65a3d93d285d9149fddeeb638f87a2d4d8cf16c525f71c417439777";
/// let bob_key = "02f43b15c50a436f5335dbea8a64dd3b4e63e34c3b50c42598acb5f4f336b5d2fb";
/// let placeholder_policy = Policy::<String>::from_str("and(pk(alice_key),pk(bob_key))").unwrap();
///
/// // Information to translator abstract String type keys to concrete bitcoin::PublicKey.
/// // In practice, wallets would map from String key names to BIP32 keys
/// struct StrPkTranslator {
///     pk_map: HashMap<String, bitcoin::PublicKey>
/// }
///
/// // If we also wanted to provide mapping of other associated types(sha256, older etc),
/// // we would use the general Translator Trait.
/// impl Translator<String, bitcoin::PublicKey, ()> for StrPkTranslator {
///     // Provides the translation public keys P -> Q
///     fn pk(&mut self, pk: &String) -> Result<bitcoin::PublicKey, ()> {
///         self.pk_map.get(pk).copied().ok_or(()) // Dummy Err
///     }
///
///     // Fail for hash types
///     translate_hash_fail!(String, bitcoin::PublicKey, ());
/// }
///
/// let mut pk_map = HashMap::new();
/// pk_map.insert(String::from("alice_key"), bitcoin::PublicKey::from_str(alice_key).unwrap());
/// pk_map.insert(String::from("bob_key"), bitcoin::PublicKey::from_str(bob_key).unwrap());
/// let mut t = StrPkTranslator { pk_map: pk_map };
/// ```
#[macro_export]
macro_rules! translate_hash_fail {
    ($source: ty, $target:ty, $error_ty: ty) => {
        fn sha256(
            &mut self,
            _sha256: &<$source as $crate::MiniscriptKey>::Sha256,
        ) -> Result<<$target as $crate::MiniscriptKey>::Sha256, $error_ty> {
            panic!("Called sha256 on translate_only_pk")
        }

        fn hash256(
            &mut self,
            _hash256: &<$source as $crate::MiniscriptKey>::Hash256,
        ) -> Result<<$target as $crate::MiniscriptKey>::Hash256, $error_ty> {
            panic!("Called hash256 on translate_only_pk")
        }

        fn hash160(
            &mut self,
            _hash160: &<$source as $crate::MiniscriptKey>::Hash160,
        ) -> Result<<$target as $crate::MiniscriptKey>::Hash160, $error_ty> {
            panic!("Called hash160 on translate_only_pk")
        }

        fn ripemd160(
            &mut self,
            _ripemd160: &<$source as $crate::MiniscriptKey>::Ripemd160,
        ) -> Result<<$target as $crate::MiniscriptKey>::Ripemd160, $error_ty> {
            panic!("Called ripemd160 on translate_only_pk")
        }
    };
}

/// Macro for translation of associated types where the associated type is the same
/// Handy for Derived -> concrete keys where the associated types are the same.
///
/// Writing the complete translator trait is tedious. This macro is handy when
/// we are not trying the associated types for hash160, ripemd160, hash256 and
/// sha256.
///
/// See also [`crate::translate_hash_fail`]
#[macro_export]
macro_rules! translate_hash_clone {
    ($source: ty, $target:ty, $error_ty: ty) => {
        fn sha256(
            &mut self,
            sha256: &<$source as $crate::MiniscriptKey>::Sha256,
        ) -> Result<<$target as $crate::MiniscriptKey>::Sha256, $error_ty> {
            Ok((*sha256).into())
        }

        fn hash256(
            &mut self,
            hash256: &<$source as $crate::MiniscriptKey>::Hash256,
        ) -> Result<<$target as $crate::MiniscriptKey>::Hash256, $error_ty> {
            Ok((*hash256).into())
        }

        fn hash160(
            &mut self,
            hash160: &<$source as $crate::MiniscriptKey>::Hash160,
        ) -> Result<<$target as $crate::MiniscriptKey>::Hash160, $error_ty> {
            Ok((*hash160).into())
        }

        fn ripemd160(
            &mut self,
            ripemd160: &<$source as $crate::MiniscriptKey>::Ripemd160,
        ) -> Result<<$target as $crate::MiniscriptKey>::Ripemd160, $error_ty> {
            Ok((*ripemd160).into())
        }
    };
}
