// Written in 2019 by Sanket Kanjalkar and Andrew Poelstra
// SPDX-License-Identifier: CC0-1.0

use core::{fmt, hash};
#[cfg(feature = "std")]
use std::error;

use bitcoin::constants::MAX_BLOCK_WEIGHT;
use bitcoin::hashes::{hash160, ripemd160, sha256};
/// `ScriptContextError` alias for backwards compatability and to reduce potential naming conflicts.
pub use ContextError as ScriptContextError;

use super::decode::ParseableKey;
use crate::miniscript::limits::{
    MAX_OPS_PER_SCRIPT, MAX_PUBKEYS_PER_MULTISIG, MAX_SCRIPTSIG_SIZE, MAX_SCRIPT_ELEMENT_SIZE,
    MAX_SCRIPT_SIZE, MAX_STACK_SIZE, MAX_STANDARD_P2WSH_SCRIPT_SIZE,
    MAX_STANDARD_P2WSH_STACK_ITEMS,
};
use crate::miniscript::types;
use crate::prelude::*;
use crate::util::witness_to_scriptsig;
use crate::{hash256, Error, ForEachKey, Key, Miniscript, Terminal};

/// Error for Script Context
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ContextError {
    /// Script Context does not permit PkH for non-malleability
    /// It is not possible to estimate the pubkey size at the creation
    /// time because of uncompressed pubkeys
    MalleablePkH,
    /// Script Context does not permit OrI for non-malleability
    /// Legacy fragments allow non-minimal IF which results in malleability
    MalleableOrI,
    /// Script Context does not permit DupIf for non-malleability
    /// Legacy fragments allow non-minimal IF which results in malleability
    MalleableDupIf,
    /// Only Compressed keys allowed under current descriptor
    /// Segwitv0 fragments do not allow uncompressed pubkeys
    CompressedOnly(String),
    /// XOnly keys are only allowed in Tap context
    /// The first element is key, and second element is current script context
    XOnlyKeysNotAllowed(String, &'static str),
    /// Tapscript descriptors cannot contain uncompressed keys
    /// Tap context can contain compressed or xonly
    UncompressedKeysNotAllowed,
    /// At least one satisfaction path in the Miniscript fragment has more than
    /// `MAX_STANDARD_P2WSH_STACK_ITEMS` (100) witness elements.
    MaxWitnessItemssExceeded { actual: usize, limit: usize },
    /// At least one satisfaction path in the Miniscript fragment contains more
    /// than `MAX_OPS_PER_SCRIPT`(201) opcodes.
    MaxOpCountExceeded,
    /// The Miniscript(under segwit context) corresponding
    /// Script would be larger than `MAX_STANDARD_P2WSH_SCRIPT_SIZE` bytes.
    MaxWitnessScriptSizeExceeded,
    /// The Miniscript (under p2sh context) corresponding Script would be
    /// larger than `MAX_SCRIPT_ELEMENT_SIZE` bytes.
    MaxRedeemScriptSizeExceeded,
    /// The policy rules of bitcoin core only permit Script size upto 1650 bytes
    MaxScriptSigSizeExceeded,
    /// Impossible to satisfy the miniscript under the current context
    ImpossibleSatisfaction,
    /// No Multi Node in Taproot context
    TaprootMultiDisabled,
    /// Stack size exceeded in script execution
    StackSizeLimitExceeded { actual: usize, limit: usize },
    /// More than 20 keys in a Multi fragment
    CheckMultiSigLimitExceeded,
    /// MultiA is only allowed in post tapscript
    MultiANotAllowed,
}

#[cfg(feature = "std")]
impl error::Error for ContextError {
    fn cause(&self) -> Option<&dyn error::Error> {
        use self::ContextError::*;

        match self {
            MalleablePkH
            | MalleableOrI
            | MalleableDupIf
            | CompressedOnly(_)
            | XOnlyKeysNotAllowed(_, _)
            | UncompressedKeysNotAllowed
            | MaxWitnessItemssExceeded { .. }
            | MaxOpCountExceeded
            | MaxWitnessScriptSizeExceeded
            | MaxRedeemScriptSizeExceeded
            | MaxScriptSigSizeExceeded
            | ImpossibleSatisfaction
            | TaprootMultiDisabled
            | StackSizeLimitExceeded { .. }
            | CheckMultiSigLimitExceeded
            | MultiANotAllowed => None,
        }
    }
}

impl fmt::Display for ContextError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ContextError::MalleablePkH => write!(f, "PkH is malleable under Legacy rules"),
            ContextError::MalleableOrI => write!(f, "OrI is malleable under Legacy rules"),
            ContextError::MalleableDupIf => {
                write!(f, "DupIf is malleable under Legacy rules")
            }
            ContextError::CompressedOnly(ref pk) => {
                write!(
                    f,
                    "Only Compressed pubkeys are allowed in segwit context. Found {}",
                    pk
                )
            }
            ContextError::XOnlyKeysNotAllowed(ref pk, ref ctx) => {
                write!(f, "x-only key {} not allowed in {}", pk, ctx)
            }
            ContextError::UncompressedKeysNotAllowed => {
                write!(
                    f,
                    "uncompressed keys cannot be used in Taproot descriptors."
                )
            }
            ContextError::MaxWitnessItemssExceeded { actual, limit } => write!(
                f,
                "At least one spending path in the Miniscript fragment has {} more \
                 witness items than limit {}.",
                actual, limit
            ),
            ContextError::MaxOpCountExceeded => write!(
                f,
                "At least one satisfaction path in the Miniscript fragment contains \
                 more than MAX_OPS_PER_SCRIPT opcodes."
            ),
            ContextError::MaxWitnessScriptSizeExceeded => write!(
                f,
                "The Miniscript corresponding Script would be larger than \
                    MAX_STANDARD_P2WSH_SCRIPT_SIZE bytes."
            ),
            ContextError::MaxRedeemScriptSizeExceeded => write!(
                f,
                "The Miniscript corresponding Script would be larger than \
                MAX_SCRIPT_ELEMENT_SIZE bytes."
            ),
            ContextError::MaxScriptSigSizeExceeded => write!(
                f,
                "At least one satisfaction in Miniscript would be larger than \
                MAX_SCRIPTSIG_SIZE scriptsig"
            ),
            ContextError::ImpossibleSatisfaction => {
                write!(
                    f,
                    "Impossible to satisfy Miniscript under the current context"
                )
            }
            ContextError::TaprootMultiDisabled => {
                write!(f, "Invalid use of Multi node in taproot context")
            }
            ContextError::StackSizeLimitExceeded { actual, limit } => {
                write!(
                    f,
                    "Stack limit {} can exceed the allowed limit {} in at least one script path during script execution",
                    actual, limit
                )
            }
            ContextError::CheckMultiSigLimitExceeded => {
                write!(
                    f,
                    "CHECkMULTISIG ('multi()' descriptor) only supports up to 20 pubkeys"
                )
            }
            ContextError::MultiANotAllowed => {
                write!(f, "Multi a(CHECKSIGADD) only allowed post tapscript")
            }
        }
    }
}

/// The Context for Miniscript. Additional type information associated with
/// miniscript that is used for carrying out checks that dependent on the
/// context under which the script is used.
/// For example, disallowing uncompressed keys in Segwit context
pub trait Context:
    fmt::Debug + Clone + Ord + PartialOrd + Eq + PartialEq + hash::Hash + private::Sealed
where
    Self::Key: Key<Sha256 = sha256::Hash>,
    Self::Key: Key<Hash256 = hash256::Hash>,
    Self::Key: Key<Ripemd160 = ripemd160::Hash>,
    Self::Key: Key<Hash160 = hash160::Hash>,
{
    /// The consensus key associated with the type. Must be a parseable key
    type Key: ParseableKey;
    /// Depending on Context, fragments can be malleable. For Example,
    /// under Legacy context, PkH is malleable because it is possible to
    /// estimate the cost of satisfaction because of compressed keys
    /// This is currently only used in compiler code for removing malleable
    /// compilations.
    /// This does NOT recursively check if the children of the fragment are
    /// valid or not. Since the compilation proceeds in a leaf to root fashion,
    /// a recursive check is unnecessary.
    fn check_terminal_non_malleable<Pk: Key>(
        _frag: &Terminal<Pk, Self>,
    ) -> Result<(), ContextError>;

    /// Check whether the given satisfaction is valid under the Context
    /// For example, segwit satisfactions may fail if the witness len is more
    /// 3600 or number of stack elements are more than 100.
    fn check_witness<Pk: Key>(_witness: &[Vec<u8>]) -> Result<(), ContextError> {
        // Only really need to do this for segwitv0 and legacy
        // Bare is already restrcited by standardness rules
        // and would reach these limits.
        Ok(())
    }

    /// Each context has slightly different rules on what Pks are allowed in descriptors
    /// Legacy/Bare does not allow x_only keys
    /// Segwit does not allow uncompressed keys and x_only keys
    /// Tapscript does not allow uncompressed keys
    fn check_pk<Pk: Key>(pk: &Pk) -> Result<(), ContextError>;

    /// Depending on script context, the size of a satifaction witness may slightly differ.
    fn max_satisfaction_size<Pk: Key>(ms: &Miniscript<Pk, Self>) -> Option<usize>;
    /// Depending on script Context, some of the Terminals might not
    /// be valid under the current consensus rules.
    /// Or some of the script resource limits may have been exceeded.
    /// These miniscripts would never be accepted by the Bitcoin network and hence
    /// it is safe to discard them
    /// For example, in Segwit Context with Key as bitcoin::PublicKey
    /// uncompressed public keys are non-standard and thus invalid.
    /// In LegacyP2SH context, scripts above 520 bytes are invalid.
    /// Post Tapscript upgrade, this would have to consider other nodes.
    /// This does *NOT* recursively check the miniscript fragments.
    fn check_global_consensus_validity<Pk: Key>(
        _ms: &Miniscript<Pk, Self>,
    ) -> Result<(), ContextError> {
        Ok(())
    }

    /// Depending on script Context, some of the script resource limits
    /// may have been exceeded under the current bitcoin core policy rules
    /// These miniscripts would never be accepted by the Bitcoin network and hence
    /// it is safe to discard them. (unless explicitly disabled by non-standard flag)
    /// For example, in Segwit Context with Key as bitcoin::PublicKey
    /// scripts over 3600 bytes are invalid.
    /// Post Tapscript upgrade, this would have to consider other nodes.
    /// This does *NOT* recursively check the miniscript fragments.
    fn check_global_policy_validity<Pk: Key>(
        _ms: &Miniscript<Pk, Self>,
    ) -> Result<(), ContextError> {
        Ok(())
    }

    /// Consensus rules at the Miniscript satisfaction time.
    /// It is possible that some paths of miniscript may exceed resource limits
    /// and our current satisfier and lifting analysis would not work correctly.
    /// For example, satisfaction path(Legacy/Segwitv0) may require more than 201 opcodes.
    fn check_local_consensus_validity<Pk: Key>(
        _ms: &Miniscript<Pk, Self>,
    ) -> Result<(), ContextError> {
        Ok(())
    }

    /// Policy rules at the Miniscript satisfaction time.
    /// It is possible that some paths of miniscript may exceed resource limits
    /// and our current satisfier and lifting analysis would not work correctly.
    /// For example, satisfaction path in Legacy context scriptSig more
    /// than 1650 bytes
    fn check_local_policy_validity<Pk: Key>(
        _ms: &Miniscript<Pk, Self>,
    ) -> Result<(), ContextError> {
        Ok(())
    }

    /// Check the consensus + policy(if not disabled) rules that are not based
    /// satisfaction
    fn check_global_validity<Pk: Key>(ms: &Miniscript<Pk, Self>) -> Result<(), ContextError> {
        Self::check_global_consensus_validity(ms)?;
        Self::check_global_policy_validity(ms)?;
        Ok(())
    }

    /// Check the consensus + policy(if not disabled) rules including the
    /// ones for satisfaction
    fn check_local_validity<Pk: Key>(ms: &Miniscript<Pk, Self>) -> Result<(), ContextError> {
        Self::check_global_consensus_validity(ms)?;
        Self::check_global_policy_validity(ms)?;
        Self::check_local_consensus_validity(ms)?;
        Self::check_local_policy_validity(ms)?;
        Ok(())
    }

    /// Check whether the top-level is type B
    fn top_level_type_check<Pk: Key>(ms: &Miniscript<Pk, Self>) -> Result<(), Error> {
        if ms.ty.corr.base != types::Base::B {
            return Err(Error::NonTopLevel(format!("{:?}", ms)));
        }
        // (Ab)use `for_each_key` to record the number of derivation paths a multipath key has.
        #[derive(PartialEq)]
        enum MultipathLenChecker {
            SinglePath,
            MultipathLen(usize),
            LenMismatch,
        }

        let mut checker = MultipathLenChecker::SinglePath;
        ms.for_each_key(|key| {
            match key.num_der_paths() {
                0 | 1 => {}
                n => match checker {
                    MultipathLenChecker::SinglePath => {
                        checker = MultipathLenChecker::MultipathLen(n);
                    }
                    MultipathLenChecker::MultipathLen(len) => {
                        if len != n {
                            checker = MultipathLenChecker::LenMismatch;
                        }
                    }
                    MultipathLenChecker::LenMismatch => {}
                },
            }
            true
        });

        if checker == MultipathLenChecker::LenMismatch {
            return Err(Error::MultipathDescLenMismatch);
        }
        Ok(())
    }

    /// Other top level checks that are context specific
    fn other_top_level_checks<Pk: Key>(_ms: &Miniscript<Pk, Self>) -> Result<(), Error> {
        Ok(())
    }

    /// Check top level consensus rules.
    // All the previous check_ were applied at each fragment while parsing script
    // Because if any of sub-miniscripts failed the reource level check, the entire
    // miniscript would also be invalid. However, there are certain checks like
    // in Bare context, only c:pk(key) (P2PK),
    // c:pk_h(key) (P2PKH), and thresh_m(k,...) up to n=3 are allowed
    // that are only applicable at the top-level
    // We can also combine the top-level check for Base::B here
    // even though it does not depend on context, but helps in cleaner code
    fn top_level_checks<Pk: Key>(ms: &Miniscript<Pk, Self>) -> Result<(), Error> {
        Self::top_level_type_check(ms)?;
        Self::other_top_level_checks(ms)
    }

    /// The type of signature required for satisfaction
    // We need to context decide whether the serialize pk to 33 byte or 32 bytes.
    // And to decide which type of signatures to look for during satisfaction
    fn sig_type() -> SigType;

    /// Get the len of public key when serialized based on context
    /// Note that this includes the serialization prefix. Returns
    /// 34/66 for Bare/Legacy based on key compressedness
    /// 34 for Segwitv0, 33 for Tap
    fn pk_len<Pk: Key>(pk: &Pk) -> usize;

    /// Local helper function to display error messages with context
    fn name_str() -> &'static str;
}

/// Signature algorithm type
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum SigType {
    /// Ecdsa signature
    Ecdsa,
    /// Schnorr Signature
    Schnorr,
}

/// Legacy Context
/// To be used as P2SH scripts
/// For creation of Bare scriptpubkeys, construct the Miniscript
/// under `Bare` Context
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Legacy {}

impl Context for Legacy {
    type Key = bitcoin::PublicKey;
    fn check_terminal_non_malleable<Pk: Key>(
        frag: &Terminal<Pk, Self>,
    ) -> Result<(), ContextError> {
        match *frag {
            Terminal::PkH(ref _pkh) => Err(ContextError::MalleablePkH),
            Terminal::RawPkH(ref _pk) => Err(ContextError::MalleablePkH),
            Terminal::OrI(ref _a, ref _b) => Err(ContextError::MalleableOrI),
            Terminal::DupIf(ref _ms) => Err(ContextError::MalleableDupIf),
            _ => Ok(()),
        }
    }

    // Only compressed and uncompressed public keys are allowed in Legacy context
    fn check_pk<Pk: Key>(pk: &Pk) -> Result<(), ContextError> {
        if pk.is_x_only_key() {
            Err(ContextError::XOnlyKeysNotAllowed(
                pk.to_string(),
                Self::name_str(),
            ))
        } else {
            Ok(())
        }
    }

    fn check_witness<Pk: Key>(witness: &[Vec<u8>]) -> Result<(), ContextError> {
        // In future, we could avoid by having a function to count only
        // len of script instead of converting it.
        if witness_to_scriptsig(witness).len() > MAX_SCRIPTSIG_SIZE {
            return Err(ContextError::MaxScriptSigSizeExceeded);
        }
        Ok(())
    }

    fn check_global_consensus_validity<Pk: Key>(
        ms: &Miniscript<Pk, Self>,
    ) -> Result<(), ContextError> {
        if ms.ext.pk_cost > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(ContextError::MaxRedeemScriptSizeExceeded);
        }

        match ms.node {
            Terminal::PkK(ref pk) => Self::check_pk(pk),
            Terminal::Multi(_k, ref pks) => {
                if pks.len() > MAX_PUBKEYS_PER_MULTISIG {
                    return Err(ContextError::CheckMultiSigLimitExceeded);
                }
                for pk in pks.iter() {
                    Self::check_pk(pk)?;
                }
                Ok(())
            }
            Terminal::MultiA(..) => Err(ContextError::MultiANotAllowed),
            _ => Ok(()),
        }
    }

    fn check_local_consensus_validity<Pk: Key>(
        ms: &Miniscript<Pk, Self>,
    ) -> Result<(), ContextError> {
        match ms.ext.ops.op_count() {
            None => Err(ContextError::MaxOpCountExceeded),
            Some(op_count) if op_count > MAX_OPS_PER_SCRIPT => {
                Err(ContextError::MaxOpCountExceeded)
            }
            _ => Ok(()),
        }
    }

    fn check_local_policy_validity<Pk: Key>(ms: &Miniscript<Pk, Self>) -> Result<(), ContextError> {
        // Legacy scripts permit upto 1000 stack elements, 520 bytes consensus limits
        // on P2SH size, it is not possible to reach the 1000 elements limit and hence
        // we do not check it.
        match ms.max_satisfaction_size() {
            Err(_e) => Err(ContextError::ImpossibleSatisfaction),
            Ok(size) if size > MAX_SCRIPTSIG_SIZE => Err(ContextError::MaxScriptSigSizeExceeded),
            _ => Ok(()),
        }
    }

    fn max_satisfaction_size<Pk: Key>(ms: &Miniscript<Pk, Self>) -> Option<usize> {
        // The scriptSig cost is the second element of the tuple
        ms.ext.max_sat_size.map(|x| x.1)
    }

    fn pk_len<Pk: Key>(pk: &Pk) -> usize {
        if pk.is_uncompressed() {
            66
        } else {
            34
        }
    }

    fn name_str() -> &'static str {
        "Legacy/p2sh"
    }

    fn sig_type() -> SigType {
        SigType::Ecdsa
    }
}

/// Segwitv0 Context
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Segwitv0 {}

impl Context for Segwitv0 {
    type Key = bitcoin::PublicKey;
    fn check_terminal_non_malleable<Pk: Key>(
        _frag: &Terminal<Pk, Self>,
    ) -> Result<(), ContextError> {
        Ok(())
    }

    // No x-only keys or uncompressed keys in Segwitv0 context
    fn check_pk<Pk: Key>(pk: &Pk) -> Result<(), ContextError> {
        if pk.is_uncompressed() {
            Err(ContextError::UncompressedKeysNotAllowed)
        } else if pk.is_x_only_key() {
            Err(ContextError::XOnlyKeysNotAllowed(
                pk.to_string(),
                Self::name_str(),
            ))
        } else {
            Ok(())
        }
    }

    fn check_witness<Pk: Key>(witness: &[Vec<u8>]) -> Result<(), ContextError> {
        if witness.len() > MAX_STANDARD_P2WSH_STACK_ITEMS {
            return Err(ContextError::MaxWitnessItemssExceeded {
                actual: witness.len(),
                limit: MAX_STANDARD_P2WSH_STACK_ITEMS,
            });
        }
        Ok(())
    }

    fn check_global_consensus_validity<Pk: Key>(
        ms: &Miniscript<Pk, Self>,
    ) -> Result<(), ContextError> {
        if ms.ext.pk_cost > MAX_SCRIPT_SIZE {
            return Err(ContextError::MaxWitnessScriptSizeExceeded);
        }

        match ms.node {
            Terminal::PkK(ref pk) => Self::check_pk(pk),
            Terminal::Multi(_k, ref pks) => {
                if pks.len() > MAX_PUBKEYS_PER_MULTISIG {
                    return Err(ContextError::CheckMultiSigLimitExceeded);
                }
                for pk in pks.iter() {
                    Self::check_pk(pk)?;
                }
                Ok(())
            }
            Terminal::MultiA(..) => Err(ContextError::MultiANotAllowed),
            _ => Ok(()),
        }
    }

    fn check_local_consensus_validity<Pk: Key>(
        ms: &Miniscript<Pk, Self>,
    ) -> Result<(), ContextError> {
        match ms.ext.ops.op_count() {
            None => Err(ContextError::MaxOpCountExceeded),
            Some(op_count) if op_count > MAX_OPS_PER_SCRIPT => {
                Err(ContextError::MaxOpCountExceeded)
            }
            _ => Ok(()),
        }
    }

    fn check_global_policy_validity<Pk: Key>(
        ms: &Miniscript<Pk, Self>,
    ) -> Result<(), ContextError> {
        if ms.ext.pk_cost > MAX_STANDARD_P2WSH_SCRIPT_SIZE {
            return Err(ContextError::MaxWitnessScriptSizeExceeded);
        }
        Ok(())
    }

    fn check_local_policy_validity<Pk: Key>(ms: &Miniscript<Pk, Self>) -> Result<(), ContextError> {
        // We don't need to know if this is actually a p2wsh as the standard satisfaction for
        // other Segwitv0 defined programs all require (much) less than 100 elements.
        // The witness script item is accounted for in max_satisfaction_witness_elements().
        match ms.max_satisfaction_witness_elements() {
            // No possible satisfactions
            Err(_e) => Err(ContextError::ImpossibleSatisfaction),
            Ok(max_witness_items) if max_witness_items > MAX_STANDARD_P2WSH_STACK_ITEMS => {
                Err(ContextError::MaxWitnessItemssExceeded {
                    actual: max_witness_items,
                    limit: MAX_STANDARD_P2WSH_STACK_ITEMS,
                })
            }
            _ => Ok(()),
        }
    }

    fn max_satisfaction_size<Pk: Key>(ms: &Miniscript<Pk, Self>) -> Option<usize> {
        // The witness stack cost is the first element of the tuple
        ms.ext.max_sat_size.map(|x| x.0)
    }

    fn pk_len<Pk: Key>(_pk: &Pk) -> usize {
        34
    }

    fn name_str() -> &'static str {
        "Segwitv0"
    }

    fn sig_type() -> SigType {
        SigType::Ecdsa
    }
}

/// Tap Context
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Tap {}

impl Context for Tap {
    type Key = bitcoin::secp256k1::XOnlyPublicKey;
    fn check_terminal_non_malleable<Pk: Key>(
        _frag: &Terminal<Pk, Self>,
    ) -> Result<(), ContextError> {
        // No fragment is malleable in tapscript context.
        // Certain fragments like Multi are invalid, but are not malleable
        Ok(())
    }

    // No uncompressed keys in Tap context
    fn check_pk<Pk: Key>(pk: &Pk) -> Result<(), ContextError> {
        if pk.is_uncompressed() {
            Err(ContextError::UncompressedKeysNotAllowed)
        } else {
            Ok(())
        }
    }

    fn check_witness<Pk: Key>(witness: &[Vec<u8>]) -> Result<(), ContextError> {
        // Note that tapscript has a 1000 limit compared to 100 of segwitv0
        if witness.len() > MAX_STACK_SIZE {
            return Err(ContextError::MaxWitnessItemssExceeded {
                actual: witness.len(),
                limit: MAX_STACK_SIZE,
            });
        }
        Ok(())
    }

    fn check_global_consensus_validity<Pk: Key>(
        ms: &Miniscript<Pk, Self>,
    ) -> Result<(), ContextError> {
        // No script size checks for global consensus rules
        // Should we really check for block limits here.
        // When the transaction sizes get close to block limits,
        // some guarantees are not easy to satisfy because of knapsack
        // constraints
        if ms.ext.pk_cost > MAX_BLOCK_WEIGHT as usize {
            return Err(ContextError::MaxWitnessScriptSizeExceeded);
        }

        match ms.node {
            Terminal::PkK(ref pk) => Self::check_pk(pk),
            Terminal::MultiA(_, ref keys) => {
                for pk in keys.iter() {
                    Self::check_pk(pk)?;
                }
                Ok(())
            }
            Terminal::Multi(..) => Err(ContextError::TaprootMultiDisabled),
            _ => Ok(()),
        }
    }

    fn check_local_consensus_validity<Pk: Key>(
        ms: &Miniscript<Pk, Self>,
    ) -> Result<(), ContextError> {
        // Taproot introduces the concept of sigops budget.
        // All valid miniscripts satisfy the sigops constraint
        // Whenever we add new fragment that uses pk(pk() or multi based on checksigadd)
        // miniscript typing rules ensure that pk when executed successfully has it's
        // own unique signature. That is, there is no way to re-use signatures from one CHECKSIG
        // to another checksig. In other words, for each successfully executed checksig
        // will have it's corresponding 64 bytes signature.
        // sigops budget = witness_script.len() + witness.size() + 50
        // Each signature will cover it's own cost(64 > 50) and thus will will never exceed the budget
        if let (Some(s), Some(h)) = (
            ms.ext.exec_stack_elem_count_sat,
            ms.ext.stack_elem_count_sat,
        ) {
            if s + h > MAX_STACK_SIZE {
                return Err(ContextError::StackSizeLimitExceeded {
                    actual: s + h,
                    limit: MAX_STACK_SIZE,
                });
            }
        }
        Ok(())
    }

    fn check_global_policy_validity<Pk: Key>(
        _ms: &Miniscript<Pk, Self>,
    ) -> Result<(), ContextError> {
        // No script rules, rules are subject to entire tx rules
        Ok(())
    }

    fn check_local_policy_validity<Pk: Key>(
        _ms: &Miniscript<Pk, Self>,
    ) -> Result<(), ContextError> {
        Ok(())
    }

    fn max_satisfaction_size<Pk: Key>(ms: &Miniscript<Pk, Self>) -> Option<usize> {
        // The witness stack cost is the first element of the tuple
        ms.ext.max_sat_size.map(|x| x.0)
    }

    fn sig_type() -> SigType {
        SigType::Schnorr
    }

    fn pk_len<Pk: Key>(_pk: &Pk) -> usize {
        33
    }

    fn name_str() -> &'static str {
        "TapscriptCtx"
    }
}

/// Bare Context
/// To be used as raw script pubkeys
/// In general, it is not recommended to use Bare descriptors
/// as they as strongly limited by standardness policies.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum BareCtx {}

impl Context for BareCtx {
    type Key = bitcoin::PublicKey;
    fn check_terminal_non_malleable<Pk: Key>(
        _frag: &Terminal<Pk, Self>,
    ) -> Result<(), ContextError> {
        // Bare fragments can't contain miniscript because of standardness rules
        // This function is only used in compiler which already checks the standardness
        // and consensus rules, and because of the limited allowance of bare scripts
        // we need check for malleable scripts
        Ok(())
    }

    // No x-only keys in Bare context
    fn check_pk<Pk: Key>(pk: &Pk) -> Result<(), ContextError> {
        if pk.is_x_only_key() {
            Err(ContextError::XOnlyKeysNotAllowed(
                pk.to_string(),
                Self::name_str(),
            ))
        } else {
            Ok(())
        }
    }

    fn check_global_consensus_validity<Pk: Key>(
        ms: &Miniscript<Pk, Self>,
    ) -> Result<(), ContextError> {
        if ms.ext.pk_cost > MAX_SCRIPT_SIZE {
            return Err(ContextError::MaxWitnessScriptSizeExceeded);
        }
        match ms.node {
            Terminal::PkK(ref key) => Self::check_pk(key),
            Terminal::Multi(_k, ref pks) => {
                if pks.len() > MAX_PUBKEYS_PER_MULTISIG {
                    return Err(ContextError::CheckMultiSigLimitExceeded);
                }
                for pk in pks.iter() {
                    Self::check_pk(pk)?;
                }
                Ok(())
            }
            Terminal::MultiA(..) => Err(ContextError::MultiANotAllowed),
            _ => Ok(()),
        }
    }

    fn check_local_consensus_validity<Pk: Key>(
        ms: &Miniscript<Pk, Self>,
    ) -> Result<(), ContextError> {
        match ms.ext.ops.op_count() {
            None => Err(ContextError::MaxOpCountExceeded),
            Some(op_count) if op_count > MAX_OPS_PER_SCRIPT => {
                Err(ContextError::MaxOpCountExceeded)
            }
            _ => Ok(()),
        }
    }

    fn other_top_level_checks<Pk: Key>(ms: &Miniscript<Pk, Self>) -> Result<(), Error> {
        match &ms.node {
            Terminal::Check(ref ms) => match &ms.node {
                Terminal::RawPkH(_pkh) => Ok(()),
                Terminal::PkK(_pk) | Terminal::PkH(_pk) => Ok(()),
                _ => Err(Error::NonStandardBareScript),
            },
            Terminal::Multi(_k, subs) if subs.len() <= 3 => Ok(()),
            _ => Err(Error::NonStandardBareScript),
        }
    }

    fn max_satisfaction_size<Pk: Key>(ms: &Miniscript<Pk, Self>) -> Option<usize> {
        // The witness stack cost is the first element of the tuple
        ms.ext.max_sat_size.map(|x| x.1)
    }

    fn pk_len<Pk: Key>(pk: &Pk) -> usize {
        if pk.is_uncompressed() {
            66
        } else {
            34
        }
    }

    fn name_str() -> &'static str {
        "BareCtx"
    }

    fn sig_type() -> SigType {
        SigType::Ecdsa
    }
}

/// "No Checks Ecdsa" Context
///
/// Used by the "satisified constraints" iterator, which is intended to read
/// scripts off of the blockchain without doing any sanity checks on them.
/// This context should *NOT* be used unless you know what you are doing.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum NoChecks {}
impl Context for NoChecks {
    // todo: When adding support for interpreter, we need a enum with all supported keys here
    type Key = bitcoin::PublicKey;
    fn check_terminal_non_malleable<Pk: Key>(
        _frag: &Terminal<Pk, Self>,
    ) -> Result<(), ContextError> {
        Ok(())
    }

    // No checks in NoChecks
    fn check_pk<Pk: Key>(_pk: &Pk) -> Result<(), ContextError> {
        Ok(())
    }

    fn check_global_policy_validity<Pk: Key>(
        _ms: &Miniscript<Pk, Self>,
    ) -> Result<(), ContextError> {
        Ok(())
    }

    fn check_global_consensus_validity<Pk: Key>(
        _ms: &Miniscript<Pk, Self>,
    ) -> Result<(), ContextError> {
        Ok(())
    }

    fn check_local_policy_validity<Pk: Key>(
        _ms: &Miniscript<Pk, Self>,
    ) -> Result<(), ContextError> {
        Ok(())
    }

    fn check_local_consensus_validity<Pk: Key>(
        _ms: &Miniscript<Pk, Self>,
    ) -> Result<(), ContextError> {
        Ok(())
    }

    fn max_satisfaction_size<Pk: Key>(_ms: &Miniscript<Pk, Self>) -> Option<usize> {
        panic!("Tried to compute a satisfaction size bound on a no-checks ecdsa miniscript")
    }

    fn pk_len<Pk: Key>(_pk: &Pk) -> usize {
        panic!("Tried to compute a pk len bound on a no-checks ecdsa miniscript")
    }

    fn name_str() -> &'static str {
        // Internally used code
        "NochecksEcdsa"
    }

    fn check_witness<Pk: Key>(_witness: &[Vec<u8>]) -> Result<(), ContextError> {
        // Only really need to do this for segwitv0 and legacy
        // Bare is already restrcited by standardness rules
        // and would reach these limits.
        Ok(())
    }

    fn check_global_validity<Pk: Key>(ms: &Miniscript<Pk, Self>) -> Result<(), ContextError> {
        Self::check_global_consensus_validity(ms)?;
        Self::check_global_policy_validity(ms)?;
        Ok(())
    }

    fn check_local_validity<Pk: Key>(ms: &Miniscript<Pk, Self>) -> Result<(), ContextError> {
        Self::check_global_consensus_validity(ms)?;
        Self::check_global_policy_validity(ms)?;
        Self::check_local_consensus_validity(ms)?;
        Self::check_local_policy_validity(ms)?;
        Ok(())
    }

    fn top_level_type_check<Pk: Key>(ms: &Miniscript<Pk, Self>) -> Result<(), Error> {
        if ms.ty.corr.base != types::Base::B {
            return Err(Error::NonTopLevel(format!("{:?}", ms)));
        }
        Ok(())
    }

    fn other_top_level_checks<Pk: Key>(_ms: &Miniscript<Pk, Self>) -> Result<(), Error> {
        Ok(())
    }

    fn top_level_checks<Pk: Key>(ms: &Miniscript<Pk, Self>) -> Result<(), Error> {
        Self::top_level_type_check(ms)?;
        Self::other_top_level_checks(ms)
    }

    fn sig_type() -> SigType {
        SigType::Ecdsa
    }
}

/// Private Mod to prevent downstream from implementing this public trait
mod private {
    use super::{BareCtx, Legacy, NoChecks, Segwitv0, Tap};

    pub trait Sealed {}

    // Implement for those same types, but no others.
    impl Sealed for BareCtx {}
    impl Sealed for Legacy {}
    impl Sealed for Segwitv0 {}
    impl Sealed for Tap {}
    impl Sealed for NoChecks {}
}
