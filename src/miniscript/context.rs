// Miniscript
// Written in 2019 by
//     Sanket Kanjalkar and Andrew Poelstra
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

use miniscript::types;
use miniscript::types::extra_props::{
    MAX_OPS_PER_SCRIPT, MAX_SCRIPTSIG_SIZE, MAX_SCRIPT_ELEMENT_SIZE, MAX_SCRIPT_SIZE,
    MAX_STANDARD_P2WSH_SCRIPT_SIZE, MAX_STANDARD_P2WSH_STACK_ITEMS,
};
use std::fmt;
use Error;
use {Miniscript, MiniscriptKey, Terminal};
/// Error for Script Context
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ScriptContextError {
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
    CompressedOnly,
    /// At least one satisfaction path in the Miniscript fragment has more than
    /// `MAX_STANDARD_P2WSH_STACK_ITEMS` (100) witness elements.
    MaxWitnessItemssExceeded,
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
}

impl fmt::Display for ScriptContextError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ScriptContextError::MalleablePkH => write!(f, "PkH is malleable under Legacy rules"),
            ScriptContextError::MalleableOrI => write!(f, "OrI is malleable under Legacy rules"),
            ScriptContextError::MalleableDupIf => {
                write!(f, "DupIf is malleable under Legacy rules")
            }
            ScriptContextError::CompressedOnly => {
                write!(f, "Uncompressed pubkeys not allowed in segwit context")
            }
            ScriptContextError::MaxWitnessItemssExceeded => write!(
                f,
                "At least one spending path in the Miniscript fragment has more \
                 witness items than MAX_STANDARD_P2WSH_STACK_ITEMS.",
            ),
            ScriptContextError::MaxOpCountExceeded => write!(
                f,
                "At least one satisfaction path in the Miniscript fragment contains \
                 more than MAX_OPS_PER_SCRIPT opcodes."
            ),
            ScriptContextError::MaxWitnessScriptSizeExceeded => write!(
                f,
                "The Miniscript corresponding Script would be larger than \
                    MAX_STANDARD_P2WSH_SCRIPT_SIZE bytes."
            ),
            ScriptContextError::MaxRedeemScriptSizeExceeded => write!(
                f,
                "The Miniscript corresponding Script would be larger than \
                MAX_SCRIPT_ELEMENT_SIZE bytes."
            ),
            ScriptContextError::MaxScriptSigSizeExceeded => write!(
                f,
                "At least one satisfaction in Miniscript would be larger than \
                MAX_SCRIPTSIG_SIZE scriptsig"
            ),
        }
    }
}

/// The ScriptContext for Miniscript. Additional type information associated with
/// miniscript that is used for carrying out checks that dependent on the
/// context under which the script is used.
/// For example, disallowing uncompressed keys in Segwit context
pub trait ScriptContext:
    fmt::Debug + Clone + Ord + PartialOrd + Eq + PartialEq + private::Sealed
{
    /// Depending on ScriptContext, fragments can be malleable. For Example,
    /// under Legacy context, PkH is malleable because it is possible to
    /// estimate the cost of satisfaction because of compressed keys
    /// This is currently only used in compiler code for removing malleable
    /// compilations.
    /// This does NOT recursively check if the children of the fragment are
    /// valid or not. Since the compilation proceeds in a leaf to root fashion,
    /// a recursive check is unnecessary.
    fn check_terminal_non_malleable<Pk: MiniscriptKey, Ctx: ScriptContext>(
        _frag: &Terminal<Pk, Ctx>,
    ) -> Result<(), ScriptContextError>;

    /// Depending on script context, the size of a satifaction witness may slightly differ.
    fn max_satisfaction_size<Pk: MiniscriptKey, Ctx: ScriptContext>(
        ms: &Miniscript<Pk, Ctx>,
    ) -> Option<usize>;
    /// Depending on script Context, some of the Terminals might not
    /// be valid under the current consensus rules.
    /// Or some of the script resource limits may have been exceeded.
    /// These miniscripts would never be accepted by the Bitcoin network and hence
    /// it is safe to discard them
    /// For example, in Segwit Context with MiniscriptKey as bitcoin::PublicKey
    /// uncompressed public keys are non-standard and thus invalid.
    /// In LegacyP2SH context, scripts above 520 bytes are invalid.
    /// Post Tapscript upgrade, this would have to consider other nodes.
    /// This does *NOT* recursively check the miniscript fragments.
    fn check_global_consensus_validity<Pk: MiniscriptKey, Ctx: ScriptContext>(
        _ms: &Miniscript<Pk, Ctx>,
    ) -> Result<(), ScriptContextError> {
        Ok(())
    }

    /// Depending on script Context, some of the script resource limits
    /// may have been exceeded under the current bitcoin core policy rules
    /// These miniscripts would never be accepted by the Bitcoin network and hence
    /// it is safe to discard them. (unless explicitly disabled by non-standard flag)
    /// For example, in Segwit Context with MiniscriptKey as bitcoin::PublicKey
    /// scripts over 3600 bytes are invalid.
    /// Post Tapscript upgrade, this would have to consider other nodes.
    /// This does *NOT* recursively check the miniscript fragments.
    fn check_global_policy_validity<Pk: MiniscriptKey, Ctx: ScriptContext>(
        _ms: &Miniscript<Pk, Ctx>,
    ) -> Result<(), ScriptContextError> {
        Ok(())
    }

    /// Consensus rules at the Miniscript satisfaction time.
    /// It is possible that some paths of miniscript may exceed resource limits
    /// and our current satisfier and lifting analysis would not work correctly.
    /// For example, satisfaction path(Legacy/Segwitv0) may require more than 201 opcodes.
    fn check_local_consensus_validity<Pk: MiniscriptKey, Ctx: ScriptContext>(
        _ms: &Miniscript<Pk, Ctx>,
    ) -> Result<(), ScriptContextError> {
        Ok(())
    }

    /// Policy rules at the Miniscript satisfaction time.
    /// It is possible that some paths of miniscript may exceed resource limits
    /// and our current satisfier and lifting analysis would not work correctly.
    /// For example, satisfaction path in Legacy context scriptSig more
    /// than 1650 bytes
    fn check_local_policy_validity<Pk: MiniscriptKey, Ctx: ScriptContext>(
        _ms: &Miniscript<Pk, Ctx>,
    ) -> Result<(), ScriptContextError> {
        Ok(())
    }

    /// Check the consensus + policy(if not disabled) rules that are not based
    /// satisfaction
    fn check_global_validity<Pk: MiniscriptKey, Ctx: ScriptContext>(
        ms: &Miniscript<Pk, Ctx>,
    ) -> Result<(), ScriptContextError> {
        Self::check_global_consensus_validity(ms)?;
        Self::check_global_policy_validity(ms)?;
        Ok(())
    }

    /// Check the consensus + policy(if not disabled) rules including the
    /// ones for satisfaction
    fn check_local_validity<Pk: MiniscriptKey, Ctx: ScriptContext>(
        ms: &Miniscript<Pk, Ctx>,
    ) -> Result<(), ScriptContextError> {
        Self::check_global_consensus_validity(ms)?;
        Self::check_global_consensus_validity(ms)?;
        Self::check_local_policy_validity(ms)?;
        Self::check_local_policy_validity(ms)?;
        Ok(())
    }

    /// Check whether the top-level is type B
    fn top_level_type_check<Pk: MiniscriptKey, Ctx: ScriptContext>(
        ms: &Miniscript<Pk, Ctx>,
    ) -> Result<(), Error> {
        if ms.ty.corr.base != types::Base::B {
            return Err(Error::NonTopLevel(format!("{:?}", ms)));
        }
        Ok(())
    }

    /// Other top level checks that are context specific
    fn other_top_level_checks<Pk: MiniscriptKey, Ctx: ScriptContext>(
        _ms: &Miniscript<Pk, Ctx>,
    ) -> Result<(), Error> {
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
    fn top_level_checks<Pk: MiniscriptKey, Ctx: ScriptContext>(
        ms: &Miniscript<Pk, Ctx>,
    ) -> Result<(), Error> {
        Self::top_level_type_check(ms)?;
        Self::other_top_level_checks(ms)
    }
}

/// Legacy ScriptContext
/// To be used as P2SH scripts
/// For creation of Bare scriptpubkeys, construct the Miniscript
/// under `Bare` ScriptContext
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum Legacy {}

impl ScriptContext for Legacy {
    fn check_terminal_non_malleable<Pk: MiniscriptKey, Ctx: ScriptContext>(
        frag: &Terminal<Pk, Ctx>,
    ) -> Result<(), ScriptContextError> {
        match *frag {
            Terminal::PkH(ref _pkh) => Err(ScriptContextError::MalleablePkH),
            Terminal::OrI(ref _a, ref _b) => Err(ScriptContextError::MalleableOrI),
            Terminal::DupIf(ref _ms) => Err(ScriptContextError::MalleableDupIf),
            _ => Ok(()),
        }
    }

    fn check_global_consensus_validity<Pk: MiniscriptKey, Ctx: ScriptContext>(
        ms: &Miniscript<Pk, Ctx>,
    ) -> Result<(), ScriptContextError> {
        if ms.ext.pk_cost > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(ScriptContextError::MaxRedeemScriptSizeExceeded);
        }
        Ok(())
    }

    fn check_local_consensus_validity<Pk: MiniscriptKey, Ctx: ScriptContext>(
        ms: &Miniscript<Pk, Ctx>,
    ) -> Result<(), ScriptContextError> {
        if let Some(op_count) = ms.ext.ops_count_sat {
            if op_count > MAX_OPS_PER_SCRIPT {
                return Err(ScriptContextError::MaxOpCountExceeded);
            }
        }
        Ok(())
    }

    fn check_local_policy_validity<Pk: MiniscriptKey, Ctx: ScriptContext>(
        ms: &Miniscript<Pk, Ctx>,
    ) -> Result<(), ScriptContextError> {
        if let Some(size) = ms.max_satisfaction_size() {
            if size > MAX_SCRIPTSIG_SIZE {
                return Err(ScriptContextError::MaxScriptSigSizeExceeded);
            }
        }
        // Legacy scripts permit upto 1000 stack elements, 520 bytes consensus limits
        // on P2SH size, it is not possible to reach the 1000 elements limit and hence
        // we do not check it.
        Ok(())
    }

    fn max_satisfaction_size<Pk: MiniscriptKey, Ctx: ScriptContext>(
        ms: &Miniscript<Pk, Ctx>,
    ) -> Option<usize> {
        // The scriptSig cost is the second element of the tuple
        ms.ext.max_sat_size.map(|x| x.1)
    }
}

/// Segwitv0 ScriptContext
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum Segwitv0 {}

impl ScriptContext for Segwitv0 {
    fn check_terminal_non_malleable<Pk: MiniscriptKey, Ctx: ScriptContext>(
        _frag: &Terminal<Pk, Ctx>,
    ) -> Result<(), ScriptContextError> {
        Ok(())
    }

    fn check_global_consensus_validity<Pk: MiniscriptKey, Ctx: ScriptContext>(
        ms: &Miniscript<Pk, Ctx>,
    ) -> Result<(), ScriptContextError> {
        if ms.ext.pk_cost > MAX_SCRIPT_SIZE {
            return Err(ScriptContextError::MaxWitnessScriptSizeExceeded);
        }

        match ms.node {
            Terminal::PkK(ref pk) => {
                if pk.is_uncompressed() {
                    return Err(ScriptContextError::CompressedOnly);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn check_local_consensus_validity<Pk: MiniscriptKey, Ctx: ScriptContext>(
        ms: &Miniscript<Pk, Ctx>,
    ) -> Result<(), ScriptContextError> {
        if let Some(op_count) = ms.ext.ops_count_sat {
            if op_count > MAX_OPS_PER_SCRIPT {
                return Err(ScriptContextError::MaxOpCountExceeded);
            }
        }
        Ok(())
    }

    fn check_global_policy_validity<Pk: MiniscriptKey, Ctx: ScriptContext>(
        ms: &Miniscript<Pk, Ctx>,
    ) -> Result<(), ScriptContextError> {
        if ms.ext.pk_cost > MAX_STANDARD_P2WSH_SCRIPT_SIZE {
            return Err(ScriptContextError::MaxWitnessScriptSizeExceeded);
        }
        Ok(())
    }

    fn check_local_policy_validity<Pk: MiniscriptKey, Ctx: ScriptContext>(
        ms: &Miniscript<Pk, Ctx>,
    ) -> Result<(), ScriptContextError> {
        // We don't need to know if this is actually a p2wsh as the standard satisfaction for
        // other Segwitv0 defined programs all require (much) less than 100 elements.
        // The witness script item is accounted for in max_satisfaction_witness_elements().
        if let Some(max_witness_items) = ms.max_satisfaction_witness_elements() {
            if max_witness_items > MAX_STANDARD_P2WSH_STACK_ITEMS {
                return Err(ScriptContextError::MaxWitnessItemssExceeded);
            }
        }
        Ok(())
    }

    fn max_satisfaction_size<Pk: MiniscriptKey, Ctx: ScriptContext>(
        ms: &Miniscript<Pk, Ctx>,
    ) -> Option<usize> {
        // The witness stack cost is the first element of the tuple
        ms.ext.max_sat_size.map(|x| x.0)
    }
}

/// Bare ScriptContext
/// To be used as raw script pubkeys
/// In general, it is not recommended to use Bare descriptors
/// as they as strongly limited by standardness policies.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum Bare {}

impl ScriptContext for Bare {
    fn check_terminal_non_malleable<Pk: MiniscriptKey, Ctx: ScriptContext>(
        _frag: &Terminal<Pk, Ctx>,
    ) -> Result<(), ScriptContextError> {
        // Bare fragments can't contain miniscript because of standardness rules
        // This function is only used in compiler which already checks the standardness
        // and consensus rules, and because of the limited allowance of bare scripts
        // we need check for malleable scripts
        Ok(())
    }

    fn check_global_consensus_validity<Pk: MiniscriptKey, Ctx: ScriptContext>(
        ms: &Miniscript<Pk, Ctx>,
    ) -> Result<(), ScriptContextError> {
        if ms.ext.pk_cost > MAX_SCRIPT_SIZE {
            return Err(ScriptContextError::MaxWitnessScriptSizeExceeded);
        }
        Ok(())
    }

    fn check_local_consensus_validity<Pk: MiniscriptKey, Ctx: ScriptContext>(
        ms: &Miniscript<Pk, Ctx>,
    ) -> Result<(), ScriptContextError> {
        if let Some(op_count) = ms.ext.ops_count_sat {
            if op_count > MAX_OPS_PER_SCRIPT {
                return Err(ScriptContextError::MaxOpCountExceeded);
            }
        }
        Ok(())
    }

    fn other_top_level_checks<Pk: MiniscriptKey, Ctx: ScriptContext>(
        ms: &Miniscript<Pk, Ctx>,
    ) -> Result<(), Error> {
        match &ms.node {
            Terminal::Check(ref ms) => match &ms.node {
                Terminal::PkH(_pkh) => Ok(()),
                Terminal::PkK(_pk) => Ok(()),
                _ => Err(Error::NonStandardBareScript),
            },
            Terminal::Multi(_k, subs) if subs.len() <= 3 => Ok(()),
            _ => Err(Error::NonStandardBareScript),
        }
    }

    fn max_satisfaction_size<Pk: MiniscriptKey, Ctx: ScriptContext>(
        ms: &Miniscript<Pk, Ctx>,
    ) -> Option<usize> {
        // The witness stack cost is the first element of the tuple
        ms.ext.max_sat_size.map(|x| x.1)
    }
}

/// "No Checks" Context
///
/// Used by the "satisified constraints" iterator, which is intended to read
/// scripts off of the blockchain without doing any sanity checks on them.
/// This context should not be used unless you know what you are doing, as
/// it will panic on any operation that triggers a check (e.g. attempting to
/// lift to an abstract policy).
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum NoChecks {}
impl ScriptContext for NoChecks {
    fn check_terminal_non_malleable<Pk: MiniscriptKey, Ctx: ScriptContext>(
        _frag: &Terminal<Pk, Ctx>,
    ) -> Result<(), ScriptContextError> {
        unreachable!()
    }

    fn check_global_policy_validity<Pk: MiniscriptKey, Ctx: ScriptContext>(
        _ms: &Miniscript<Pk, Ctx>,
    ) -> Result<(), ScriptContextError> {
        unreachable!()
    }

    fn check_global_consensus_validity<Pk: MiniscriptKey, Ctx: ScriptContext>(
        _ms: &Miniscript<Pk, Ctx>,
    ) -> Result<(), ScriptContextError> {
        unreachable!()
    }

    fn check_local_policy_validity<Pk: MiniscriptKey, Ctx: ScriptContext>(
        _ms: &Miniscript<Pk, Ctx>,
    ) -> Result<(), ScriptContextError> {
        unreachable!()
    }

    fn check_local_consensus_validity<Pk: MiniscriptKey, Ctx: ScriptContext>(
        _ms: &Miniscript<Pk, Ctx>,
    ) -> Result<(), ScriptContextError> {
        unreachable!()
    }

    fn max_satisfaction_size<Pk: MiniscriptKey, Ctx: ScriptContext>(
        _ms: &Miniscript<Pk, Ctx>,
    ) -> Option<usize> {
        unreachable!()
    }
}

#[allow(unsafe_code)]
impl NoChecks {
    pub(crate) fn from_legacy<Pk: MiniscriptKey>(
        ms: &Miniscript<Pk, Legacy>,
    ) -> &Miniscript<Pk, NoChecks> {
        // The fields Miniscript<Pk, Legacy> and Miniscript<Pk, NoChecks> only
        // differ in PhantomData. This unsafe assumes that the unlerlying byte
        // representation of the both should be the same. There is a Miri test
        // checking the same.
        unsafe {
            use std::mem::transmute;
            transmute::<&Miniscript<Pk, Legacy>, &Miniscript<Pk, NoChecks>>(ms)
        }
    }

    pub(crate) fn from_segwitv0<Pk: MiniscriptKey>(
        ms: &Miniscript<Pk, Segwitv0>,
    ) -> &Miniscript<Pk, NoChecks> {
        // The fields Miniscript<Pk, Segwitv0> and Miniscript<Pk, NoChecks> only
        // differ in PhantomData. This unsafe assumes that the unlerlying byte
        // representation of the both should be the same. There is a Miri test
        // checking the same.
        unsafe {
            use std::mem::transmute;
            transmute::<&Miniscript<Pk, Segwitv0>, &Miniscript<Pk, NoChecks>>(ms)
        }
    }

    pub(crate) fn from_bare<Pk: MiniscriptKey>(ms: &Miniscript<Pk, Bare>) -> &Miniscript<Pk, NoChecks> {
        // The fields Miniscript<Pk, Bare> and Miniscript<Pk, NoChecks> only
        // differ in PhantomData. This unsafe assumes that the unlerlying byte
        // representation of the both should be the same. There is a Miri test
        // checking the same.
        unsafe {
            use std::mem::transmute;
            transmute::<&Miniscript<Pk, Bare>, &Miniscript<Pk, NoChecks>>(ms)
        }
    }
}

/// Private Mod to prevent downstream from implementing this public trait
mod private {
    use super::{NoChecks, Bare, Legacy, Segwitv0};

    pub trait Sealed {}

    // Implement for those same types, but no others.
    impl Sealed for Bare {}
    impl Sealed for Legacy {}
    impl Sealed for Segwitv0 {}
    impl Sealed for NoChecks {}
}

#[cfg(test)]
mod tests {
    use super::{NoChecks, Bare, Legacy, Segwitv0};

    use {DummyKey, Miniscript};
    type Segwitv0Script = Miniscript<DummyKey, Segwitv0>;
    type LegacyScript = Miniscript<DummyKey, Legacy>;
    type BareScript = Miniscript<DummyKey, Bare>;

    //miri test for unsafe code
    #[test]
    fn miri_test_context_transform() {
        let segwit_ms = Segwitv0Script::from_str_insane("andor(pk(),or_i(and_v(vc:pk_h(),hash160(1111111111111111111111111111111111111111)),older(1008)),pk())").unwrap();
        let legacy_ms = LegacyScript::from_str_insane("andor(pk(),or_i(and_v(vc:pk_h(),hash160(1111111111111111111111111111111111111111)),older(1008)),pk())").unwrap();
        let bare_ms = BareScript::from_str_insane("multi(2,,,)").unwrap();

        let _any = NoChecks::from_legacy(&legacy_ms);
        let _any = NoChecks::from_segwitv0(&segwit_ms);
        let _any = NoChecks::from_bare(&bare_ms);
    }
}
