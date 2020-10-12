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

use miniscript::types::extra_props::{
    MAX_OPS_PER_SCRIPT, MAX_STANDARD_P2WSH_SCRIPT_SIZE, MAX_STANDARD_P2WSH_STACK_ITEMS,
};
use std::fmt;
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
    /// The Miniscript corresponding Script would be larger than `MAX_STANDARD_P2WSH_SCRIPT_SIZE`
    /// bytes.
    MaxWitnessScriptSizeExceeded,
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
        }
    }
}

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
    fn check_frag_non_malleable<Pk: MiniscriptKey, Ctx: ScriptContext>(
        _frag: &Terminal<Pk, Ctx>,
    ) -> Result<(), ScriptContextError>;

    /// Depending on script Context, some of the Miniscripts might not be valid.
    /// For example, in Segwit Context requiring a too high number of stack elements
    /// for a satisfaction path is non-standard.
    /// In both legacy and Segwit contexts using more than 201 OPs is invalid by consensus.
    fn check_ms_validity<Pk: MiniscriptKey, Ctx: ScriptContext>(
        ms: &Miniscript<Pk, Ctx>,
    ) -> Result<(), ScriptContextError>;
}

/// Legacy ScriptContext
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum Legacy {}

impl ScriptContext for Legacy {
    fn check_frag_non_malleable<Pk: MiniscriptKey, Ctx: ScriptContext>(
        frag: &Terminal<Pk, Ctx>,
    ) -> Result<(), ScriptContextError> {
        match *frag {
            Terminal::PkH(ref _pkh) => Err(ScriptContextError::MalleablePkH),
            Terminal::OrI(ref _a, ref _b) => Err(ScriptContextError::MalleableOrI),
            Terminal::DupIf(ref _ms) => Err(ScriptContextError::MalleableDupIf),
            _ => Ok(()),
        }
    }

    fn check_ms_validity<Pk: MiniscriptKey, Ctx: ScriptContext>(
        ms: &Miniscript<Pk, Ctx>,
    ) -> Result<(), ScriptContextError> {
        if let Some(op_count) = ms.ext.ops_count_sat {
            if op_count > MAX_OPS_PER_SCRIPT {
                return Err(ScriptContextError::MaxOpCountExceeded);
            }
        }

        Ok(())
    }
}

/// Segwitv0 ScriptContext
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum Segwitv0 {}

impl ScriptContext for Segwitv0 {
    fn check_frag_non_malleable<Pk: MiniscriptKey, Ctx: ScriptContext>(
        _frag: &Terminal<Pk, Ctx>,
    ) -> Result<(), ScriptContextError> {
        Ok(())
    }

    fn check_ms_validity<Pk: MiniscriptKey, Ctx: ScriptContext>(
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

        if ms.ext.pk_cost > MAX_STANDARD_P2WSH_SCRIPT_SIZE {
            return Err(ScriptContextError::MaxWitnessScriptSizeExceeded);
        }

        if let Some(op_count) = ms.ext.ops_count_sat {
            if op_count > MAX_OPS_PER_SCRIPT {
                return Err(ScriptContextError::MaxOpCountExceeded);
            }
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
}

/// Any ScriptContext. None of the checks should ever be invokde from
/// under this context.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum Any {}
impl ScriptContext for Any {
    fn check_frag_non_malleable<Pk: MiniscriptKey, Ctx: ScriptContext>(
        _frag: &Terminal<Pk, Ctx>,
    ) -> Result<(), ScriptContextError> {
        unreachable!()
    }

    fn check_ms_validity<Pk: MiniscriptKey, Ctx: ScriptContext>(
        _ms: &Miniscript<Pk, Ctx>,
    ) -> Result<(), ScriptContextError> {
        unreachable!()
    }
}

impl Any {
    pub(crate) fn from_legacy<Pk: MiniscriptKey>(
        ms: &Miniscript<Pk, Legacy>,
    ) -> &Miniscript<Pk, Any> {
        // The fields Miniscript<Pk, Legacy> and Miniscript<Any, Legacy> only
        // differ in PhantomData. This unsafe assumes that the unlerlying byte
        // representation of the both should be the same. There is a Miri test
        // checking the same.
        unsafe {
            use std::mem::transmute;
            transmute::<&Miniscript<Pk, Legacy>, &Miniscript<Pk, Any>>(ms)
        }
    }

    pub(crate) fn from_segwitv0<Pk: MiniscriptKey>(
        ms: &Miniscript<Pk, Segwitv0>,
    ) -> &Miniscript<Pk, Any> {
        // The fields Miniscript<Pk, Legacy> and Miniscript<Any, Legacy> only
        // differ in PhantomData. This unsafe assumes that the unlerlying byte
        // representation of the both should be the same. There is a Miri test
        // checking the same.
        unsafe {
            use std::mem::transmute;
            transmute::<&Miniscript<Pk, Segwitv0>, &Miniscript<Pk, Any>>(ms)
        }
    }
}

/// Private Mod to prevent downstream from implementing this public trait
mod private {
    use super::{Any, Legacy, Segwitv0};

    pub trait Sealed {}

    // Implement for those same types, but no others.
    impl Sealed for Legacy {}
    impl Sealed for Segwitv0 {}
    impl Sealed for Any {}
}

#[cfg(test)]
mod tests {
    use super::{Any, Legacy, Segwitv0};
    use std::str::FromStr;

    use {DummyKey, Miniscript};
    type Segwitv0Script = Miniscript<DummyKey, Segwitv0>;
    type LegacyScript = Miniscript<DummyKey, Legacy>;

    //miri test for unsafe code
    #[test]
    fn miri_test_context_transform() {
        let segwit_ms = Segwitv0Script::from_str("andor(pk(),or_i(and_v(vc:pk_h(),hash160(1111111111111111111111111111111111111111)),older(1008)),pk())").unwrap();
        let legacy_ms = LegacyScript::from_str("andor(pk(),or_i(and_v(vc:pk_h(),hash160(1111111111111111111111111111111111111111)),older(1008)),pk())").unwrap();

        let _any = Any::from_legacy(&legacy_ms);
        let _any = Any::from_segwitv0(&segwit_ms);
    }
}
