// SPDX-License-Identifier: CC0-1.0

//!  Script Policies
//!
//! Tools for representing Bitcoin scriptpubkeys as abstract spending policies.
//! These may be compiled to Miniscript, which contains extra information to
//! describe the exact representation as Bitcoin script.
//!
//! The format represents EC public keys abstractly to allow wallets to replace
//! these with BIP32 paths, pay-to-contract instructions, etc.

#[cfg(feature = "compiler")]
pub mod compiler;
pub mod concrete;

/// Re-export/re-name to facilitate usage of `Concrete` instead of `concrete::Policy`.
#[rustfmt::skip]
pub use self::concrete::Policy as Concrete;

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use bitcoin::Sequence;
    #[cfg(feature = "compiler")]
    use sync::Arc;

    use super::super::miniscript::context::Segwitv0;
    use super::super::miniscript::Miniscript;
    use super::*;
    #[cfg(feature = "compiler")]
    use crate::descriptor::Tr;
    use crate::lift::{Lift, Lifted};
    use crate::prelude::*;
    #[cfg(feature = "compiler")]
    use crate::{descriptor::TapTree, Descriptor, Tap};

    type ConcretePol = Concrete<String>;
    type SemanticPol = Lifted<String>;

    fn concrete_policy_rtt(s: &str) {
        let conc = ConcretePol::from_str(s).unwrap();
        let output = conc.to_string();
        assert_eq!(s.to_lowercase(), output.to_lowercase());
    }

    fn semantic_policy_rtt(s: &str) {
        let sem = SemanticPol::from_str(s).unwrap();
        let output = sem.normalized().to_string();
        assert_eq!(s.to_lowercase(), output.to_lowercase());
    }

    #[test]
    fn test_timelock_validity() {
        // only height
        assert!(ConcretePol::from_str("after(100)").is_ok());
        // only time
        assert!(ConcretePol::from_str("after(1000000000)").is_ok());
        // disjunction
        assert!(ConcretePol::from_str("or(after(1000000000),after(100))").is_ok());
        // conjunction
        assert!(ConcretePol::from_str("and(after(1000000000),after(100))").is_err());
        // thresh with k = 1
        assert!(ConcretePol::from_str("thresh(1,pk(),after(1000000000),after(100))").is_ok());
        // thresh with k = 2
        assert!(ConcretePol::from_str("thresh(2,after(1000000000),after(100),pk())").is_err());
    }
    #[test]
    fn policy_rtt_tests() {
        concrete_policy_rtt("pk()");
        concrete_policy_rtt("or(1@pk(),1@pk())");
        concrete_policy_rtt("or(99@pk(),1@pk())");
        concrete_policy_rtt("and(pk(),or(99@pk(),1@older(12960)))");

        semantic_policy_rtt("pk()");
        semantic_policy_rtt("or(pk(),pk())");
        semantic_policy_rtt("and(pk(),pk())");

        //fuzzer crashes
        assert!(ConcretePol::from_str("thresh()").is_err());
        assert!(SemanticPol::from_str("thresh(0)").is_err());
        assert!(SemanticPol::from_str("thresh()").is_err());
        concrete_policy_rtt("ripemd160()");
    }

    #[test]
    fn compile_invalid() {
        // Since the root Error does not support Eq type, we have to
        // compare the string representations of the error
        assert_eq!(
            ConcretePol::from_str("thresh(2,pk(),thresh(0))")
                .unwrap_err()
                .to_string(),
            "Threshold k must be greater than 0 and less than or equal to n 0<k<=n"
        );
        assert_eq!(
            ConcretePol::from_str("thresh(2,pk(),thresh(0,pk()))")
                .unwrap_err()
                .to_string(),
            "Threshold k must be greater than 0 and less than or equal to n 0<k<=n"
        );
        assert_eq!(
            ConcretePol::from_str("and(pk())").unwrap_err().to_string(),
            "And policy fragment must take 2 arguments"
        );
        assert_eq!(
            ConcretePol::from_str("or(pk())").unwrap_err().to_string(),
            "Or policy fragment must take 2 arguments"
        );
        assert_eq!(
            ConcretePol::from_str("thresh(3,after(0),pk(),pk())")
                .unwrap_err()
                .to_string(),
            "Time must be greater than 0; n > 0"
        );

        assert_eq!(
            ConcretePol::from_str("thresh(2,older(2147483650),pk(),pk())")
                .unwrap_err()
                .to_string(),
            "Relative/Absolute time must be less than 2^31; n < 2^31"
        );
    }

    //https://github.com/apoelstra/rust-miniscript/issues/41
    #[test]
    fn heavy_nest() {
        let policy_string = "thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk(),thresh(1,pk(),pk(),pk()))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))";
        ConcretePol::from_str(policy_string).unwrap_err();
    }

    #[test]
    fn lift_andor() {
        let key_a: bitcoin::PublicKey =
            "02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e"
                .parse()
                .unwrap();
        let key_b: bitcoin::PublicKey =
            "03b506a1dbe57b4bf48c95e0c7d417b87dd3b4349d290d2e7e9ba72c912652d80a"
                .parse()
                .unwrap();

        let ms_str: Miniscript<bitcoin::PublicKey, Segwitv0> =
            format!("andor(multi(1,{}),older(42),c:pk_k({}))", key_a.inner, key_b.inner)
                .parse()
                .unwrap();
        assert_eq!(
            Lifted::Threshold(
                1,
                vec![
                    Lifted::Threshold(
                        2,
                        vec![Lifted::Key(key_a), Lifted::Older(Sequence::from_height(42))]
                    ),
                    Lifted::Key(key_b)
                ]
            ),
            ms_str.lift().unwrap()
        );
    }

    #[test]
    #[cfg(feature = "compiler")]
    fn taproot_compile() {
        // Trivial single-node compilation
        let unspendable_key: String = "UNSPENDABLE".to_string();
        {
            let policy: Concrete<String> = policy_str!("thresh(2,pk(A),pk(B),pk(C),pk(D))");
            let descriptor = policy.compile_tr(Some(unspendable_key.clone())).unwrap();

            let ms_compilation: Miniscript<String, Tap> = ms_str!("multi_a(2,A,B,C,D)");
            let tree: TapTree<String> = TapTree::Leaf(Arc::new(ms_compilation));
            let expected_descriptor =
                Descriptor::new_tr(unspendable_key.clone(), Some(tree)).unwrap();
            assert_eq!(descriptor, expected_descriptor);
        }

        // Trivial multi-node compilation
        {
            let policy: Concrete<String> = policy_str!("or(and(pk(A),pk(B)),and(pk(C),pk(D)))");
            let descriptor = policy.compile_tr(Some(unspendable_key.clone())).unwrap();

            let left_ms_compilation: Arc<Miniscript<String, Tap>> =
                Arc::new(ms_str!("and_v(v:pk(C),pk(D))"));
            let right_ms_compilation: Arc<Miniscript<String, Tap>> =
                Arc::new(ms_str!("and_v(v:pk(A),pk(B))"));

            let left = TapTree::Leaf(left_ms_compilation);
            let right = TapTree::Leaf(right_ms_compilation);
            let tree = TapTree::combine(left, right);

            let expected_descriptor =
                Descriptor::new_tr(unspendable_key.clone(), Some(tree)).unwrap();
            assert_eq!(descriptor, expected_descriptor);
        }

        {
            // Invalid policy compilation (Duplicate PubKeys)
            let policy: Concrete<String> = policy_str!("or(and(pk(A),pk(B)),and(pk(A),pk(D)))");
            let descriptor = policy.compile_tr(Some(unspendable_key.clone()));

            assert_eq!(descriptor.unwrap_err().to_string(), "Policy contains duplicate keys");
        }

        // Non-trivial multi-node compilation
        {
            let node_policies = [
                "and(pk(A),pk(B))",
                "and(pk(C),older(12960))",
                "pk(D)",
                "pk(E)",
                "thresh(3,pk(F),pk(G),pk(H))",
                "and(and(or(2@pk(I),1@pk(J)),or(1@pk(K),20@pk(L))),pk(M))",
                "pk(N)",
            ];

            // Floating-point precision errors cause the minor errors
            let node_probabilities: [f64; 7] =
                [0.12000002, 0.28, 0.08, 0.12, 0.19, 0.18999998, 0.02];

            let policy: Concrete<String> = policy_str!(
                "{}",
                &format!(
                    "or(4@or(3@{},7@{}),6@thresh(1,or(4@{},6@{}),{},or(9@{},1@{})))",
                    node_policies[0],
                    node_policies[1],
                    node_policies[2],
                    node_policies[3],
                    node_policies[4],
                    node_policies[5],
                    node_policies[6]
                )
            );
            let descriptor = policy.compile_tr(Some(unspendable_key.clone())).unwrap();

            let mut sorted_policy_prob = node_policies
                .iter()
                .zip(node_probabilities.iter())
                .collect::<Vec<_>>();
            sorted_policy_prob.sort_by(|a, b| (a.1).partial_cmp(&b.1).unwrap());
            let sorted_policies = sorted_policy_prob
                .into_iter()
                .map(|(x, _prob)| x)
                .collect::<Vec<_>>();

            // Generate TapTree leaves compilations from the given sub-policies
            let node_compilations = sorted_policies
                .into_iter()
                .map(|x| {
                    let leaf_policy: Concrete<String> = policy_str!("{}", x);
                    TapTree::Leaf(Arc::from(leaf_policy.compile::<Tap>().unwrap()))
                })
                .collect::<Vec<_>>();

            // Arrange leaf compilations (acc. to probabilities) using huffman encoding into a TapTree
            let tree = TapTree::combine(
                TapTree::combine(node_compilations[4].clone(), node_compilations[5].clone()),
                TapTree::combine(
                    TapTree::combine(
                        TapTree::combine(
                            node_compilations[0].clone(),
                            node_compilations[1].clone(),
                        ),
                        node_compilations[3].clone(),
                    ),
                    node_compilations[6].clone(),
                ),
            );

            let expected_descriptor = Descriptor::new_tr("E".to_string(), Some(tree)).unwrap();
            assert_eq!(descriptor, expected_descriptor);
        }
    }

    #[test]
    #[cfg(feature = "compiler")]
    fn experimental_taproot_compile() {
        let unspendable_key = "UNSPEND".to_string();

        {
            let pol = Concrete::<String>::from_str(
                "thresh(7,pk(A),pk(B),pk(C),pk(D),pk(E),pk(F),pk(G),pk(H))",
            )
            .unwrap();
            let desc = pol
                .compile_tr_private_experimental(Some(unspendable_key.clone()))
                .unwrap();
            let expected_desc = Descriptor::Tr(
                Tr::<String>::from_str(
                    "tr(UNSPEND ,{
                {
                    {multi_a(7,B,C,D,E,F,G,H),multi_a(7,A,C,D,E,F,G,H)},
                    {multi_a(7,A,B,D,E,F,G,H),multi_a(7,A,B,C,E,F,G,H)}
                },
                {
                    {multi_a(7,A,B,C,D,F,G,H),multi_a(7,A,B,C,D,E,G,H)}
                   ,{multi_a(7,A,B,C,D,E,F,H),multi_a(7,A,B,C,D,E,F,G)}
                }})"
                    .replace(&['\t', ' ', '\n'][..], "")
                    .as_str(),
                )
                .unwrap(),
            );
            assert_eq!(desc, expected_desc);
        }

        {
            let pol =
                Concrete::<String>::from_str("thresh(3,pk(A),pk(B),pk(C),pk(D),pk(E))").unwrap();
            let desc = pol
                .compile_tr_private_experimental(Some(unspendable_key.clone()))
                .unwrap();
            let expected_desc = Descriptor::Tr(
                Tr::<String>::from_str(
                    "tr(UNSPEND,
                    {{
                        {multi_a(3,A,D,E),multi_a(3,A,C,E)},
                        {multi_a(3,A,C,D),multi_a(3,A,B,E)}\
                    },
                    {
                        {multi_a(3,A,B,D),multi_a(3,A,B,C)},
                        {
                            {multi_a(3,C,D,E),multi_a(3,B,D,E)},
                            {multi_a(3,B,C,E),multi_a(3,B,C,D)}
                    }}})"
                        .replace(&['\t', ' ', '\n'][..], "")
                        .as_str(),
                )
                .unwrap(),
            );
            assert_eq!(desc, expected_desc);
        }
    }
}

#[cfg(all(bench, feature = "compiler"))]
mod benches {
    use core::str::FromStr;

    use test::{black_box, Bencher};

    use super::{Concrete, Error};
    use crate::descriptor::Descriptor;
    use crate::prelude::*;
    type TapDesc = Result<Descriptor<String>, Error>;

    #[bench]
    pub fn compile_large_tap(bh: &mut Bencher) {
        let pol = Concrete::<String>::from_str(
            "thresh(20,pk(A),pk(B),pk(C),pk(D),pk(E),pk(F),pk(G),pk(H),pk(I),pk(J),pk(K),pk(L),pk(M),pk(N),pk(O),pk(P),pk(Q),pk(R),pk(S),pk(T),pk(U),pk(V),pk(W),pk(X),pk(Y),pk(Z))",
        )
        .expect("parsing");
        bh.iter(|| {
            let pt: TapDesc = pol.compile_tr_private_experimental(Some("UNSPEND".to_string()));
            black_box(pt).unwrap();
        });
    }
}
