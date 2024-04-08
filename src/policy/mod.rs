// SPDX-License-Identifier: CC0-1.0

//!  Script Policies
//!
//! Tools for representing Bitcoin scriptpubkeys as abstract spending policies.
//! These may be compiled to Miniscript, which contains extra information to
//! describe the exact representation as Bitcoin script.
//!
//! The format represents EC public keys abstractly to allow wallets to replace
//! these with BIP32 paths, pay-to-contract instructions, etc.
//!
use core::fmt;
#[cfg(feature = "std")]
use std::error;

#[cfg(feature = "compiler")]
pub mod compiler;
pub mod concrete;
pub mod semantic;

pub use self::concrete::Policy as Concrete;
pub use self::semantic::Policy as Semantic;
use crate::descriptor::Descriptor;
use crate::miniscript::{Miniscript, ScriptContext};
use crate::sync::Arc;
#[cfg(all(not(feature = "std"), not(test)))]
use crate::Vec;
use crate::{Error, MiniscriptKey, Terminal, Threshold};

/// Policy entailment algorithm maximum number of terminals allowed.
const ENTAILMENT_MAX_TERMINALS: usize = 20;

/// Trait describing script representations which can be lifted into
/// an abstract policy, by discarding information.
///
/// After Lifting all policies are converted into `KeyHash(Pk::HasH)` to
/// maintain the following invariant(modulo resource limits):
/// `Lift(Concrete) == Concrete -> Miniscript -> Script -> Miniscript -> Semantic`
///
/// Lifting from [`Miniscript`] or [`Descriptor`] can fail if the miniscript
/// contains a timelock combination or if it contains a branch that exceeds
/// resource limits.
///
/// Lifting from concrete policies can fail if the policy contains a timelock
/// combination. It is possible that a concrete policy has some branches that
/// exceed resource limits for any compilation but cannot detect such policies
/// while lifting. Note that our compiler would not succeed for any such
/// policies.
pub trait Liftable<Pk: MiniscriptKey> {
    /// Converts this object into an abstract policy.
    fn lift(&self) -> Result<Semantic<Pk>, Error>;
}

/// Error occurring during lifting.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum LiftError {
    /// Cannot lift policies that have a combination of height and timelocks.
    HeightTimelockCombination,
    /// Duplicate public keys.
    BranchExceedResourceLimits,
    /// Cannot lift raw descriptors.
    RawDescriptorLift,
}

impl fmt::Display for LiftError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LiftError::HeightTimelockCombination => {
                f.write_str("Cannot lift policies that have a heightlock and timelock combination")
            }
            LiftError::BranchExceedResourceLimits => f.write_str(
                "Cannot lift policies containing one branch that exceeds resource limits",
            ),
            LiftError::RawDescriptorLift => f.write_str("Cannot lift raw descriptors"),
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for LiftError {
    fn cause(&self) -> Option<&dyn error::Error> {
        use self::LiftError::*;

        match self {
            HeightTimelockCombination | BranchExceedResourceLimits | RawDescriptorLift => None,
        }
    }
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> Miniscript<Pk, Ctx> {
    /// Lifting corresponds to conversion of a miniscript into a [`Semantic`]
    /// policy for human readable or machine analysis. However, naively lifting
    /// miniscripts can result in incorrect interpretations that don't
    /// correspond to the underlying semantics when we try to spend them on
    /// bitcoin network. This can occur if the miniscript contains:
    /// 1. A combination of timelocks
    /// 2. A spend that exceeds resource limits
    pub fn lift_check(&self) -> Result<(), LiftError> {
        if !self.within_resource_limits() {
            Err(LiftError::BranchExceedResourceLimits)
        } else if self.has_mixed_timelocks() {
            Err(LiftError::HeightTimelockCombination)
        } else {
            Ok(())
        }
    }
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> Liftable<Pk> for Miniscript<Pk, Ctx> {
    fn lift(&self) -> Result<Semantic<Pk>, Error> {
        // check whether the root miniscript can have a spending path that is
        // a combination of heightlock and timelock
        self.lift_check()?;
        self.as_inner().lift()
    }
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> Liftable<Pk> for Terminal<Pk, Ctx> {
    fn lift(&self) -> Result<Semantic<Pk>, Error> {
        let ret = match *self {
            Terminal::PkK(ref pk) | Terminal::PkH(ref pk) => Semantic::Key(pk.clone()),
            Terminal::RawPkH(ref _pkh) => {
                return Err(Error::LiftError(LiftError::RawDescriptorLift))
            }
            Terminal::After(t) => Semantic::After(t),
            Terminal::Older(t) => Semantic::Older(t),
            Terminal::Sha256(ref h) => Semantic::Sha256(h.clone()),
            Terminal::Hash256(ref h) => Semantic::Hash256(h.clone()),
            Terminal::Ripemd160(ref h) => Semantic::Ripemd160(h.clone()),
            Terminal::Hash160(ref h) => Semantic::Hash160(h.clone()),
            Terminal::False => Semantic::Unsatisfiable,
            Terminal::True => Semantic::Trivial,
            Terminal::Alt(ref sub)
            | Terminal::Swap(ref sub)
            | Terminal::Check(ref sub)
            | Terminal::DupIf(ref sub)
            | Terminal::Verify(ref sub)
            | Terminal::NonZero(ref sub)
            | Terminal::ZeroNotEqual(ref sub) => sub.node.lift()?,
            Terminal::AndV(ref left, ref right) | Terminal::AndB(ref left, ref right) => {
                Semantic::Thresh(Threshold::and(
                    Arc::new(left.node.lift()?),
                    Arc::new(right.node.lift()?),
                ))
            }
            Terminal::AndOr(ref a, ref b, ref c) => Semantic::Thresh(Threshold::or(
                Arc::new(Semantic::Thresh(Threshold::and(
                    Arc::new(a.node.lift()?),
                    Arc::new(b.node.lift()?),
                ))),
                Arc::new(c.node.lift()?),
            )),
            Terminal::OrB(ref left, ref right)
            | Terminal::OrD(ref left, ref right)
            | Terminal::OrC(ref left, ref right)
            | Terminal::OrI(ref left, ref right) => Semantic::Thresh(Threshold::or(
                Arc::new(left.node.lift()?),
                Arc::new(right.node.lift()?),
            )),
            Terminal::Thresh(ref thresh) => thresh
                .translate_ref(|sub| sub.lift().map(Arc::new))
                .map(Semantic::Thresh)?,
            Terminal::Multi(ref thresh) => Semantic::Thresh(
                thresh
                    .map_ref(|key| Arc::new(Semantic::Key(key.clone())))
                    .forget_maximum(),
            ),
            Terminal::MultiA(ref thresh) => Semantic::Thresh(
                thresh
                    .map_ref(|key| Arc::new(Semantic::Key(key.clone())))
                    .forget_maximum(),
            ),
        }
        .normalized();
        Ok(ret)
    }
}

impl<Pk: MiniscriptKey> Liftable<Pk> for Descriptor<Pk> {
    fn lift(&self) -> Result<Semantic<Pk>, Error> {
        match *self {
            Descriptor::Bare(ref bare) => bare.lift(),
            Descriptor::Pkh(ref pkh) => pkh.lift(),
            Descriptor::Wpkh(ref wpkh) => wpkh.lift(),
            Descriptor::Wsh(ref wsh) => wsh.lift(),
            Descriptor::Sh(ref sh) => sh.lift(),
            Descriptor::Tr(ref tr) => tr.lift(),
        }
    }
}

impl<Pk: MiniscriptKey> Liftable<Pk> for Semantic<Pk> {
    fn lift(&self) -> Result<Semantic<Pk>, Error> { Ok(self.clone()) }
}

impl<Pk: MiniscriptKey> Liftable<Pk> for Concrete<Pk> {
    fn lift(&self) -> Result<Semantic<Pk>, Error> {
        // do not lift if there is a possible satisfaction
        // involving combination of timelocks and heightlocks
        self.check_timelocks()?;
        let ret = match *self {
            Concrete::Unsatisfiable => Semantic::Unsatisfiable,
            Concrete::Trivial => Semantic::Trivial,
            Concrete::Key(ref pk) => Semantic::Key(pk.clone()),
            Concrete::After(t) => Semantic::After(t),
            Concrete::Older(t) => Semantic::Older(t),
            Concrete::Sha256(ref h) => Semantic::Sha256(h.clone()),
            Concrete::Hash256(ref h) => Semantic::Hash256(h.clone()),
            Concrete::Ripemd160(ref h) => Semantic::Ripemd160(h.clone()),
            Concrete::Hash160(ref h) => Semantic::Hash160(h.clone()),
            Concrete::And(ref subs) => {
                let semantic_subs: Result<Vec<Semantic<Pk>>, Error> =
                    subs.iter().map(Liftable::lift).collect();
                let semantic_subs = semantic_subs?.into_iter().map(Arc::new).collect();
                Semantic::Thresh(Threshold::new(2, semantic_subs).unwrap())
            }
            Concrete::Or(ref subs) => {
                let semantic_subs: Result<Vec<Semantic<Pk>>, Error> =
                    subs.iter().map(|(_p, sub)| sub.lift()).collect();
                let semantic_subs = semantic_subs?.into_iter().map(Arc::new).collect();
                Semantic::Thresh(Threshold::new(1, semantic_subs).unwrap())
            }
            Concrete::Thresh(ref thresh) => {
                Semantic::Thresh(thresh.translate_ref(|sub| Liftable::lift(sub).map(Arc::new))?)
            }
        }
        .normalized();
        Ok(ret)
    }
}
impl<Pk: MiniscriptKey> Liftable<Pk> for Arc<Concrete<Pk>> {
    fn lift(&self) -> Result<Semantic<Pk>, Error> { self.as_ref().lift() }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::*;
    #[cfg(feature = "compiler")]
    use crate::descriptor::Tr;
    use crate::miniscript::context::Segwitv0;
    use crate::prelude::*;
    use crate::RelLockTime;
    #[cfg(feature = "compiler")]
    use crate::{descriptor::TapTree, Tap};

    type ConcretePol = Concrete<String>;
    type SemanticPol = Semantic<String>;

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
            "thresholds in Miniscript must be nonempty",
        );
        assert_eq!(
            ConcretePol::from_str("thresh(2,pk(),thresh(0,pk()))")
                .unwrap_err()
                .to_string(),
            "thresholds in Miniscript must have k > 0",
        );
        assert_eq!(
            ConcretePol::from_str("and(pk())").unwrap_err().to_string(),
            "And policy fragment must take 2 arguments"
        );
        assert_eq!(
            ConcretePol::from_str("or(pk())").unwrap_err().to_string(),
            "Or policy fragment must take 2 arguments"
        );
        // these weird "unexpected" wrapping of errors will go away in a later PR
        // which rewrites the expression parser
        assert_eq!(
            ConcretePol::from_str("thresh(3,after(0),pk(),pk())")
                .unwrap_err()
                .to_string(),
            "unexpected «absolute locktimes in Miniscript have a minimum value of 1»",
        );

        assert_eq!(
            ConcretePol::from_str("thresh(2,older(2147483650),pk(),pk())")
                .unwrap_err()
                .to_string(),
            "unexpected «locktime value 2147483650 is not a valid BIP68 relative locktime»"
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
            Semantic::Thresh(Threshold::or(
                Arc::new(Semantic::Thresh(Threshold::and(
                    Arc::new(Semantic::Key(key_a)),
                    Arc::new(Semantic::Older(RelLockTime::from_height(42)))
                ))),
                Arc::new(Semantic::Key(key_b))
            )),
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
            sorted_policy_prob.sort_by(|a, b| (a.1).partial_cmp(b.1).unwrap());
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
                    {and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:pk(B),pk(C)),pk(D)),pk(E)),pk(F)),pk(G)),pk(H)),and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:pk(A),pk(C)),pk(D)),pk(E)),pk(F)),pk(G)),pk(H))},
                    {and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:pk(A),pk(B)),pk(D)),pk(E)),pk(F)),pk(G)),pk(H)),and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:pk(A),pk(B)),pk(C)),pk(E)),pk(F)),pk(G)),pk(H))}
                },
                {
                    {and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:pk(A),pk(B)),pk(C)),pk(D)),pk(F)),pk(G)),pk(H)),and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:pk(A),pk(B)),pk(C)),pk(D)),pk(E)),pk(G)),pk(H))},
                    {and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:pk(A),pk(B)),pk(C)),pk(D)),pk(E)),pk(F)),pk(H)),and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:pk(A),pk(B)),pk(C)),pk(D)),pk(E)),pk(F)),pk(G))}
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
            println!("{}", desc);
            let expected_desc = Descriptor::Tr(
                Tr::<String>::from_str(
                    "tr(UNSPEND,
                    {{
                        {and_v(v:and_v(v:pk(A),pk(D)),pk(E)),and_v(v:and_v(v:pk(A),pk(C)),pk(E))},
                        {and_v(v:and_v(v:pk(A),pk(C)),pk(D)),and_v(v:and_v(v:pk(A),pk(B)),pk(E))}
                    },
                    {
                        {and_v(v:and_v(v:pk(A),pk(B)),pk(D)),and_v(v:and_v(v:pk(A),pk(B)),pk(C))},
                        {
                            {and_v(v:and_v(v:pk(C),pk(D)),pk(E)),and_v(v:and_v(v:pk(B),pk(D)),pk(E))},
                            {and_v(v:and_v(v:pk(B),pk(C)),pk(E)),and_v(v:and_v(v:pk(B),pk(C)),pk(D))}
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
