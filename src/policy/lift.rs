// SPDX-License-Identifier: CC0-1.0

//! Lifting of semantic to concrete policies.

use core::fmt;
#[cfg(feature = "std")]
use std::error;

use super::semantic::Semantic;
use super::Policy;
use crate::descriptor::Descriptor;
use crate::iter::TreeLike as _;
use crate::miniscript::{Miniscript, ScriptContext};
use crate::sync::Arc;
#[cfg(all(not(feature = "std"), not(test)))]
use crate::Vec;
use crate::{Error, MiniscriptKey, Terminal, Threshold};

/// Trait describing script representations which can be lifted into
/// an abstract policy, by discarding information.
///
/// After Lifting all policies are converted into `KeyHash(Pk::HasH)` to
/// maintain the following invariant(modulo resource limits):
/// `Lift(Policy) == Policy -> Miniscript -> Script -> Miniscript -> Semantic`
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

        let mut stack = vec![];
        for item in self.rtl_post_order_iter() {
            let new_term = match item.node.node {
                Terminal::PkK(ref pk) | Terminal::PkH(ref pk) => {
                    Arc::new(Semantic::Key(pk.clone()))
                }
                Terminal::RawPkH(ref _pkh) => {
                    return Err(Error::LiftError(LiftError::RawDescriptorLift))
                }
                Terminal::After(t) => Arc::new(Semantic::After(t)),
                Terminal::Older(t) => Arc::new(Semantic::Older(t)),
                Terminal::Sha256(ref h) => Arc::new(Semantic::Sha256(h.clone())),
                Terminal::Hash256(ref h) => Arc::new(Semantic::Hash256(h.clone())),
                Terminal::Ripemd160(ref h) => Arc::new(Semantic::Ripemd160(h.clone())),
                Terminal::Hash160(ref h) => Arc::new(Semantic::Hash160(h.clone())),
                Terminal::False => Arc::new(Semantic::Unsatisfiable),
                Terminal::True => Arc::new(Semantic::Trivial),
                Terminal::Alt(..)
                | Terminal::Swap(..)
                | Terminal::Check(..)
                | Terminal::DupIf(..)
                | Terminal::Verify(..)
                | Terminal::NonZero(..)
                | Terminal::ZeroNotEqual(..) => stack.pop().unwrap(),
                Terminal::AndV(..) | Terminal::AndB(..) => Arc::new(Semantic::Thresh(
                    Threshold::and(stack.pop().unwrap(), stack.pop().unwrap()),
                )),
                Terminal::AndOr(..) => Arc::new(Semantic::Thresh(Threshold::or(
                    Arc::new(Semantic::Thresh(Threshold::and(
                        stack.pop().unwrap(),
                        stack.pop().unwrap(),
                    ))),
                    stack.pop().unwrap(),
                ))),
                Terminal::OrB(..) | Terminal::OrD(..) | Terminal::OrC(..) | Terminal::OrI(..) => {
                    Arc::new(Semantic::Thresh(Threshold::or(
                        stack.pop().unwrap(),
                        stack.pop().unwrap(),
                    )))
                }
                Terminal::Thresh(ref thresh) => {
                    Arc::new(Semantic::Thresh(thresh.map_ref(|_| stack.pop().unwrap())))
                }
                Terminal::Multi(ref thresh) | Terminal::SortedMulti(ref thresh) => {
                    Arc::new(Semantic::Thresh(
                        thresh
                            .map_ref(|key| Arc::new(Semantic::Key(key.clone())))
                            .forget_maximum(),
                    ))
                }
                Terminal::MultiA(ref thresh) | Terminal::SortedMultiA(ref thresh) => {
                    Arc::new(Semantic::Thresh(
                        thresh
                            .map_ref(|key| Arc::new(Semantic::Key(key.clone())))
                            .forget_maximum(),
                    ))
                }
            };
            stack.push(new_term)
        }
        Ok(Arc::try_unwrap(stack.pop().unwrap()).unwrap().normalized())
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

impl<Pk: MiniscriptKey> Liftable<Pk> for Policy<Pk> {
    fn lift(&self) -> Result<Semantic<Pk>, Error> {
        // do not lift if there is a possible satisfaction
        // involving combination of timelocks and heightlocks
        self.check_timelocks().map_err(Error::ConcretePolicy)?;
        let ret = match *self {
            Policy::Unsatisfiable => Semantic::Unsatisfiable,
            Policy::Trivial => Semantic::Trivial,
            Policy::Key(ref pk) => Semantic::Key(pk.clone()),
            Policy::After(t) => Semantic::After(t),
            Policy::Older(t) => Semantic::Older(t),
            Policy::Sha256(ref h) => Semantic::Sha256(h.clone()),
            Policy::Hash256(ref h) => Semantic::Hash256(h.clone()),
            Policy::Ripemd160(ref h) => Semantic::Ripemd160(h.clone()),
            Policy::Hash160(ref h) => Semantic::Hash160(h.clone()),
            Policy::And(ref subs) => {
                let semantic_subs: Result<Vec<Semantic<Pk>>, Error> =
                    subs.iter().map(Liftable::lift).collect();
                let semantic_subs = semantic_subs?.into_iter().map(Arc::new).collect();
                Semantic::Thresh(Threshold::new(2, semantic_subs).unwrap())
            }
            Policy::Or(ref subs) => {
                let semantic_subs: Result<Vec<Semantic<Pk>>, Error> =
                    subs.iter().map(|(_p, sub)| sub.lift()).collect();
                let semantic_subs = semantic_subs?.into_iter().map(Arc::new).collect();
                Semantic::Thresh(Threshold::new(1, semantic_subs).unwrap())
            }
            Policy::Thresh(ref thresh) => {
                Semantic::Thresh(thresh.translate_ref(|sub| Liftable::lift(sub).map(Arc::new))?)
            }
        }
        .normalized();
        Ok(ret)
    }
}
impl<Pk: MiniscriptKey> Liftable<Pk> for Arc<Policy<Pk>> {
    fn lift(&self) -> Result<Semantic<Pk>, Error> { self.as_ref().lift() }
}
