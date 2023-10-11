// SPDX-License-Identifier: CC0-1.0

//! Provides the `Lift` trait and `Liftable` type.
//!
//! **Please Note**: lifting is a `rust-miniscript` thing not a general miniscript thing.
//!
//! Script representations, like descriptors and concrete policies, can be "lifted" into an abstract
//! representation by discarding information.

use core::fmt;
#[cfg(feature = "std")]
use std::error;

pub mod lifted;

/// Re-export/re-name to facilitate usage of `Lifted` instead of `lifted::Policy`.
#[rustfmt::skip]
pub use self::lifted::Policy as Lifted;

use crate::descriptor::Descriptor;
use crate::miniscript::{Miniscript, ScriptContext};
use crate::policy::concrete;
use crate::sync::Arc;
use crate::{Error, MiniscriptKey, Terminal};

/// Policy entailment algorithm maximum number of terminals allowed.
pub const ENTAILMENT_MAX_TERMINALS: usize = 20;

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
pub trait Lift<Pk: MiniscriptKey> {
    /// Converts this object into an abstract policy.
    fn lift(&self) -> Result<Lifted<Pk>, Error>;
}

/// Error occurring during lifting.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
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
    /// Lifting corresponds to conversion of a miniscript into a [`Lifted`]
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

impl<Pk: MiniscriptKey, Ctx: ScriptContext> Lift<Pk> for Miniscript<Pk, Ctx> {
    fn lift(&self) -> Result<Lifted<Pk>, Error> {
        // check whether the root miniscript can have a spending path that is
        // a combination of heightlock and timelock
        self.lift_check()?;
        self.as_inner().lift()
    }
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> Lift<Pk> for Terminal<Pk, Ctx> {
    fn lift(&self) -> Result<Lifted<Pk>, Error> {
        let ret = match *self {
            Terminal::PkK(ref pk) | Terminal::PkH(ref pk) => Lifted::Key(pk.clone()),
            Terminal::RawPkH(ref _pkh) => {
                return Err(Error::LiftError(LiftError::RawDescriptorLift))
            }
            Terminal::After(t) => Lifted::After(t),
            Terminal::Older(t) => Lifted::Older(t),
            Terminal::Sha256(ref h) => Lifted::Sha256(h.clone()),
            Terminal::Hash256(ref h) => Lifted::Hash256(h.clone()),
            Terminal::Ripemd160(ref h) => Lifted::Ripemd160(h.clone()),
            Terminal::Hash160(ref h) => Lifted::Hash160(h.clone()),
            Terminal::False => Lifted::Unsatisfiable,
            Terminal::True => Lifted::Trivial,
            Terminal::Alt(ref sub)
            | Terminal::Swap(ref sub)
            | Terminal::Check(ref sub)
            | Terminal::DupIf(ref sub)
            | Terminal::Verify(ref sub)
            | Terminal::NonZero(ref sub)
            | Terminal::ZeroNotEqual(ref sub) => sub.node.lift()?,
            Terminal::AndV(ref left, ref right) | Terminal::AndB(ref left, ref right) => {
                Lifted::Threshold(2, vec![left.node.lift()?, right.node.lift()?])
            }
            Terminal::AndOr(ref a, ref b, ref c) => Lifted::Threshold(
                1,
                vec![
                    Lifted::Threshold(2, vec![a.node.lift()?, b.node.lift()?]),
                    c.node.lift()?,
                ],
            ),
            Terminal::OrB(ref left, ref right)
            | Terminal::OrD(ref left, ref right)
            | Terminal::OrC(ref left, ref right)
            | Terminal::OrI(ref left, ref right) => {
                Lifted::Threshold(1, vec![left.node.lift()?, right.node.lift()?])
            }
            Terminal::Thresh(k, ref subs) => {
                let semantic_subs: Result<_, Error> = subs.iter().map(|s| s.node.lift()).collect();
                Lifted::Threshold(k, semantic_subs?)
            }
            Terminal::Multi(k, ref keys) | Terminal::MultiA(k, ref keys) => {
                Lifted::Threshold(k, keys.iter().map(|k| Lifted::Key(k.clone())).collect())
            }
        }
        .normalized();
        Ok(ret)
    }
}

impl<Pk: MiniscriptKey> Lift<Pk> for Descriptor<Pk> {
    fn lift(&self) -> Result<Lifted<Pk>, Error> {
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

impl<Pk: MiniscriptKey> Lift<Pk> for Lifted<Pk> {
    fn lift(&self) -> Result<Lifted<Pk>, Error> { Ok(self.clone()) }
}

impl<Pk: MiniscriptKey> Lift<Pk> for concrete::Policy<Pk> {
    fn lift(&self) -> Result<Lifted<Pk>, Error> {
        use concrete::Policy as Concrete;

        // do not lift if there is a possible satisfaction
        // involving combination of timelocks and heightlocks
        self.check_timelocks()?;
        let ret = match *self {
            Concrete::Unsatisfiable => Lifted::Unsatisfiable,
            Concrete::Trivial => Lifted::Trivial,
            Concrete::Key(ref pk) => Lifted::Key(pk.clone()),
            Concrete::After(t) => Lifted::After(t),
            Concrete::Older(t) => Lifted::Older(t),
            Concrete::Sha256(ref h) => Lifted::Sha256(h.clone()),
            Concrete::Hash256(ref h) => Lifted::Hash256(h.clone()),
            Concrete::Ripemd160(ref h) => Lifted::Ripemd160(h.clone()),
            Concrete::Hash160(ref h) => Lifted::Hash160(h.clone()),
            Concrete::And(ref subs) => {
                let semantic_subs: Result<_, Error> = subs.iter().map(Lift::lift).collect();
                Lifted::Threshold(2, semantic_subs?)
            }
            Concrete::Or(ref subs) => {
                let semantic_subs: Result<_, Error> =
                    subs.iter().map(|(_p, sub)| sub.lift()).collect();
                Lifted::Threshold(1, semantic_subs?)
            }
            Concrete::Threshold(k, ref subs) => {
                let semantic_subs: Result<_, Error> = subs.iter().map(Lift::lift).collect();
                Lifted::Threshold(k, semantic_subs?)
            }
        }
        .normalized();
        Ok(ret)
    }
}
impl<Pk: MiniscriptKey> Lift<Pk> for Arc<concrete::Policy<Pk>> {
    fn lift(&self) -> Result<Lifted<Pk>, Error> { self.as_ref().lift() }
}
