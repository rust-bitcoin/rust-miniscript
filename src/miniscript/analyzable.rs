// Miniscript Analysis
// Written in 2018 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
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

//!  Miniscript Analysis
//!
//! Tools for determining whether the guarantees offered by the library
//! actually hold.

use core::fmt;
#[cfg(feature = "std")]
use std::error;

use crate::miniscript::iter::PkPkh;
use crate::prelude::*;
use crate::{Key, Miniscript, ScriptContext};

/// Possible reasons Miniscript guarantees can fail
/// We currently mark Miniscript as Non-Analyzable if
/// 1. It is unsafe(does not require a digital signature to spend it)
/// 2. It contains a unspendable path because of either
///     a. Resource limitations
///     b. Timelock Mixing
/// 3. The script is malleable and thereby some of satisfaction weight
///    guarantees are not satisfied.
/// 4. It has repeated publickeys
#[derive(Debug, PartialEq)]
pub enum AnalysisError {
    /// Top level is not safe.
    SiglessBranch,
    /// Repeated Pubkeys
    RepeatedPubkeys,
    /// Miniscript contains at least one path that exceeds resource limits
    BranchExceedResouceLimits,
    /// Contains a combination of heightlock and timelock
    HeightTimelockCombination,
    /// Malleable script
    Malleable,
}

impl fmt::Display for AnalysisError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AnalysisError::SiglessBranch => {
                f.write_str("All spend paths must require a signature")
            }
            AnalysisError::RepeatedPubkeys => {
                f.write_str("Miniscript contains repeated pubkeys or pubkeyhashes")
            }
            AnalysisError::BranchExceedResouceLimits => {
                f.write_str("At least one spend path exceeds the resource limits(stack depth/satisfaction size..)")
            }
            AnalysisError::HeightTimelockCombination => {
                f.write_str("Contains a combination of heightlock and timelock")
            }
            AnalysisError::Malleable => f.write_str("Miniscript is malleable")
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for AnalysisError {
    fn cause(&self) -> Option<&dyn error::Error> {
        use self::AnalysisError::*;

        match self {
            SiglessBranch
            | RepeatedPubkeys
            | BranchExceedResouceLimits
            | HeightTimelockCombination
            | Malleable => None,
        }
    }
}

impl<Pk: Key, Ctx: ScriptContext> Miniscript<Pk, Ctx> {
    /// Whether all spend paths of miniscript require a signature
    pub fn requires_sig(&self) -> bool {
        self.ty.mall.safe
    }

    /// Whether the miniscript is malleable
    pub fn is_non_malleable(&self) -> bool {
        self.ty.mall.non_malleable
    }

    /// Whether the miniscript can exceed the resource limits(Opcodes, Stack limit etc)
    // It maybe possible to return a detail error type containing why the miniscript
    // failed. But doing so may require returning a collection of errors
    pub fn within_resource_limits(&self) -> bool {
        Ctx::check_local_validity(self).is_ok()
    }

    /// Whether the miniscript contains a combination of timelocks
    pub fn has_mixed_timelocks(&self) -> bool {
        self.ext.timelock_info.contains_unspendable_path()
    }

    /// Whether the miniscript has repeated Pk or Pkh
    pub fn has_repeated_keys(&self) -> bool {
        // Simple way to check whether all of these are correct is
        // to have an iterator
        let all_pkhs_len = self.iter_pk_pkh().count();

        let unique_pkhs_len = self
            .iter_pk_pkh()
            .map(|pk_pkh| match pk_pkh {
                PkPkh::PlainPubkey(pk) => pk.to_pubkeyhash(),
                PkPkh::HashedPubkey(h) => h,
            })
            .collect::<HashSet<_>>()
            .len();

        unique_pkhs_len != all_pkhs_len
    }

    /// Check whether the underlying Miniscript is safe under the current context
    /// Lifting these polices would create a semantic representation that does
    /// not represent the underlying semantics when miniscript is spent.
    /// Signing logic may not find satisfaction even if one exists.
    ///
    /// For most cases, users should be dealing with safe scripts.
    /// Use this function to check whether the guarantees of library hold.
    /// Most functions of the library like would still
    /// work, but results cannot be relied upon
    pub fn sanity_check(&self) -> Result<(), AnalysisError> {
        if !self.requires_sig() {
            Err(AnalysisError::SiglessBranch)
        } else if !self.is_non_malleable() {
            Err(AnalysisError::Malleable)
        } else if !self.within_resource_limits() {
            Err(AnalysisError::BranchExceedResouceLimits)
        } else if self.has_repeated_keys() {
            Err(AnalysisError::RepeatedPubkeys)
        } else if self.has_mixed_timelocks() {
            Err(AnalysisError::HeightTimelockCombination)
        } else {
            Ok(())
        }
    }
}
