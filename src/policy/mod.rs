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

#[cfg(feature = "compiler")]
pub mod compiler;
pub mod concrete;

/// Policy entailment algorithm maximum number of terminals allowed.
pub(crate) const ENTAILMENT_MAX_TERMINALS: usize = 20;
