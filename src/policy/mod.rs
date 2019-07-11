// Miniscript
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

//!  Script Policies
//!
//! Tools for representing Bitcoin scriptpubkeys as abstract spending policies.
//! These may be compiled to Miniscript, which contains extra information to
//! describe the exact representation as Bitcoin script.
//!
//! The format represents EC public keys abstractly to allow wallets to replace
//! these with BIP32 paths, pay-to-contract instructions, etc.
//!

pub mod concrete;
pub mod semantic;
#[cfg(feature="compiler")]
pub mod compiler;

use descriptor::Descriptor;
use miniscript::astelem::AstElem;
use miniscript::Miniscript;

pub use self::concrete::Policy as Concrete;
/// Semantic policies are "abstract" policies elsewhere; but we
/// avoid this word because it is a reserved keyword in Rust
pub use self::semantic::Policy as Semantic;

/// Trait describing script representations which can be lifted into
/// an abstract policy, by discarding information
pub trait Liftable<Pk, Pkh> {
    /// Convert the object into an abstract policy
    fn into_lift(self) -> Semantic<Pk, Pkh>;
}

impl<Pk, Pkh> Liftable<Pk, Pkh> for Miniscript<Pk, Pkh> {
    fn into_lift(self) -> Semantic<Pk, Pkh> {
        self.into_inner().into_lift()
    }
}

impl<Pk, Pkh> Liftable<Pk, Pkh> for AstElem<Pk, Pkh> {
    fn into_lift(self) -> Semantic<Pk, Pkh> {
        match self {
            AstElem::Pk(pk) => Semantic::Key(pk),
            AstElem::PkH(pkh) => Semantic::KeyHash(pkh),
            AstElem::After(t) => Semantic::After(t),
            AstElem::Older(t) => Semantic::Older(t),
            AstElem::Sha256(h) => Semantic::Sha256(h),
            AstElem::Hash256(h) => Semantic::Hash256(h),
            AstElem::Ripemd160(h) => Semantic::Ripemd160(h),
            AstElem::Hash160(h) => Semantic::Hash160(h),
            AstElem::True => Semantic::Trivial,
            AstElem::False => Semantic::Unsatisfiable,
            AstElem::Alt(sub)
                | AstElem::Swap(sub)
                | AstElem::Check(sub)
                | AstElem::DupIf(sub)
                | AstElem::Verify(sub)
                | AstElem::NonZero(sub)
                | AstElem::ZeroNotEqual(sub) => sub.into_lift(),
            AstElem::AndV(left, right)
                | AstElem::AndB(left, right)
                => Semantic::And(vec![left.into_lift(), right.into_lift()]),
            AstElem::AndOr(a, b, c) => Semantic::Or(vec![
                Semantic::And(vec![a.into_lift(), c.into_lift()]),
                b.into_lift(),
            ]),
            AstElem::OrB(left, right)
                | AstElem::OrD(left, right)
                | AstElem::OrC(left, right)
                | AstElem::OrI(left, right)
                => Semantic::Or(vec![left.into_lift(), right.into_lift()]),
            AstElem::Thresh(k, subs) => Semantic::Threshold(
                k,
                subs.into_iter().map(|s| s.into_lift()).collect(),
            ),
            AstElem::ThreshM(k, keys) => Semantic::Threshold(
                k,
                keys.into_iter().map(|k| Semantic::Key(k)).collect(),
            ),
        }.normalized()
    }
}

impl<Pk, Pkh> Liftable<Pk, Pkh> for Descriptor<Pk, Pkh> {
    fn into_lift(self) -> Semantic<Pk, Pkh> {
        match self {
            Descriptor::Bare(d)
                | Descriptor::Sh(d)
                | Descriptor::Wsh(d)
                | Descriptor::ShWsh(d) => d.into_lift(),
            Descriptor::Pk(p)
                | Descriptor::Pkh(p)
                | Descriptor::Wpkh(p)
                | Descriptor::ShWpkh(p) => Semantic::Key(p),
        }
    }
}

impl<Pk, Pkh> Liftable<Pk, Pkh> for Semantic<Pk, Pkh> {
    fn into_lift(self) -> Semantic<Pk, Pkh> {
        self
    }
}

impl<Pk, Pkh> Liftable<Pk, Pkh> for Concrete<Pk, Pkh> {
    fn into_lift(self) -> Semantic<Pk, Pkh> {
        match self {
            Concrete::Key(pk) => Semantic::Key(pk),
            Concrete::KeyHash(pkh) => Semantic::KeyHash(pkh),
            Concrete::After(t) => Semantic::After(t),
            Concrete::Older(t) => Semantic::Older(t),
            Concrete::Sha256(h) => Semantic::Sha256(h),
            Concrete::Hash256(h) => Semantic::Hash256(h),
            Concrete::Ripemd160(h) => Semantic::Ripemd160(h),
            Concrete::Hash160(h) => Semantic::Hash160(h),
            Concrete::And(subs) => Semantic::And(
                subs.into_iter().map(Liftable::into_lift).collect()
            ),
            Concrete::Or(subs) => Semantic::Or(
                subs.into_iter().map(|(_, sub)| sub.into_lift()).collect()
            ),
            Concrete::Threshold(k, subs) => Semantic::Threshold(
                k,
                subs.into_iter().map(Liftable::into_lift).collect(),
            ),
        }.normalized()
    }
}
