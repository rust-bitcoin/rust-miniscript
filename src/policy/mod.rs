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
use miniscript::Miniscript;
use Terminal;

pub use self::concrete::Policy as Concrete;
/// Semantic policies are "abstract" policies elsewhere; but we
/// avoid this word because it is a reserved keyword in Rust
pub use self::semantic::Policy as Semantic;
use MiniscriptKey;

/// Trait describing script representations which can be lifted into
/// an abstract policy, by discarding information.
/// After Lifting all policies are converted into `KeyHash(Pk::HasH)` to
/// maintain the following invariant:
/// `Lift(Concrete) == Concrete -> Miniscript -> Script -> Miniscript -> Semantic`
pub trait Liftable<Pk: MiniscriptKey> {
    /// Convert the object into an abstract policy
    fn into_lift(self) -> Semantic<Pk>;
}

impl<Pk: MiniscriptKey> Liftable<Pk> for Miniscript<Pk> {
    fn into_lift(self) -> Semantic<Pk> {
        self.into_inner().into_lift()
    }
}

impl<Pk: MiniscriptKey> Liftable<Pk> for Terminal<Pk> {
    fn into_lift(self) -> Semantic<Pk> {
        match self {
            Terminal::Pk(pk) => Semantic::Key(pk),
            Terminal::PkH(pkh) => Semantic::KeyHash(pkh),
            Terminal::After(t) => Semantic::After(t),
            Terminal::Older(t) => Semantic::Older(t),
            Terminal::Sha256(h) => Semantic::Sha256(h),
            Terminal::Hash256(h) => Semantic::Hash256(h),
            Terminal::Ripemd160(h) => Semantic::Ripemd160(h),
            Terminal::Hash160(h) => Semantic::Hash160(h),
            Terminal::True => Semantic::Trivial,
            Terminal::False => Semantic::Unsatisfiable,
            Terminal::Alt(sub)
                | Terminal::Swap(sub)
                | Terminal::Check(sub)
                | Terminal::DupIf(sub)
                | Terminal::Verify(sub)
                | Terminal::NonZero(sub)
                | Terminal::ZeroNotEqual(sub) => sub.node.into_lift(),
            Terminal::AndV(left, right)
                | Terminal::AndB(left, right)
                => Semantic::And(vec![left.node.into_lift(), right.node.into_lift()]),
            Terminal::AndOr(a, b, c) => Semantic::Or(vec![
                Semantic::And(vec![a.node.into_lift(), c.node.into_lift()]),
                b.node.into_lift(),
            ]),
            Terminal::OrB(left, right)
                | Terminal::OrD(left, right)
                | Terminal::OrC(left, right)
                | Terminal::OrI(left, right)
                => Semantic::Or(vec![left.node.into_lift(), right.node.into_lift()]),
            Terminal::Thresh(k, subs) => Semantic::Threshold(
                k,
                subs.into_iter().map(|s| s.node.into_lift()).collect(),
            ),
            Terminal::ThreshM(k, keys) => Semantic::Threshold(
                k,
                keys.into_iter().map(|k| Semantic::Key(k)).collect(),
            ),
        }.normalized()
    }
}

impl<Pk: MiniscriptKey> Liftable<Pk> for Descriptor<Pk> {
    fn into_lift(self) -> Semantic<Pk> {
        match self {
            Descriptor::Bare(d)
                | Descriptor::Sh(d)
                | Descriptor::Wsh(d)
                | Descriptor::ShWsh(d) => d.node.into_lift(),
            Descriptor::Pk(p)
                | Descriptor::Pkh(p)
                | Descriptor::Wpkh(p)
                | Descriptor::ShWpkh(p) => Semantic::Key(p),
        }
    }
}

impl<Pk: MiniscriptKey> Liftable<Pk> for Semantic<Pk> {
    fn into_lift(self) -> Semantic<Pk> {
        self
    }
}

impl<Pk: MiniscriptKey> Liftable<Pk> for Concrete<Pk> {
    fn into_lift(self) -> Semantic<Pk> {
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
