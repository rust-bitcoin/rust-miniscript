// Script Descriptor Language
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

//! # Script Descriptors
//!
//! Tools for representing Bitcoin scriptpubkeys as abstract spending policies, known
//! as "script descriptors".
//!
//! The format represents EC public keys abstractly to allow wallets to replace these with
//! BIP32 paths, pay-to-contract instructions, etc.
//!

use bitcoin::blockdata::script::{self ,Script};
use bitcoin::blockdata::transaction::SigHashType;
use bitcoin::util::hash::Sha256dHash; // TODO needs to be sha256, not sha256d
use secp256k1;
use std::fmt;
use std::str::{self, FromStr};

use expression;
use descript::Descript;
use Error;

/// Script descriptor
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Descriptor<P> {
    /// A raw scriptpubkey
    Bare(Descript<P>),
    /// Pay-to-PubKey-Hash
    Pkh(P),
    /// Pay-to-Witness-PubKey-Hash
    Wpkh(P),
    /// Pay-to-ScriptHash
    Sh(Descript<P>),
    /// Pay-to-Witness-ScriptHash
    Wsh(Descript<P>),
    /// P2SH-P2WSH
    ShWsh(Descript<P>),
}

impl<P> Descriptor<P> {
    /// Convert a descriptor using abstract keys to one using specific keys
    pub fn translate<F, Q, E>(&self, translatefn: &F) -> Result<Descriptor<Q>, E>
        where F: Fn(&P) -> Result<Q, E>
    {
        match *self {
            Descriptor::Bare(ref descript) => {
                Ok(Descriptor::Bare(descript.translate(translatefn)?))
            }
            Descriptor::Pkh(ref pk) => {
                translatefn(pk).map(Descriptor::Pkh)
            }
            Descriptor::Wpkh(ref pk) => {
                translatefn(pk).map(Descriptor::Wpkh)
            }
            Descriptor::Sh(ref descript) => {
                Ok(Descriptor::Bare(descript.translate(translatefn)?))
            }
            Descriptor::Wsh(ref descript) => {
                Ok(Descriptor::Bare(descript.translate(translatefn)?))
            }
            Descriptor::ShWsh(ref descript) => {
                Ok(Descriptor::Bare(descript.translate(translatefn)?))
            }
        }
    }
}

impl Descriptor<secp256k1::PublicKey> {
    /// Computes the scriptpubkey of the descriptor
    pub fn script_pubkey(&self) -> Script {
        match *self {
            Descriptor::Bare(ref d) => d.serialize(),
            _ => unimplemented!()
        }
    }
}

impl<P: ToString> Descriptor<P> {
    /// Attempts to produce a satisfying witness or scriptSig, as the case may be,
    /// for the descriptor
    pub fn satisfy<F, H>(&self, keyfn: Option<&F>, hashfn: Option<&H>, age: u32)
        -> Result<Vec<Vec<u8>>, Error>
        where F: Fn(&P) -> Option<(secp256k1::Signature, Option<SigHashType>)>,
              H: Fn(Sha256dHash) -> Option<[u8; 32]>
    {
        match *self {
            Descriptor::Bare(ref d) => {
                let witness = d.satisfy(keyfn, hashfn, age)?;
                // For bare descriptors we have to translate the witness into a scriptSig
                let mut b = script::Builder::new();
                for wit in &witness {
                    if let Ok(n) = script::read_scriptint(wit) {
                        b = b.push_int(n);
                    } else {
                        b = b.push_slice(wit);
                    }
                }
                // Return it as a single-entry vector since the signature of this function is
                // designed for segwit really
                Ok(vec![b.into_script().into_bytes()])
            }
            _ => unimplemented!()
        }
    }
}

impl<P: FromStr> expression::FromTree for Descriptor<P>
    where <P as FromStr>::Err: ToString,
{
    /// Parse an expression tree into a descriptor
    fn from_tree(top: &expression::Tree) -> Result<Descriptor<P>, Error> {
        match (top.name, top.args.len() as u32) {
            ("pkh", 1) => expression::terminal(
                &top.args[0],
                |pk| P::from_str(pk).map(Descriptor::Pkh)
            ),
            ("wpkh", 1) => expression::terminal(
                &top.args[0],
                |pk| P::from_str(pk).map(Descriptor::Wpkh)
            ),
            ("sh", 1) => {
                let newtop = &top.args[0];
                match (newtop.name, newtop.args.len()) {
                    ("wsh", 1) => {
                        let sub = Descript::from_tree(&newtop.args[0])?;
                        Ok(Descriptor::ShWsh(sub))
                    }
                    _ => {
                        let sub = Descript::from_tree(&top.args[0])?;
                        Ok(Descriptor::Sh(sub))
                    }
                }
            }
            ("wsh", 1) => expression::unary(top, Descriptor::Wsh),
            _ => {
                let sub = expression::FromTree::from_tree(&top)?;
                Ok(Descriptor::Bare(sub))
            }
        }
    }
}

impl<P: FromStr> FromStr for Descriptor<P>
    where <P as FromStr>::Err: ToString,
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Descriptor<P>, Error> {
        for ch in s.as_bytes() {
            if *ch < 20 || *ch > 127 {
                return Err(Error::Unprintable(*ch));
            }
        }

        let top = expression::Tree::from_str(s)?;
        expression::FromTree::from_tree(&top)
    }
}

impl <P: fmt::Debug> fmt::Debug for Descriptor<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Descriptor::Bare(ref sub) => write!(f, "{:?}", sub),
            Descriptor::Pkh(ref p) => write!(f, "pkh({:?})", p),
            Descriptor::Wpkh(ref p) => write!(f, "wpkh({:?})", p),
            Descriptor::Sh(ref sub) => write!(f, "sh({:?})", sub),
            Descriptor::Wsh(ref sub) => write!(f, "wsh({:?})", sub),
            Descriptor::ShWsh(ref sub) => write!(f, "sh(wsh({:?}))", sub),
        }
    }
}

impl <P: fmt::Display> fmt::Display for Descriptor<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Descriptor::Bare(ref sub) => write!(f, "{}", sub),
            Descriptor::Pkh(ref p) => write!(f, "pkh({})", p),
            Descriptor::Wpkh(ref p) => write!(f, "wpkh({})", p),
            Descriptor::Sh(ref sub) => write!(f, "sh({})", sub),
            Descriptor::Wsh(ref sub) => write!(f, "wsh({})", sub),
            Descriptor::ShWsh(ref sub) => write!(f, "sh(wsh({}))", sub),
        }
    }
}

#[cfg(test)]
mod tests {
    use secp256k1;
    use std::str::FromStr;

    use Descriptor;

    #[test]
    fn parse_descriptor() {
        assert!(Descriptor::<secp256k1::PublicKey>::from_str("(").is_err());
        assert!(Descriptor::<secp256k1::PublicKey>::from_str("(x()").is_err());
        assert!(Descriptor::<secp256k1::PublicKey>::from_str("(\u{7f}()3").is_err());
        assert!(Descriptor::<secp256k1::PublicKey>::from_str("pk()").is_err());

        assert!(Descriptor::<secp256k1::PublicKey>::from_str("pk(020000000000000000000000000000000000000000000000000000000000000002)").is_ok());
    }
}

