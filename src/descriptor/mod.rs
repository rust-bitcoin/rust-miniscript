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

//! # Output Descriptors
//!
//! Tools for representing Bitcoin output's scriptPubKeys as abstract spending
//! policies known as "output descriptors". These include a Miniscript which
//! describes the actual signing policy, as well as the blockchain format (P2SH,
//! Segwit v0, etc.)
//!
//! The format represents EC public keys abstractly to allow wallets to replace these with
//! BIP32 paths, pay-to-contract instructions, etc.
//!

use bitcoin::{self, PublicKey, Script, SigHashType};
use bitcoin::blockdata::script;
use bitcoin_hashes::sha256;
use secp256k1;
use std::fmt;
use std::str::{self, FromStr};

use expression;
use miniscript::Miniscript;
use Error;

/// Script descriptor
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Descriptor<P> {
    /// A raw scriptpubkey (including pay-to-pubkey)
    Bare(Miniscript<P>),
    /// Pay-to-PubKey-Hash
    Pkh(P),
    /// Pay-to-Witness-PubKey-Hash
    Wpkh(P),
    /// Pay-to-Witness-PubKey-Hash inside P2SH
    ShWpkh(P),
    /// Pay-to-ScriptHash
    Sh(Miniscript<P>),
    /// Pay-to-Witness-ScriptHash
    Wsh(Miniscript<P>),
    /// P2SH-P2WSH
    ShWsh(Miniscript<P>),
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
            Descriptor::ShWpkh(ref pk) => {
                translatefn(pk).map(Descriptor::ShWpkh)
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

impl Descriptor<PublicKey> {
    /// Computes the scriptpubkey of the descriptor
    pub fn script_pubkey(&self) -> Script {
        match *self {
            Descriptor::Bare(ref d) => d.serialize(),
            Descriptor::Pkh(ref pk) => {
                let addr = bitcoin::Address::p2pkh(pk, bitcoin::Network::Bitcoin);
                addr.script_pubkey()
            },
            Descriptor::Wpkh(ref pk) => {
                let addr = bitcoin::Address::p2wpkh(pk, bitcoin::Network::Bitcoin);
                addr.script_pubkey()
            },
            Descriptor::ShWpkh(ref pk) => {
                let addr = bitcoin::Address::p2shwpkh(pk, bitcoin::Network::Bitcoin);
                addr.script_pubkey()
            },
            Descriptor::Sh(ref miniscript) => miniscript.serialize().to_p2sh(),
            Descriptor::Wsh(ref miniscript) => miniscript.serialize().to_v0_p2wsh(),
            Descriptor::ShWsh(ref miniscript) => miniscript.serialize().to_v0_p2wsh().to_p2sh(),
        }
    }
}

impl<P: ToString> Descriptor<P> {
    /// Attempts to produce a satisfying witness or scriptSig, as the case may be,
    /// for the descriptor
    pub fn satisfy<F, H>(
        &self,
        keyfn: Option<&F>,
        hashfn: Option<&H>,
        age: u32,
    ) -> Result<Vec<Vec<u8>>, Error>
        where F: Fn(&P) -> Option<(secp256k1::Signature, Option<SigHashType>)>,
              H: Fn(sha256::Hash) -> Option<[u8; 32]>
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
                        let sub = Miniscript::from_tree(&newtop.args[0])?;
                        Ok(Descriptor::ShWsh(sub))
                    }
                    ("wpkh", 1) => expression::terminal(
                        &newtop.args[0],
                        |pk| P::from_str(pk).map(Descriptor::ShWpkh)
                    ),
                    _ => {
                        let sub = Miniscript::from_tree(&top.args[0])?;
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
            Descriptor::ShWpkh(ref p) => write!(f, "sh(wpkh({:?}))", p),
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
            Descriptor::ShWpkh(ref p) => write!(f, "sh(wpkh({}))", p),
            Descriptor::Sh(ref sub) => write!(f, "sh({})", sub),
            Descriptor::Wsh(ref sub) => write!(f, "wsh({})", sub),
            Descriptor::ShWsh(ref sub) => write!(f, "sh(wsh({}))", sub),
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{self, PublicKey};
    use bitcoin::blockdata::{opcodes, script};
    use bitcoin_hashes::{hash160, sha256};
    use bitcoin_hashes::hex::FromHex;

    use std::str::FromStr;

    use Descriptor;

    #[test]
    fn parse_descriptor() {
        assert!(Descriptor::<PublicKey>::from_str("(").is_err());
        assert!(Descriptor::<PublicKey>::from_str("(x()").is_err());
        assert!(Descriptor::<PublicKey>::from_str("(\u{7f}()3").is_err());
        assert!(Descriptor::<PublicKey>::from_str("pk()").is_err());

        assert!(Descriptor::<PublicKey>::from_str("pk(020000000000000000000000000000000000000000000000000000000000000002)").is_ok());
    }

    #[test]
    pub fn script_pubkey() {
        let bare = Descriptor::<PublicKey>::from_str(
            "time(1000)"
        ).unwrap();
        assert_eq!(
            bare.script_pubkey(),
            bitcoin::Script::from(vec![0x02, 0xe8, 0x03, 0xb2]),
        );

        let pk = Descriptor::<PublicKey>::from_str(
            "pk(020000000000000000000000000000000000000000000000000000000000000002)"
        ).unwrap();
        assert_eq!(
            pk.script_pubkey(),
            bitcoin::Script::from(vec![
                0x21,
                0x02,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                0xac,
            ]),
        );

        let pkh = Descriptor::<PublicKey>::from_str(
            "pkh(020000000000000000000000000000000000000000000000000000000000000002)"
        ).unwrap();
        assert_eq!(
            pkh.script_pubkey(),
            script::Builder::new()
                .push_opcode(opcodes::all::OP_DUP)
                .push_opcode(opcodes::all::OP_HASH160)
                .push_slice(&hash160::Hash::from_hex(
                    "84e9ed95a38613f0527ff685a9928abe2d4754d4",
                ).unwrap()[..])
                .push_opcode(opcodes::all::OP_EQUALVERIFY)
                .push_opcode(opcodes::all::OP_CHECKSIG)
                .into_script(),
        );

        let wpkh = Descriptor::<PublicKey>::from_str(
            "wpkh(020000000000000000000000000000000000000000000000000000000000000002)"
        ).unwrap();
        assert_eq!(
            wpkh.script_pubkey(),
            script::Builder::new()
                .push_opcode(opcodes::all::OP_PUSHBYTES_0)
                .push_slice(&hash160::Hash::from_hex(
                    "84e9ed95a38613f0527ff685a9928abe2d4754d4",
                ).unwrap()[..])
                .into_script(),
        );

        let shwpkh = Descriptor::<PublicKey>::from_str(
            "sh(wpkh(020000000000000000000000000000000000000000000000000000000000000002))"
        ).unwrap();
        assert_eq!(
            shwpkh.script_pubkey(),
            script::Builder::new()
                .push_opcode(opcodes::all::OP_HASH160)
                .push_slice(&hash160::Hash::from_hex(
                    "f1c3b9a431134cb90a500ec06e0067cfa9b8bba7",
                ).unwrap()[..])
                .push_opcode(opcodes::all::OP_EQUAL)
                .into_script(),
        );

        let sh = Descriptor::<PublicKey>::from_str(
            "sh(pk(020000000000000000000000000000000000000000000000000000000000000002))"
        ).unwrap();
        assert_eq!(
            sh.script_pubkey(),
            script::Builder::new()
                .push_opcode(opcodes::all::OP_HASH160)
                .push_slice(&hash160::Hash::from_hex(
                    "aa5282151694d3f2f32ace7d00ad38f927a33ac8",
                ).unwrap()[..])
                .push_opcode(opcodes::all::OP_EQUAL)
                .into_script(),
        );

        let wsh = Descriptor::<PublicKey>::from_str(
            "wsh(pk(020000000000000000000000000000000000000000000000000000000000000002))"
        ).unwrap();
        assert_eq!(
            wsh.script_pubkey(),
            script::Builder::new()
                .push_opcode(opcodes::all::OP_PUSHBYTES_0)
                .push_slice(&sha256::Hash::from_hex(
                    "f9379edc8983152dc781747830075bd53896e4b0ce5bff73777fd77d124ba085",
                ).unwrap()[..])
                .into_script(),
        );

        let shwsh = Descriptor::<PublicKey>::from_str(
            "sh(wsh(pk(020000000000000000000000000000000000000000000000000000000000000002)))"
        ).unwrap();
        assert_eq!(
            shwsh.script_pubkey(),
            script::Builder::new()
                .push_opcode(opcodes::all::OP_HASH160)
                .push_slice(&hash160::Hash::from_hex(
                    "4bec5d7feeed99e1d0a23fe32a4afe126a7ff07e",
                ).unwrap()[..])
                .push_opcode(opcodes::all::OP_EQUAL)
                .into_script(),
        );
    }
}

