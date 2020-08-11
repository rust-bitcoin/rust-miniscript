// Miniscript
// Written in 2019 by
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

//! # Partially-Signed Bitcoin Transactions
//!
//! This module implements the Finalizer and Extractor roles defined in
//! BIP 173, PSBT, described at
//! `https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki`
//!

use std::{error, fmt};

use bitcoin::util::psbt;
use bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
use bitcoin::{self, secp256k1};

use super::descriptor::DescriptorPublicKey;
use miniscript::{Legacy, Segwitv0};
use BitcoinSig;
use Miniscript;
use Satisfier;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    InvalidSignature {
        pubkey: bitcoin::PublicKey,
        index: usize,
    },
    MissingWitness(usize),
    MissingWitnessScript(usize),
    WrongInputCount {
        in_tx: usize,
        in_map: usize,
    },
    WrongSigHashFlag {
        required: bitcoin::SigHashType,
        got: bitcoin::SigHashType,
        pubkey: bitcoin::PublicKey,
        index: usize,
    },
}

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        None
    }

    fn description(&self) -> &str {
        ""
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidSignature { pubkey, index } => write!(
                f,
                "PSBT: bad signature with key {} on input {}",
                pubkey.key, index
            ),
            Error::MissingWitness(index) => {
                write!(f, "PSBT is missing witness for input {}", index)
            }
            Error::MissingWitnessScript(index) => {
                write!(f, "PSBT is missing witness script for input {}", index)
            }
            Error::WrongInputCount { in_tx, in_map } => write!(
                f,
                "PSBT had {} inputs in transaction but {} inputs in map",
                in_tx, in_map
            ),
            Error::WrongSigHashFlag {
                required,
                got,
                pubkey,
                index,
            } => write!(
                f,
                "PSBT: signature on input {} with key {} had \
                 sighashflag {:?} rather than required {:?}",
                index, pubkey.key, got, required
            ),
        }
    }
}

impl Satisfier<bitcoin::PublicKey> for psbt::Input {
    fn lookup_sig(&self, pk: &bitcoin::PublicKey) -> Option<BitcoinSig> {
        if let Some(rawsig) = self.partial_sigs.get(pk) {
            let (flag, sig) = rawsig.split_last().unwrap();
            let flag = bitcoin::SigHashType::from_u32(*flag as u32);
            let sig = match secp256k1::Signature::from_der(sig) {
                Ok(sig) => sig,
                Err(..) => return None,
            };
            Some((sig, flag))
        } else {
            None
        }
    }
}

impl Satisfier<DescriptorPublicKey> for psbt::Input {
    fn lookup_sig(&self, descriptor_key: &DescriptorPublicKey) -> Option<BitcoinSig> {
        let pubkey = match descriptor_key {
            &DescriptorPublicKey::PubKey(pubkey) => Some(pubkey),
            &DescriptorPublicKey::XPub(ref xpub) => self
                .hd_keypaths
                .iter()
                .filter_map(|(&pubkey, &(fingerprint, ref path))| {
                    if xpub.matches(fingerprint.clone(), &path).is_some() {
                        Some(pubkey)
                    } else {
                        None
                    }
                })
                .next(),
        };

        pubkey.and_then(|pk| self.lookup_sig(&pk))
    }
}

fn sanity_check(psbt: &Psbt) -> Result<(), super::Error> {
    if psbt.global.unsigned_tx.input.len() != psbt.inputs.len() {
        return Err(Error::WrongInputCount {
            in_tx: psbt.global.unsigned_tx.input.len(),
            in_map: psbt.inputs.len(),
        }
        .into());
    }

    Ok(())
}

pub fn finalize(psbt: &mut Psbt) -> Result<(), super::Error> {
    sanity_check(psbt)?;

    // Check well-formedness of input data
    for (n, input) in psbt.inputs.iter().enumerate() {
        if let Some(target) = input.sighash_type {
            for (key, rawsig) in &input.partial_sigs {
                if rawsig.is_empty() {
                    return Err(Error::InvalidSignature {
                        pubkey: *key,
                        index: n,
                    }
                    .into());
                }
                let (flag, sig) = rawsig.split_last().unwrap();
                let flag = bitcoin::SigHashType::from_u32(*flag as u32);
                if target != flag {
                    return Err(Error::WrongSigHashFlag {
                        required: target,
                        got: flag,
                        pubkey: *key,
                        index: n,
                    }
                    .into());
                }
                if let Err(_) = secp256k1::Signature::from_der(sig) {
                    return Err(Error::InvalidSignature {
                        pubkey: *key,
                        index: n,
                    }
                    .into());
                }
                // TODO check signature
            }
        }
    }

    // Actually construct the witnesses
    for (n, input) in psbt.inputs.iter_mut().enumerate() {
        // Only one of PSBT redeem script or witness script must be set in the
        // PSBT input
        if let Some(script) = input.witness_script.as_ref() {
            let miniscript = Miniscript::<_, Segwitv0>::parse(script)?;
            input.final_script_witness = miniscript.satisfy(&*input);
        } else if let Some(script) = input.redeem_script.as_ref() {
            let miniscript = Miniscript::<_, Legacy>::parse(script)?;
            input.final_script_witness = miniscript.satisfy(&*input);
        } else {
            return Err(Error::MissingWitnessScript(n).into());
        }
    }
    Ok(())
}

pub fn extract(psbt: &mut Psbt) -> Result<bitcoin::Transaction, super::Error> {
    sanity_check(psbt)?;

    let mut ret = psbt.global.unsigned_tx.clone();
    for (n, input) in psbt.inputs.iter().enumerate() {
        if let Some(witness) = input.final_script_witness.as_ref() {
            ret.input[n].witness = witness.clone();
        } else {
            return Err(Error::MissingWitness(n).into());
        }
    }

    unimplemented!()
}
