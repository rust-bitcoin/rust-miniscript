// Miniscript
// Written in 2019 by
//     Sanket Kanjular and Andrew Poelstra
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

use bitcoin;
use bitcoin::hashes::{hash160, sha256, Hash};

use miniscript::context::NoChecks;
use {Miniscript, MiniscriptKey, NullCtx};
use super::{Error, Stack, stack};

/// Attempts to parse a slice as a Bitcoin public key, checking compressedness
/// if asked to, but otherwise dropping it
fn pk_from_slice(
    slice: &[u8],
    require_compressed: bool,
) -> Result<bitcoin::PublicKey, Error> {
    if let Ok(pk) = bitcoin::PublicKey::from_slice(slice) {
        if require_compressed && !pk.compressed {
            Err(Error::UncompressedPubkey)
        } else {
            Ok(pk)
        }
    } else {
        Err(Error::PubkeyParseError)
    }
}

fn pk_from_stackelem<'a>(
    elem: &stack::Element<'a>,
    require_compressed: bool,
) -> Result<bitcoin::PublicKey, Error> {
    let slice = if let stack::Element::Push(slice) = *elem {
        slice
    } else {
        return Err(Error::PubkeyParseError);
    };
    pk_from_slice(slice, require_compressed)
}

fn script_from_stackelem<'a>(
    elem: &stack::Element<'a>,
) -> Result<Miniscript<bitcoin::PublicKey, NoChecks>, Error> {
    match *elem {
        stack::Element::Push(sl) => Miniscript::parse_insane(&bitcoin::Script::from(sl.to_owned()))
            .map_err(Error::from),
        stack::Element::Satisfied => Miniscript::from_ast(::Terminal::True)
            .map_err(Error::from),
        stack::Element::Dissatisfied => Miniscript::from_ast(::Terminal::False)
            .map_err(Error::from),
    }
}

/// Helper type to indicate the origin of the bare pubkey that the interpereter uses
pub enum PubkeyType {
    Pk,
    Pkh,
    Wpkh,
}

/// Helper type to indicate the origin of the bare miniscript that the interpereter uses
pub enum ScriptType {
    Bare,
    Sh,
    Wsh,
    ShWsh,
}

/// Structure representing a script under evaluation as a Miniscript
pub enum Inner {
    /// The script being evaluated is a simple public key check (pay-to-pk,
    /// pay-to-pkhash or pay-to-witness-pkhash)
    PublicKey(bitcoin::PublicKey, PubkeyType),
    /// The script being evaluated is an actual script
    Script(Miniscript<bitcoin::PublicKey, NoChecks>, ScriptType),
}

// The `Script` returned by this method is always generated/cloned ... when
// rust-bitcoin is updated to use a copy-on-write internal representation we
// should revisit this and return references to the actual txdata wherever
// possible
/// Parses an `Inner` and appropriate `Stack` from completed transaction data,
/// as well as the script that should be used as a scriptCode in a sighash
pub fn from_txdata<'txin>(
    spk: &bitcoin::Script,
    script_sig: &'txin bitcoin::Script,
    witness: &'txin [Vec<u8>],
) -> Result<(Inner, Stack<'txin>, bitcoin::Script), Error> {
    let mut ssig_stack: Stack = script_sig
        .instructions_minimal()
        .map(stack::Element::from_instruction)
        .collect::<Result<Vec<stack::Element>, Error>>()?
        .into();
    let mut wit_stack: Stack = witness
        .iter()
        .map(stack::Element::from)
        .collect::<Vec<stack::Element>>()
        .into();

    // ** pay to pubkey **
    if spk.is_p2pk() {
        if !wit_stack.is_empty() {
            Err(Error::NonEmptyWitness)
        } else {
            Ok((
                Inner::PublicKey(pk_from_slice(&spk[1..spk.len() - 1], false)?, PubkeyType::Pk),
                ssig_stack,
                spk.clone(),
            ))
        }
    // ** pay to pubkeyhash **
    } else if spk.is_p2pkh() {
        if !wit_stack.is_empty() {
            Err(Error::NonEmptyWitness)
        } else {
            match ssig_stack.pop() {
                Some(elem) => {
                    let pk = pk_from_stackelem(&elem, false)?;
                    if *spk == bitcoin::Script::new_p2pkh(&pk.to_pubkeyhash().into()) {
                        Ok((Inner::PublicKey(pk, PubkeyType::Pkh), ssig_stack, spk.clone()))
                    } else {
                        Err(Error::IncorrectPubkeyHash)
                    }
                },
                None => Err(Error::UnexpectedStackEnd),
            }
        }
    // ** pay to witness pubkeyhash **
    } else if spk.is_v0_p2wpkh() {
        if !ssig_stack.is_empty() {
            Err(Error::NonEmptyScriptSig)
        } else {
            match wit_stack.pop() {
                Some(elem) => {
                    let pk = pk_from_stackelem(&elem, true)?;
                    if *spk == bitcoin::Script::new_v0_wpkh(&pk.to_pubkeyhash().into()) {
                        Ok((
                            Inner::PublicKey(pk, PubkeyType::Wpkh),
                            wit_stack,
                            bitcoin::Script::new_p2pkh(&pk.to_pubkeyhash().into()), // bip143, why..
                        ))
                    } else {
                        Err(Error::IncorrectWPubkeyHash)
                    }
                },
                None => Err(Error::UnexpectedStackEnd),
            }
        }
    // ** pay to witness scripthash **
    } else if spk.is_v0_p2wsh() {
        if !ssig_stack.is_empty() {
            Err(Error::NonEmptyScriptSig)
        } else {
            match wit_stack.pop() {
                Some(elem) => {
                    let miniscript = script_from_stackelem(&elem)?;
                    let script = miniscript.encode(NullCtx);
                    let scripthash = sha256::Hash::hash(&script[..]);
                    if *spk == bitcoin::Script::new_v0_wsh(&scripthash.into()) {
                        Ok((Inner::Script(miniscript, ScriptType::Wsh), wit_stack, script))
                    } else {
                        Err(Error::IncorrectWScriptHash)
                    }
                },
                None => Err(Error::UnexpectedStackEnd),
            }
        }
    // ** pay to scripthash **
    } else if spk.is_p2sh() {
        match ssig_stack.pop() {
            Some(elem) => {
                // ** p2sh-wrapped wsh **
                if let stack::Element::Push(slice) = elem {
                    let scripthash = hash160::Hash::hash(slice);
                    if *spk != bitcoin::Script::new_p2sh(&scripthash.into()) {
                        return Err(Error::IncorrectScriptHash);
                    }
                    if slice.len() == 34 && slice[0] == 0 && slice[1] == 32 {
                        return match wit_stack.pop() {
                            Some(elem) => {
                                if !ssig_stack.is_empty() {
                                    Err(Error::NonEmptyScriptSig)
                                } else {
                                    let miniscript = script_from_stackelem(&elem)?;
                                    let script = miniscript.encode(NullCtx);
                                    let scripthash = sha256::Hash::hash(&script[..]);
                                    if slice == &bitcoin::Script::new_v0_wsh(&scripthash.into())[..] {
                                        Ok((Inner::Script(miniscript, ScriptType::ShWsh), wit_stack, script))
                                    } else {
                                        Err(Error::IncorrectWScriptHash)
                                    }
                                }
                            },
                            None => Err(Error::UnexpectedStackEnd),
                        }
                    }
                }
                // normal p2sh
                let miniscript = script_from_stackelem(&elem)?;
                let script = miniscript.encode(NullCtx);
                if wit_stack.is_empty() {
                    let scripthash = hash160::Hash::hash(&script[..]);
                    if *spk == bitcoin::Script::new_p2sh(&scripthash.into()) {
                        Ok((Inner::Script(miniscript, ScriptType::Sh), ssig_stack, script))
                    } else {
                        Err(Error::IncorrectScriptHash)
                    }
                } else {
                    Err(Error::NonEmptyWitness)
                }
            },
            None => Err(Error::UnexpectedStackEnd),
        }
    // ** bare script **
    } else {
        if wit_stack.is_empty() {
            let miniscript = Miniscript::parse(spk)?;
            Ok((Inner::Script(miniscript, ScriptType::Bare), ssig_stack, spk.clone()))
        } else {
            Err(Error::NonEmptyWitness)
        }
    }
}



