//! Tools for creating Descriptor and witness stack from given scriptpubkey and corresponding
//! scriptsig and witness.
//!

use bitcoin::{self, Script};

use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::Instruction;
use descriptor::satisfied_constraints::Error as IntError;
use descriptor::satisfied_constraints::{Stack, StackElement};
use descriptor::Descriptor;
use miniscript::{Legacy, Miniscript, Segwitv0};
use Error;
use ToPublicKey;

/// Helper function for creating StackElement from Push instructions. Special case required for
/// handling OP_PUSHNUM_1.
/// Dissatisfied is Pushbytes0 and witness are mapped to Pushbytes instruction in scriptsig and
/// satisfied is mapped as OP_PUSHNUM_1.
/// Other opcodes are considered Non-standard in bitcoin core.
/// Miniscript should not use other pushes apart from PUSHNUM_1. This will err on receiving anything
/// which is not PUSHBYTES, OR PUSHNUM_1 as other things are expected to happen in Miniscript
///
/// NOTE: Miniscript pushes should only be either boolean, 1 or 0, signatures, and hash preimages.
/// As per the current implementation, PUSH_NUM2 results in an error
fn instr_to_stackelem<'txin>(ins: &Instruction<'txin>) -> Result<StackElement<'txin>, Error> {
    match *ins {
        //Also covers the dissatisfied case as PushBytes0
        Instruction::PushBytes(v) => Ok(StackElement::from(v)),
        Instruction::Op(opcodes::all::OP_PUSHNUM_1) => Ok(StackElement::Satisfied),
        _ => Err(Error::BadScriptSig),
    }
}

/// Helper function which splits the scriptsig into 2 parts returns the corresponding elements.
/// Usually used for scripts which have top element as Pk (p2pkh) or redeem script(p2sh).
/// Converts the other script elements into Vec<StackElement>
fn parse_scriptsig_top<'txin>(
    script_sig: &'txin bitcoin::Script,
) -> Result<(Vec<u8>, Stack<'txin>), Error> {
    let stack: Result<Vec<StackElement>, Error> = script_sig
        .iter(true)
        .map(|instr| instr_to_stackelem(&instr))
        .collect();
    let mut stack = stack?;
    if let Some(StackElement::Push(pk_bytes)) = stack.pop() {
        Ok((pk_bytes.to_vec(), Stack(stack)))
    } else {
        Err(Error::InterpreterError(IntError::UnexpectedStackEnd))
    }
}

/// Creates a pk descriptor based on scriptsig and script_pubkey.
/// Pushes all remaining witness elements into witness<StackElement>
fn verify_p2pk<'txin>(
    script_pubkey: &bitcoin::Script,
    script_sig: &'txin bitcoin::Script,
    witness: &[Vec<u8>],
) -> Result<(Descriptor<bitcoin::PublicKey>, Stack<'txin>), Error> {
    let script_pubkey_len = script_pubkey.len();
    let pk_bytes = &script_pubkey.to_bytes();
    if let Ok(pk) = bitcoin::PublicKey::from_slice(&pk_bytes[1..script_pubkey_len - 1]) {
        let stack: Result<Vec<StackElement>, Error> = script_sig
            .iter(true)
            .map(|instr| instr_to_stackelem(&instr))
            .collect();
        if !witness.is_empty() {
            Err(Error::NonEmptyWitness)
        } else {
            Ok((Descriptor::Pk(pk), Stack(stack?)))
        }
    } else {
        Err(Error::InterpreterError(IntError::PubkeyParseError))
    }
}
/// Helper to create a wpkh descriptor based on script_pubkey and witness. Validates the pubkey hash
/// and pushes rest of witness to Vec<StackElement> as is.
/// This does not check the signature, only creates the corresponding descriptor
fn verify_p2wpkh<'txin>(
    script_pubkey: &bitcoin::Script,
    script_sig: &bitcoin::Script,
    witness: &'txin [Vec<u8>],
) -> Result<(bitcoin::PublicKey, Stack<'txin>), Error> {
    //script_sig must be empty
    if !script_sig.is_empty() {
        return Err(Error::NonEmptyScriptSig);
    }
    if let Some((pk_bytes, witness)) = witness.split_last() {
        if let Ok(pk) = bitcoin::PublicKey::from_slice(pk_bytes) {
            let addr = bitcoin::Address::p2wpkh(&pk.to_public_key(), bitcoin::Network::Bitcoin);
            if addr.script_pubkey() != *script_pubkey {
                return Err(Error::InterpreterError(IntError::PkEvaluationError(pk)));
            }
            let stack: Vec<StackElement> = witness
                .iter()
                .map(|elem| StackElement::from(elem))
                .collect();
            Ok((pk, Stack(stack)))
        } else {
            Err(Error::InterpreterError(IntError::PubkeyParseError))
        }
    } else {
        Err(Error::InterpreterError(IntError::UnexpectedStackEnd))
    }
}

/// Helper for creating a wsh descriptor based on script_pubkey and witness. Validates the wsh
/// hash based on witness script, pops the witness script from the stack and returns
/// witness Vec<StackElement>. Does not interpret/check the witness against the miniscript inside
/// the descriptor
fn verify_wsh<'txin>(
    script_pubkey: &bitcoin::Script,
    script_sig: &bitcoin::Script,
    witness: &'txin [Vec<u8>],
) -> Result<(Miniscript<bitcoin::PublicKey, Segwitv0>, Stack<'txin>), Error> {
    if !script_sig.is_empty() {
        return Err(Error::NonEmptyScriptSig);
    }
    if let Some((witness_script, witness)) = witness.split_last() {
        let witness_script = Script::from(witness_script.clone());
        if witness_script.to_v0_p2wsh() != *script_pubkey {
            return Err(Error::IncorrectScriptHash);
        }
        let ms = Miniscript::<bitcoin::PublicKey, Segwitv0>::parse(&witness_script)?;
        //only iter till len -1 to not include the witness script
        let stack: Vec<StackElement> = witness
            .iter()
            .map(|elem| StackElement::from(elem))
            .collect();
        Ok((ms, Stack(stack)))
    } else {
        Err(Error::InterpreterError(IntError::UnexpectedStackEnd))
    }
}

/// Creates a pkh descriptor based on scriptsig and script_pubkey. Validates the hash checks for
/// p2pkh against top element(pk) and pushes all remaining witness elements into witness<StackElement>
fn verify_p2pkh<'txin>(
    script_pubkey: &bitcoin::Script,
    script_sig: &'txin bitcoin::Script,
    witness: &[Vec<u8>],
) -> Result<(Descriptor<bitcoin::PublicKey>, Stack<'txin>), Error> {
    let (pk_bytes, stack) = parse_scriptsig_top(script_sig)?;
    if let Ok(pk) = bitcoin::PublicKey::from_slice(&pk_bytes) {
        let addr = bitcoin::Address::p2pkh(&pk.to_public_key(), bitcoin::Network::Bitcoin);
        if !witness.is_empty() {
            return Err(Error::NonEmptyWitness);
        }
        if *script_pubkey != addr.script_pubkey() {
            return Err(Error::IncorrectPubkeyHash);
        }
        Ok((Descriptor::Pkh(pk), stack))
    } else {
        Err(Error::InterpreterError(IntError::PubkeyParseError))
    }
}

/// Helper for creating a p2sh descriptor based on script_pubkey and witness. Validates the p2sh
/// hash based on redeem script, pops the redeem script from the script sig stack, translates other
/// elements from scriptsig into Vec<StackElement>
fn verify_p2sh<'txin>(
    script_pubkey: &bitcoin::Script,
    script_sig: &'txin bitcoin::Script,
) -> Result<(Script, Stack<'txin>), Error> {
    let (redeem_script, stack) = parse_scriptsig_top(script_sig)?;
    let redeem_script = Script::from(redeem_script);
    if redeem_script.to_p2sh() != *script_pubkey {
        return Err(Error::IncorrectScriptHash);
    }
    Ok((redeem_script, stack))
}

/// Figures out the the type of descriptor based on scriptpubkey, witness and scriptsig.
/// Outputs a `Descriptor` and `Stack` which can be directly fed into the
/// interpreter. All script_sig and witness are translated into a single witness stack.
/// 1. `PK`: creates a `Pk` descriptor and translates the scriptsig to a `Stack`
/// 2. `Pkh`: Removes top element(pk) and validates pubkey hash, pushes rest of witness to
/// a `Stack` and outputs a `Pkh` descriptor
/// 3. `Wphk`: translates witness to a `Stack`, validates sig and pubkey hash
/// and outputs a `Wpkh` descriptor
/// 4. `Wsh`: pops witness script and checks wsh output hash, translates remaining witness elements
/// to a `Stack` and outputs a `Wsh` descriptor. Does not check miniscript inside the descriptor
/// 5. `Bare`: translates script_sig to a `Stack` and script_pubkey to miniscript
/// 6. `Sh`: Checks redeem_script hash, translates remaining elements from script_sig to
/// a `Stack` and redeem script to miniscript. Does not check the miniscript
/// 7. `ShWpkh`: Checks redeem_script hash, translates remaining elements from script_sig to
/// a `Stack` and validates `Wpkh` sig, pubkey.
/// 8. `ShWsh`: Checks witness script hash, pops witness script and converts it to miniscript.
/// translates the remaining witness to a `Stack`
pub fn from_txin_with_witness_stack<'txin>(
    script_pubkey: &bitcoin::Script,
    script_sig: &'txin bitcoin::Script,
    witness: &'txin [Vec<u8>],
) -> Result<(Descriptor<bitcoin::PublicKey>, Stack<'txin>), Error> {
    if script_pubkey.is_p2pk() {
        verify_p2pk(script_pubkey, script_sig, witness)
    } else if script_pubkey.is_p2pkh() {
        verify_p2pkh(script_pubkey, script_sig, witness)
    } else if script_pubkey.is_v0_p2wpkh() {
        let (pk, stack) = verify_p2wpkh(script_pubkey, script_sig, witness)?;
        Ok((Descriptor::Wpkh(pk), stack))
    } else if script_pubkey.is_v0_p2wsh() {
        let (ms, stack) = verify_wsh(script_pubkey, script_sig, witness)?;
        Ok((Descriptor::Wsh(ms), stack))
    } else if script_pubkey.is_p2sh() {
        let (redeem_script, stack) = verify_p2sh(script_pubkey, script_sig)?;
        if redeem_script.is_v0_p2wpkh() {
            //Therefore while calling verify_wpkh, an argument of Script::new() is passed instead
            //of script_sig. The redeem_script becomes the script_pubkey
            let (pk, stack) = verify_p2wpkh(&redeem_script, &Script::new(), witness)?;
            Ok((Descriptor::ShWpkh(pk), stack))
        } else if redeem_script.is_v0_p2wsh() {
            //Therefore while calling verify_wpkh, an argument of Script::new() is passed instead
            //of script_sig. The redeem_script becomes the script_pubkey
            let (ms, stack) = verify_wsh(&redeem_script, &Script::new(), witness)?;
            Ok((Descriptor::ShWsh(ms), stack))
        } else {
            if !witness.is_empty() {
                return Err(Error::NonEmptyWitness);
            }
            let ms = Miniscript::<bitcoin::PublicKey, Legacy>::parse(&redeem_script)?;
            Ok((Descriptor::Sh(ms), stack))
        }
    } else {
        //bare
        let stack: Result<Vec<StackElement>, Error> = script_sig
            .iter(true)
            .map(|instr| instr_to_stackelem(&instr))
            .collect();
        if !witness.is_empty() {
            return Err(Error::NonEmptyWitness);
        }
        let ms = Miniscript::<bitcoin::PublicKey, Legacy>::parse(script_pubkey)?;
        Ok((Descriptor::Bare(ms), Stack(stack?)))
    }
}

#[cfg(test)]
mod tests {
    use bitcoin;
    use bitcoin::blockdata::{opcodes, script};
    use bitcoin::secp256k1::{self, Secp256k1, VerifyOnly};
    use descriptor::create_descriptor::from_txin_with_witness_stack;
    use descriptor::satisfied_constraints::{Stack, StackElement};
    use std::str::FromStr;
    use ToPublicKey;
    use {Descriptor, Miniscript};

    macro_rules! stack {
        ($($data:ident$(($pushdata:expr))*),*) => (
            Stack(vec![$(StackElement::$data$(($pushdata))*),*])
        )
    }

    fn setup_keys_sigs(
        n: usize,
    ) -> (
        Vec<bitcoin::PublicKey>,
        Vec<Vec<u8>>,
        secp256k1::Message,
        Secp256k1<VerifyOnly>,
    ) {
        let secp_sign = secp256k1::Secp256k1::signing_only();
        let secp_verify = secp256k1::Secp256k1::verification_only();
        let msg = secp256k1::Message::from_slice(&b"Yoda: btc, I trust. HODL I must!"[..])
            .expect("32 bytes");
        let mut pks = vec![];
        let mut sigs = vec![];
        let mut sk = [0; 32];
        for i in 1..n + 1 {
            sk[0] = i as u8;
            sk[1] = (i >> 8) as u8;
            sk[2] = (i >> 16) as u8;

            let sk = secp256k1::SecretKey::from_slice(&sk[..]).expect("secret key");
            let pk = bitcoin::PublicKey {
                key: secp256k1::PublicKey::from_secret_key(&secp_sign, &sk),
                compressed: true,
            };
            let sig = secp_sign.sign(&msg, &sk);
            let mut sigser = sig.serialize_der().to_vec();
            sigser.push(0x01); // sighash_all
            pks.push(pk);
            sigs.push(sigser);
        }
        (pks, sigs, msg, secp_verify)
    }

    #[test]
    fn create_witness_stack() {
        let (pks, sigs, _, _) = setup_keys_sigs(10);

        //test pkh
        let script_pubkey =
            bitcoin::Address::p2pkh(&pks[0], bitcoin::Network::Bitcoin).script_pubkey();
        let script_sig = script::Builder::new()
            .push_slice(&sigs[0])
            .push_key(&pks[0])
            .into_script();
        let witness = vec![] as Vec<Vec<u8>>;

        let (des, stack) = from_txin_with_witness_stack(&script_pubkey, &script_sig, &witness)
            .expect("Descriptor/Witness stack creation to succeed");
        assert_eq!(des_str!("pkh({})", pks[0]), des);
        assert_eq!(stack, stack![Push(&sigs[0])]);

        //test pk
        let script_pubkey = script::Builder::new()
            .push_key(&pks[0].to_public_key())
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script();
        let script_sig = script::Builder::new().push_slice(&sigs[0]).into_script();
        let witness = vec![] as Vec<Vec<u8>>;

        let (des, stack) = from_txin_with_witness_stack(&script_pubkey, &script_sig, &witness)
            .expect("Descriptor/Witness stack creation to succeed");
        assert_eq!(des_str!("pk({})", pks[0]), des);
        assert_eq!(stack, stack![Push(&sigs[0])]);

        //test wpkh
        let script_pubkey =
            bitcoin::Address::p2wpkh(&pks[1], bitcoin::Network::Bitcoin).script_pubkey();
        let script_sig = script::Builder::new().into_script();
        let witness = vec![sigs[1].clone(), pks[1].clone().to_bytes()];
        let (des, stack) = from_txin_with_witness_stack(&script_pubkey, &script_sig, &witness)
            .expect("Descriptor/Witness stack creation to succeed");
        assert_eq!(des_str!("wpkh({})", pks[1]), des);
        assert_eq!(stack, stack![Push(&sigs[1])]);

        //test Wsh: and(pkv, pk). Note this does not check miniscript.
        let ms = ms_str!("and_v(vc:pk_k({}),c:pk_k({}))", pks[0], pks[1]);
        let script_pubkey =
            bitcoin::Address::p2wsh(&ms.encode(), bitcoin::Network::Bitcoin).script_pubkey();
        let script_sig = script::Builder::new().into_script();
        let witness = vec![sigs[1].clone(), sigs[0].clone(), ms.encode().to_bytes()];
        let (des, stack) = from_txin_with_witness_stack(&script_pubkey, &script_sig, &witness)
            .expect("Descriptor/Witness stack creation to succeed");
        assert_eq!(Descriptor::Wsh(ms.clone()), des);
        assert_eq!(stack, stack![Push(&sigs[1]), Push(&sigs[0])]);

        //test Bare: and(pkv, pk). Note this does not check miniscript.
        let ms = ms_str!("or_b(c:pk_k({}),sc:pk_k({}))", pks[0], pks[1]);
        let script_pubkey = ms.encode();
        let script_sig = script::Builder::new()
            .push_int(0)
            .push_slice(&sigs[0])
            .into_script();
        let witness = vec![] as Vec<Vec<u8>>;
        let (des, stack) = from_txin_with_witness_stack(&script_pubkey, &script_sig, &witness)
            .expect("Descriptor/Witness stack creation to succeed");
        assert_eq!(Descriptor::Bare(ms.clone()), des);
        assert_eq!(stack, stack![Dissatisfied, Push(&sigs[0])]);

        //test Sh: and(pkv, pk). Note this does not check miniscript.
        let ms = ms_str!("c:or_i(pk_k({}),pk_k({}))", pks[0], pks[1]);
        let script_pubkey =
            bitcoin::Address::p2sh(&ms.encode(), bitcoin::Network::Bitcoin).script_pubkey();
        let script_sig = script::Builder::new()
            .push_slice(&sigs[0])
            .push_int(1)
            .push_slice(&ms.encode().to_bytes())
            .into_script();
        let witness = vec![] as Vec<Vec<u8>>;
        let (des, stack) = from_txin_with_witness_stack(&script_pubkey, &script_sig, &witness)
            .expect("Descriptor/Witness stack creation to succeed");
        assert_eq!(Descriptor::Sh(ms.clone()), des);
        assert_eq!(stack, stack![Push(&sigs[0]), Satisfied]);

        //test Shwsh: and(pkv, pk). Note this does not check miniscript.
        //This test passes incorrect witness argument.
        let ms = ms_str!("and_v(vc:pk_k({}),c:pk_k({}))", pks[0], pks[1]);
        let script_pubkey =
            bitcoin::Address::p2shwsh(&ms.encode(), bitcoin::Network::Bitcoin).script_pubkey();
        let script_sig = script::Builder::new()
            .push_slice(&ms.encode().to_v0_p2wsh().to_bytes())
            .into_script();
        let witness = vec![sigs[1].clone(), sigs[3].clone(), ms.encode().to_bytes()];
        let (des, stack) = from_txin_with_witness_stack(&script_pubkey, &script_sig, &witness)
            .expect("Descriptor/Witness stack creation to succeed");
        assert_eq!(Descriptor::ShWsh(ms.clone()), des);
        assert_eq!(stack, stack![Push(&sigs[1]), Push(&sigs[3])]);

        //test shwpkh
        let script_pubkey =
            bitcoin::Address::p2shwpkh(&pks[2], bitcoin::Network::Bitcoin).script_pubkey();
        let redeem_script =
            bitcoin::Address::p2wpkh(&pks[2], bitcoin::Network::Bitcoin).script_pubkey();
        let script_sig = script::Builder::new()
            .push_slice(&redeem_script.to_bytes())
            .into_script();
        let witness = vec![sigs[2].clone(), pks[2].clone().to_bytes()];
        let (des, stack) = from_txin_with_witness_stack(&script_pubkey, &script_sig, &witness)
            .expect("Descriptor/Witness stack creation to succeed");
        assert_eq!(des_str!("sh(wpkh({}))", pks[2]), des);
        assert_eq!(stack, stack![Push(&sigs[2])]);
    }
}
