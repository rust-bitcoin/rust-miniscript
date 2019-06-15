//! Tools for creating Descriptor and witness stack from given scriptpubkey and corresponding
//! scriptsig and witness.
//!

use bitcoin::{self, Script, PublicKey};

use descriptor::Descriptor;
use miniscript::Miniscript;
use miniscript::evaluate::StackElement;
use Error;
use ToPublicKey;
use bitcoin::blockdata::script::Instruction;
use bitcoin::blockdata::opcodes;

/// Helper function for creating StackElement from Push instructions. Special case required for
/// handling OP_PUSHNUM_1.
/// Dissatisfied is Pushbytes0 and witness are mapped to Pushbytes instruction in scriptsig and
/// satisfied is mapped as OP_PUSHNUM_1.
/// Other opcodes are considered Non-standard in bitcoin core.
/// Miniscript should not use other pushes apart from PUSHNUM_1. This will err on reciving anything
/// which is not PUSHBYTES, OR PUSHNUM_1 as other things are expected to happen in Miniscript
///
/// NOTE: Miniscript pushes should only be either boolean, 1 or 0, signatures, and hash preimages.
/// As per the current implementation, PUSH_NUM2 results in an error
fn instr_to_stackelem(ins: Instruction) -> Result< StackElement, Error> {
    match ins {
        //Also covers the dissatisfied case as PushBytes0
        Instruction::PushBytes(v) => Ok(StackElement::from(v.to_vec())),
        Instruction::Op(opcodes::all::OP_PUSHNUM_1) => Ok(StackElement::Satisfied),
        _ => Err(Error::BadDescriptor),
    }
}

/// Helper function which splits the scriptsig into 2 parts returns the corresponding elements.
/// Usually used for scripts which have top element as Pk (p2pkh) or redeem script(p2sh).
/// Converts the other script elements into Vec<StackElement>
fn parse_scriptsig_top(script_sig: &bitcoin::Script) -> Result<(Vec<u8>, Vec<StackElement>), Error>
{
    let instructions : Vec<Instruction> = script_sig.iter(false).collect();
    let (pk_bytes, witness) = instructions.split_last().expect("public key/Redeem script");

    let stack: Result< Vec<StackElement>, Error> = witness
        .iter()
        .map(|instr| instr_to_stackelem(instr.clone()))
        .collect();

    if let &Instruction::PushBytes(ref top) = pk_bytes {
        Ok((top.to_vec(), stack?))
    }
    else {
        Err(Error::BadDescriptor)
    }
}

/// Helper to create a wpkh descriptor based on script_pubkey and witness. Validates the pubkey hash
/// and pushes rest of witness to Vec<StackElement> as is.
/// This does not check the signature, only creates the corresponding descriptor
fn verify_wpkh(
    script_pubkey: &bitcoin::Script,
    script_sig: &bitcoin::Script,
    witness: Vec<Vec<u8>>,
) -> Result<(PublicKey, Vec<StackElement>), Error>
{
    //script_sig must be empty
    if *script_sig != Script::new(){
        return Err(Error::CouldnotEvaluate)
    }
    let (pk_bytes, witness) = witness.split_last().expect("Public key");
    let pk = bitcoin::PublicKey::from_slice(pk_bytes).expect("Public key parse");
    let addr = bitcoin::Address::p2wpkh(
        &pk.to_public_key(),
        bitcoin::Network::Bitcoin,
    );
    if addr.script_pubkey() != *script_pubkey{
        return Err(Error::CouldnotEvaluate)
    }
    let stack : Vec<StackElement> = witness.iter()
        .map(|elem| StackElement::from(elem.clone())).collect();
    Ok((pk, stack))
}

/// Helper for creating a wsh descriptor based on script_pubkey and witness. Validates the wsh
/// hash based on witness script, pops the witness script from the stack and returns
/// witness Vec<StackElement>. Does not interpret/check the witness against the miniscript inside
/// the descriptor
fn verify_wsh(
    script_pubkey: &bitcoin::Script,
    script_sig: &bitcoin::Script,
    witness: Vec<Vec<u8>>,
) -> Result<(Miniscript<PublicKey>, Vec<StackElement>), Error>
{
    if *script_sig != Script::new(){
        return Err(Error::BadDescriptor)
    }
    let (witness_script, witness) = witness.split_last().expect("Public key");
    let witness_script = Script::from(witness_script.clone());
    if witness_script.to_v0_p2wsh() != *script_pubkey{
        return Err(Error::BadDescriptor)
    }
    let ms = Miniscript::parse(&witness_script)?;
    //only iter till len -1 to not include the witness script
    let stack : Vec<StackElement> = witness.iter()
        .map(|elem| StackElement::from(elem.clone())).collect();
    Ok((ms, stack))
}


/// Creates a pkh descriptor based on scriptsig and script_pubkey. Validates the hash checks for
/// p2pkh against top element(pk) and pushes all remaining witness elements into witness<StackElement>
fn verify_p2pkh(
    script_pubkey: &bitcoin::Script,
    script_sig: &bitcoin::Script,
    witness: Vec<Vec<u8>>,
) -> Result<(Descriptor<PublicKey>, Vec<StackElement>), Error>
{
    let (pk_bytes, stack) = parse_scriptsig_top(script_sig)?;
    let pk = bitcoin::PublicKey::from_slice(&pk_bytes).expect("Public key parse");
    let addr = bitcoin::Address::p2pkh(
        &pk.to_public_key(),
        bitcoin::Network::Bitcoin,
    );
    if *script_pubkey != addr.script_pubkey() || witness.len() != 0{
        return Err(Error::BadDescriptor)
    }
    Ok((Descriptor::Pkh(pk), stack))
}

/// Helper for creating a p2sh descriptor based on script_pubkey and witness. Validates the p2sh
/// hash based on redeem script, pops the redeem script from the script sig stack, translates other
/// elements from scriptsig into Vec<StackElement>
fn verify_p2sh(
    script_pubkey: &bitcoin::Script,
    script_sig: &bitcoin::Script,
) -> Result<(Script, Vec<StackElement>), Error>
{
    let (redeem_script, stack) = parse_scriptsig_top(script_sig)?;
    let redeem_script = Script::from(redeem_script);
    if redeem_script.to_p2sh() != *script_pubkey {
        return Err(Error::BadDescriptor)
    }
    Ok((redeem_script, stack))
}

/// Figures out the the type of descriptor based on scriptpubkey, witness and scriptsig.
/// Outputs a descriptor and witness_stack for all descriptors which can be directly fed into the
/// interpreter. All script_sig and witness are translated into a single witness stack
/// Vec<StackElement>
/// 1) Pkh: Removes top element(pk) and validates pubkey hash, pushes rest of witness to
/// witness_stack<StackElement> and outputs a Pkh descriptor
/// 2) Wphk: translates witness to witness_stack<StackElement>, validates sig and pubkey hash
/// and outputs a Wpkh descriptor
/// 3) Wsh: pops witness script and checks wsh output hash, translates remaining witness elements
/// to Vec<StackElement> and outputs a Wsh descriptor. Does not check miniscript inside the descriptor
/// 4) Bare: translates script_sig to witness_stack<StackElement> and script_pubkey to miniscript
/// 5) Sh: Checks redeem_script hash, translates remaining elements from script_sig to
/// witness_stack<StackElement> and redeem script to miniscript. Does not check the miniscript
/// 6) ShWpkh: Sh: Checks redeem_script hash, translates remaining elements from script_sig to
/// witness_stack<StackElement> and validates Wpkh sig, pubkey.
/// 7) ShWsh: Checks witness script hash, pops witness script and converts it to miniscript.
/// translates the remaining witness to witness_stack<StackElement>
pub fn witness_stack(
    script_pubkey: &bitcoin::Script,
    script_sig: &bitcoin::Script,
    witness: Vec<Vec<u8>>,
) -> Result<(Descriptor<PublicKey>, Vec<StackElement>), Error>
{
    if script_pubkey.is_p2pkh(){
        verify_p2pkh(script_pubkey, script_sig, witness)
    }
    else if script_pubkey.is_v0_p2wpkh(){
        let (pk, stack) = verify_wpkh(script_pubkey, script_sig, witness)?;
        Ok((Descriptor::Wpkh(pk), stack))
    }
    else if script_pubkey.is_v0_p2wsh(){
        let (ms, stack) = verify_wsh(script_pubkey, script_sig, witness)?;
        Ok((Descriptor::Wsh(ms), stack))
    }
    else if script_pubkey.is_p2sh(){
        let (redeem_script, stack) = verify_p2sh(script_pubkey, script_sig)?;
        if redeem_script.is_v0_p2wpkh()
        {
            //ensures that scriptsig after popping redeem script contains 0 elements.
            //Therefore while calling verify_wpkh, an argument of Script::new() is passed instead
            //of script_sig. The redeem_script becomes the script_pubkey
            if stack.len() != 0{
                return Err(Error::BadDescriptor)
            }
            let (pk, stack) = verify_wpkh(&redeem_script, &Script::new(), witness)?;
            Ok((Descriptor::ShWpkh(pk), stack))
        }else if redeem_script.is_v0_p2wsh() {
            //ensures that scriptsig after popping redeem script contains 0 elements.
            //Therefore while calling verify_wpkh, an argument of Script::new() is passed instead
            //of script_sig. The redeem_script becomes the script_pubkey
            if stack.len() != 0{
                return Err(Error::BadDescriptor)
            }
            let (ms, stack) = verify_wsh(&redeem_script, &Script::new(), witness)?;
            Ok((Descriptor::ShWsh(ms), stack))
        }
        else{
            if witness.len() != 0{
                return Err(Error::BadDescriptor)
            }
            let ms = Miniscript::parse(&redeem_script)?;
            Ok((Descriptor::Sh(ms), stack))
        }
    }
    else{
        //bare
        let stack : Result <Vec<StackElement>, Error> = script_sig
            .iter(false)
            .map(|instr| instr_to_stackelem(instr.clone()))
            .collect();
        if witness.len() != 0{
            return Err(Error::BadDescriptor)
        }
        let ms = Miniscript::parse(script_pubkey)?;
        Ok((Descriptor::Bare(ms), stack?))
    }
}

#[cfg(test)]
mod tests {
    use ::{Descriptor, Miniscript};
    use descriptor::create_descriptor::witness_stack;
    use bitcoin::blockdata::script;
    use bitcoin::{self, PublicKey};
    use secp256k1::{self, Secp256k1, VerifyOnly};
    use miniscript::evaluate::StackElement;
    use miniscript::astelem::AstElem;

    fn setup_keys_sigs(n: usize)
                       -> ( Vec<PublicKey>, Vec<Vec<u8> >, secp256k1::Message, Secp256k1<VerifyOnly>) {
        let secp_sign = secp256k1::Secp256k1::signing_only();
        let secp_verify = secp256k1::Secp256k1::verification_only();
        let msg = secp256k1::Message::from_slice(
            &b"Yoda: btc, I trust. HODL I must!"[..]
        ).expect("32 bytes");
        let mut pks = vec![];
        let mut sigs = vec![];
        let mut sk = [0; 32];
        for i in 1..n+1 {
            sk[0] = i as u8;
            sk[1] = (i >> 8) as u8;
            sk[2] = (i >> 16) as u8;

            let sk = secp256k1::SecretKey::from_slice(&sk[..]).expect("secret key");
            let pk = PublicKey {
                key: secp256k1::PublicKey::from_secret_key(
                    &secp_sign,
                    &sk,
                ),
                compressed: true,
            };
            let sig = secp_sign.sign(&msg, &sk);
            let mut sigser = sig.serialize_der();
            sigser.push(0x01); // sighash_all
            pks.push(pk);
            sigs.push(sigser);
        }
        (pks, sigs, msg, secp_verify)
    }

    #[test]
    fn create_witness_stack(){
        let (pks,sigs, _, _) = setup_keys_sigs(10);

        //test pkh
        let script_pubkey =  bitcoin::Address::p2pkh(
            &pks[0],
            bitcoin::Network::Bitcoin,
        ).script_pubkey();
        let script_sig = script::Builder::new()
            .push_slice(&sigs[0])
            .push_key(&pks[0])
            .into_script();
        let witness = vec![] as Vec<Vec<u8>>;
        let (des, stack) = witness_stack(
            &script_pubkey,
            &script_sig,
            witness,
        ).expect("Descriptor/Witness stack creation to succeed");
        assert_eq!(Descriptor::Pkh(pks[0]), des);
        assert_eq!(stack,
                   vec![StackElement::Witness(sigs[0].clone())]);

        //test wpkh
        let script_pubkey =  bitcoin::Address::p2wpkh(
            &pks[1],
            bitcoin::Network::Bitcoin,
        ).script_pubkey();
        let script_sig = script::Builder::new().into_script();
        let witness = vec![sigs[1].clone(), pks[1].clone().to_bytes()];
        let (des, stack) = witness_stack(
            &script_pubkey,
            &script_sig,
            witness,
        ).expect("Descriptor/Witness stack creation to succeed");
        assert_eq!(Descriptor::Wpkh(pks[1]), des);
        assert_eq!(stack, vec![StackElement::Witness(sigs[1].clone())]);

        //test Wsh: and(pkv, pk). Note this does not check miniscript.
        let ms = Miniscript(AstElem::AndCat(
            Box::new(AstElem::PkV(pks[0].clone())),
            Box::new(AstElem::Pk(pks[1].clone()))));
        let script_pubkey =  bitcoin::Address::p2wsh(
            &ms.encode(),
            bitcoin::Network::Bitcoin,
        ).script_pubkey();
        let script_sig = script::Builder::new().into_script();
        let witness = vec![sigs[1].clone(), sigs[0].clone(), ms.encode().to_bytes()];
        let (des, stack) = witness_stack(
            &script_pubkey,
            &script_sig,
            witness,
        ).expect("Descriptor/Witness stack creation to succeed");
        assert_eq!(Descriptor::Wsh(ms.clone()), des);
        assert_eq!(stack,
                   vec![StackElement::Witness(sigs[1].clone()),
                        StackElement::Witness(sigs[0].clone())]);

        //test Bare: and(pkv, pk). Note this does not check miniscript.
        let ms = Miniscript(AstElem::OrBool(
            Box::new(AstElem::Pk(pks[0].clone())),
            Box::new(AstElem::PkW(pks[1].clone()))));
        let script_pubkey =  ms.encode();
        let script_sig = script::Builder::new()
            .push_int(0)
            .push_slice(&sigs[0])
            .into_script();
        let witness = vec![] as Vec<Vec<u8>>;
        let (des, stack) = witness_stack(
            &script_pubkey,
            &script_sig,
            witness,
        ).expect("Descriptor/Witness stack creation to succeed");
        assert_eq!(Descriptor::Bare(ms.clone()), des);
        assert_eq!(stack,
                   vec![StackElement::Dissatisfied,
                        StackElement::Witness(sigs[0].clone())]);

        //test Sh: and(pkv, pk). Note this does not check miniscript.
        let ms = Miniscript(AstElem::OrKey(
            Box::new(AstElem::PkQ(pks[0].clone())),
            Box::new(AstElem::PkQ(pks[1].clone()))));
        let script_pubkey =  bitcoin::Address::p2sh(
            &ms.encode(),
            bitcoin::Network::Bitcoin,
        ).script_pubkey();
        let script_sig = script::Builder::new()
            .push_slice(&sigs[0])
            .push_int(1)
            .push_slice(&ms.encode().to_bytes())
            .into_script();
        let witness = vec![] as Vec<Vec<u8>>;
        let (des, stack) = witness_stack(
            &script_pubkey,
            &script_sig,
            witness,
        ).expect("Descriptor/Witness stack creation to succeed");
        assert_eq!(Descriptor::Sh(ms.clone()), des);
        assert_eq!(stack,
                   vec![StackElement::Witness(sigs[0].clone()),
                        StackElement::Satisfied]);

        //test Shwsh: and(pkv, pk). Note this does not check miniscript.
        //Check with incorrect witness
        let ms = Miniscript(AstElem::AndCat(
            Box::new(AstElem::PkV(pks[0].clone())),
            Box::new(AstElem::Pk(pks[1].clone()))));
        let script_pubkey =  bitcoin::Address::p2shwsh(
            &ms.encode(),
            bitcoin::Network::Bitcoin,
        ).script_pubkey();
        let script_sig = script::Builder::new()
            .push_slice(&ms.encode().to_v0_p2wsh().to_bytes())
            .into_script();
        let witness = vec![sigs[1].clone(), sigs[3].clone(), ms.encode().to_bytes()];
        let (des, stack) = witness_stack(
            &script_pubkey,
            &script_sig,
            witness,
        ).expect("Descriptor/Witness stack creation to succeed");
        assert_eq!(Descriptor::ShWsh(ms.clone()), des);
        assert_eq!(stack,
                   vec![StackElement::Witness(sigs[1].clone()),
                        StackElement::Witness(sigs[3].clone())]);

        //test wpkh
        let script_pubkey =  bitcoin::Address::p2shwpkh(
            &pks[2],
            bitcoin::Network::Bitcoin,
        ).script_pubkey();
        let redeem_script =  bitcoin::Address::p2wpkh(
            &pks[2],
            bitcoin::Network::Bitcoin,
        ).script_pubkey();
        let script_sig = script::Builder::new()
            .push_slice(&redeem_script.to_bytes())
            .into_script();
        let witness = vec![sigs[2].clone(), pks[2].clone().to_bytes()];
        let (des, stack) = witness_stack(
            &script_pubkey,
            &script_sig,
            witness,
        ).expect("Descriptor/Witness stack creation to succeed");
        assert_eq!(Descriptor::ShWpkh(pks[2]), des);
        assert_eq!(stack, vec![StackElement::Witness(sigs[2].clone())]);
    }
}