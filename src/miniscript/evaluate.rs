//! # Interpreatation of Miniscript scripts
//!
//! Traits and implementations to support for interpretation of miniscripts.
//!
//!
use bitcoin_hashes::sha256;
use secp256k1;

use Error;
use miniscript::astelem::AstElem;
use ToPublicKey;
use secp256k1::{Secp256k1, Signature, VerifyOnly};
use bitcoin_hashes::Hash;
use bitcoin;

///Primitives for Miniscript: a vector of public keys(sigs), hashlocks and timelocks
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Primitives{
    pub pks: Vec<bitcoin::PublicKey>,
    pub hashlocks : Vec<Vec<u8>>,
    pub timelocks : Vec<u32>
}

impl Primitives
{
    fn join(&mut self, other: &Primitives){
        self.pks.extend(other.pks.clone());
        self.hashlocks.extend(other.hashlocks.clone());
        self.timelocks.extend(other.timelocks.clone());
    }
}


/// Definition of Stack Element of the Witness stack used for interpretation of Miniscript.
/// All stack elements with vec![] go to Dissatisfied and vec![1] are marked to Satisfied.
/// Others are directly pushed as witness
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum StackElement {
    /// Result of a satisfied E/T/W/F
    Satisfied,
    /// Result of a dissatisfied E/W
    Dissatisfied,
    /// Input from the witness stack
    Witness(Vec<u8>),
}

impl From<Vec<u8>> for StackElement {
    fn from(v: Vec<u8>) -> StackElement {
        match v{
            _ if v == vec![1] => StackElement::Satisfied,
            _ if v == vec![] => StackElement::Dissatisfied,
            _ => StackElement::Witness(v)
        }
    }
}

impl StackElement{

    pub fn is_witness_or_err(self) -> Result<Vec<u8>, Error>
    {
        match self{
            StackElement::Witness(v) => Ok(v),
            _ => Err(Error::CouldnotEvaluate)
        }
    }
}

/// Trait describing an AST element which can be evaluated /interpreted , given an input witness and
/// maps from the public data to corresponding witness data.
pub trait Interpretable<P> {
    /// Attempt to interpret a miniscript for a given witness and
    fn interpret(
        &self,
        secp: &Secp256k1<VerifyOnly>,
        stack: &mut Vec<StackElement>,
        sighash: &secp256k1::Message,
        age: u32,
    ) -> Result<Primitives, Error>
    where P : ToPublicKey + Clone;
}

impl <P: ToPublicKey + Clone> Interpretable<P> for AstElem<P> {
    fn interpret(
        &self,
        secp: &Secp256k1<VerifyOnly>,
        stack: &mut Vec<StackElement>,
        sighash: &secp256k1::Message,
        age: u32,
    ) -> Result<Primitives, Error>
    {
        match *self {
            AstElem::True => {
                stack.push(StackElement::Satisfied);
                Ok(Primitives{pks: vec![], hashlocks: vec![], timelocks: vec![]})
            }
            AstElem::Pk(ref p) => evaluate_pk(secp, stack, sighash, p),
            AstElem::PkV(ref p) => {
                let res = evaluate_pk(secp, stack, sighash, p)?;
                evaluate_verify(stack)?;
                Ok(res)
            }
            AstElem::PkQ(ref p) => {
                stack.push(StackElement::Witness(p.to_public_key().to_bytes()));
                Ok(Primitives{pks: vec![], hashlocks: vec![], timelocks: vec![]})
            }
            AstElem::PkW(ref p) => {
                let witnesslen = stack.len();
                stack.swap(witnesslen-1, witnesslen -2);//swap the last elements
                evaluate_pk(secp, stack, sighash, p)
            }
            AstElem::Multi(k, ref keys) => evaluate_multi(secp, stack, sighash, k, keys),
            AstElem::MultiV(k, ref keys) => {
                let res = evaluate_multi(secp, stack, sighash, k, keys)?;
                evaluate_verify(stack)?;
                Ok(res)
            }
            AstElem::Time(t) => {
                let res = evaluate_csv(age, t)?;
                //Ideally should be: build_scriptint(t as i64)). But since this is a T value
                //and it will never be popped, it is safe to push Satisfied.
                stack.push(StackElement::Satisfied);
                Ok(res)
            }
            AstElem::TimeV(t) =>  evaluate_csv(age, t),
            AstElem::TimeF(t) => {
                let res = evaluate_csv(age, t)?;
                stack.push(StackElement::Satisfied);
                Ok(res)
            }
            AstElem::TimeE(t) => evaluate_time_e(stack, age, t),
            AstElem::TimeW(t) => {
                let witnesslen = stack.len();
                stack.swap(witnesslen-1, witnesslen -2);//swap the last elements
                evaluate_time_e(stack, age, t)
            }
            AstElem::Hash(h) => evaluate_hash_t(stack, h),
            AstElem::HashV(h) => {
                let res = evaluate_hash_t(stack, h)?;
                evaluate_verify(stack)?;
                Ok(res)
            }
            AstElem::HashW(h) => evaluate_hash_w(stack, h),
            AstElem::Wrap(ref sub) => {
                let top = stack.pop().expect("Witness stack has at least one element");
                let res = sub.interpret(secp, stack, sighash, age)?;
                stack.push(top);
                Ok(res)
            }
            AstElem::Likely(ref sub) => {
                let top = stack.pop().expect("Witness stack has at least one element");
                match top{
                    StackElement::Satisfied => Ok(Primitives{pks: vec![], hashlocks: vec![], timelocks: vec![]}),
                    StackElement::Dissatisfied => sub.interpret(secp, stack, sighash, age),
                    _ =>  Err(Error::CouldnotEvaluate)
                }
            },
            AstElem::Unlikely(ref sub) => {
                let top = stack.pop().expect("Witness stack has at least one element");
                match top{
                    StackElement::Dissatisfied => Ok(Primitives{pks: vec![], hashlocks: vec![], timelocks: vec![]}),
                    StackElement::Satisfied => sub.interpret(secp, stack, sighash, age),
                    _ =>  Err(Error::CouldnotEvaluate)
                }
            },
            AstElem::AndCat(ref left, ref right) => {
                let mut res = left.interpret(secp, stack, sighash, age)?;
                res.join(&right.interpret(secp, stack, sighash, age)?);
                Ok(res)
            }
            AstElem::AndBool(ref left, ref right) => interpret_and_bool(secp, stack, sighash, age, left, right),
            AstElem::AndCasc(ref left, ref right) => interpret_and_casc(secp, stack, sighash, age, left, right),
            AstElem::OrBool(ref left, ref right) => interpret_or_bool(secp, stack, sighash, age, left, right),
            AstElem::OrCasc(ref left, ref right) |
            AstElem::OrCont(ref left, ref right) => interpret_or_casc(secp, stack, sighash, age, left, right),
            AstElem::OrKey(ref left, ref right) => interpret_or_key(secp, stack, sighash, age, left, right),
            AstElem::OrKeyV(ref left, ref right) => {
                let res = interpret_or_key(secp, stack, sighash, age, left, right)?;
                evaluate_verify(stack)?;
                Ok(res)
            }
            AstElem::OrIf(ref left, ref right) =>  interpret_or_if(secp, stack, sighash, age, left, right),
            AstElem::OrIfV(ref left, ref right) => {
                let res = interpret_or_if(secp, stack, sighash, age, left, right)?;
                evaluate_verify(stack)?;
                Ok(res)

            }
            AstElem::OrNotif(ref left, ref right) => interpret_or_if(secp, stack, sighash, age, right, left),
            AstElem::Thresh(k, ref subs) => evaluate_thres(secp, stack, sighash,age, k, subs),
            AstElem::ThreshV(k, ref subs) => {
                let res = evaluate_thres(secp, stack, sighash,age, k, subs)?;
                evaluate_verify(stack)?;
                Ok(res)
            }
        }
    }

}

/// This functions is equivalent to VERIFY. This pops the top element and checks if it is non-zero.
/// Gives an error in all other cases
fn evaluate_verify(stack: &mut Vec<StackElement>) -> Result<(), Error>{
    let top = stack.pop().expect("Non-zero element for verify");
    match top {
        StackElement::Dissatisfied => Err(Error::CouldnotEvaluate),
        _ => Ok(())
    }
}

/// Helper function to verify serialized signature
pub fn verify_sersig(
    secp: &secp256k1::Secp256k1<VerifyOnly>,
    sighash: &secp256k1::Message,
    pk: &bitcoin::PublicKey,
    sigser: &Vec<u8>,
) -> Result<(), Error>
{
    let mut sig = sigser.clone();
    sig.pop().expect("SighashType: One byte");
    let sig = Signature::from_der(&sig).expect("Signature parse");
    let res = secp.verify(&sighash, &sig, &pk.key);

    match res{
        Ok(()) => Ok(()),
        Err(..) => Err(Error::VerifySigFail(pk.clone(), sig, sighash.clone()))
    }
}


/// Helper function to evaluate a Pk Node which takes the top of the stack as input
/// signature and validates it.
/// Sat: If the signature witness is correct, 1 is pushed
/// Unsat: For empty witness a 0 is pushed
/// Err: All of other witness result in errors.
fn evaluate_pk<P>(
    secp: &secp256k1::Secp256k1<VerifyOnly>,
    stack: &mut Vec<StackElement>,
    sighash: &secp256k1::Message,
    pk: &P,
) -> Result<Primitives, Error>
    where P: ToPublicKey + Clone,
{
    let sigser = stack.pop().expect("Witness stack has at least one element");

    match sigser{
        StackElement::Dissatisfied => {
                stack.push(StackElement::Dissatisfied);
                Ok(Primitives {pks: vec![], hashlocks: vec![],timelocks: vec![]})
        },
        StackElement::Witness(sigser) => {
            verify_sersig(secp, sighash, &pk.clone().to_public_key(), &sigser)?;
            stack.push(StackElement::Satisfied);
            Ok(Primitives{ pks: vec![pk.clone().to_public_key()], hashlocks: vec![], timelocks: vec![]})
        }
        StackElement::Satisfied => Err(Error::CouldnotEvaluate)
    }
}

/// Helper function to evaluate a checkmultisig which takes the top of the stack as input
/// signature and validates it.
/// Sat: 0 sig1 sig2 ... sig_k, 1 is pushed onto the stack
/// Unsat: 0 (0)*k, 0 is pushed on the stack
/// Err: All of other witness result in errors.
fn evaluate_multi<P>(
    secp: &secp256k1::Secp256k1<VerifyOnly>,
    stack: &mut Vec<StackElement>,
    sighash: &secp256k1::Message,
    k: usize,
    keys: &Vec<P>,
) -> Result<Primitives, Error>
    where P: ToPublicKey + Clone,
{
    let len = stack.len();
    let sigs = stack.split_off(len - k);
    let extrazero = stack.pop().expect("Missing additional 0 element in checkmultisig");
    let mut ret = Primitives{pks: vec![], hashlocks: vec![], timelocks: vec![]};

    //Remove the extra zero from multi-sig check
    if extrazero != StackElement::Dissatisfied {
        return Err(Error::CouldnotEvaluate)
    }

    //Non-satisfaction case
    let nonsat : Vec<bool> = sigs.iter().
        map(|sig| *sig == StackElement::Dissatisfied).
        filter(|empty| *empty).
        collect();
    if nonsat.len() == k{
        stack.push(StackElement::Dissatisfied);
        return Ok(ret)
    }

    for witness_sig in sigs {
        for pk in keys {
            if let StackElement::Witness(ref sig) = witness_sig {
                if let Ok(()) = verify_sersig(secp, sighash, &pk.to_public_key(), sig) {
                    ret.pks.push(pk.clone().to_public_key());
                    break;
                }
            }
        }
    }
    if ret.pks.len() == k {
        stack.push(StackElement::Satisfied);
        Ok(ret)
    } else {
        Err(Error::CouldnotEvaluate)
    }
}

/// Equivalent of `n CHECKSEQUENCEVERIFY`. There is no Unsat condition for CSV, hence result is not
/// sent using EvalResult
fn evaluate_csv(age: u32, n: u32) -> Result<Primitives, Error>
{
    if age >= n {
        Ok(Primitives{pks: vec![], hashlocks: vec![], timelocks: vec![n]})
    } else {
        Err(Error::LocktimeNotMet(n))
    }
}

/// Script: DUP IF n CHECKSEQUENCEVERIFY DROP ENDIF. This does not actually check the timelock on
/// input 0. Upon input 1, this function does CSV and DROP.
fn evaluate_time_e( stack: &mut Vec<StackElement>, age: u32, n: u32,) -> Result<Primitives, Error>
{
    let top = stack.pop().expect("Witness Stack must contain one element");
    match top {
        StackElement::Dissatisfied => {
            stack.push(StackElement::Dissatisfied);
            Ok(Primitives{pks: vec![], hashlocks: vec![], timelocks: vec![]})
        }
        StackElement::Satisfied => {
            let res = evaluate_csv(age, n)?;
            stack.push(StackElement::Satisfied);
            Ok(res)
        }
        _ => Err(Error::CouldnotEvaluate)
    }
}

/// helper function for calculating equivalent of HASH256 hash OP_EQUAL
/// len(preimage) = 32 and SHA256(preimage) = hash
fn evaluate_hash(stack: &mut Vec<StackElement>, hash: sha256::Hash, preimage: &Vec<u8>)
                   -> Result<Primitives, Error >
{
    if preimage.len() != 32{
        return Err(Error::VerifyHashFail(hash, preimage.clone()))
    }
    if sha256::Hash::hash(preimage) == hash{
        stack.push(StackElement::Satisfied);
        Ok(Primitives{pks: vec![], hashlocks: vec![preimage.clone()], timelocks: vec![]})
    }
    else{
        Err(Error::VerifyHashFail(hash, preimage.clone()))
    }
}

fn evaluate_hash_t(stack:&mut Vec<StackElement>, hash: sha256::Hash)
    -> Result<Primitives, Error >
{
    let pre_image = stack.pop().expect("Preimage missing");
    if let StackElement::Witness(pre) = pre_image {
        evaluate_hash(stack, hash, &pre)
    } else{
        Err(Error::CouldnotEvaluate)
    }
}

fn evaluate_hash_w(stack: &mut Vec<StackElement>, hash: sha256::Hash)
    -> Result<Primitives, Error >
{
    let stacklen = stack.len();
    stack.swap(stacklen - 1, stacklen - 2);//swap the last elements
    let preimage = stack.pop().expect("Preimage");
    match preimage {
        StackElement::Dissatisfied => {
            stack.push(StackElement::Dissatisfied);
            Ok(Primitives { pks: vec![], hashlocks: vec![], timelocks: vec![] })
        }
        StackElement::Witness(pre) => evaluate_hash(stack, hash, &pre),
        _ => Err(Error::CouldnotEvaluate)
    }
}

/// A and B. Evaluates both A and B and then computes BOOLAND
fn interpret_and_bool<P>(
    secp: &secp256k1::Secp256k1<VerifyOnly>,
    stack: &mut Vec<StackElement>,
    sighash: &secp256k1::Message,
    age: u32,
    left: &AstElem<P>,
    right: &AstElem<P>,
) -> Result<Primitives, Error >
    where P: ToPublicKey + Clone,
{
    let mut res = left.interpret(secp, stack, sighash, age)?;
    res.join(&right.interpret(secp, stack, sighash, age)?);

    let left_res = stack.pop().expect("Witness stack has at least one element");
    let right_res = stack.pop().expect("Witness stack has at least one element");
    match (left_res, right_res) {
        (StackElement::Satisfied, StackElement::Satisfied) => {
            stack.push(StackElement::Satisfied);
            Ok(res)
        }
        (StackElement::Satisfied, StackElement::Dissatisfied) |
        (StackElement::Dissatisfied, StackElement::Satisfied) |
        (StackElement::Dissatisfied, StackElement::Dissatisfied) => {
            //If the script evaluates to false, all primitives inside it are ignored.
            stack.push(StackElement::Dissatisfied);
            Ok(Primitives { pks: vec![], hashlocks: vec![], timelocks: vec![] })
        }
        _ => unreachable!() //Both expressions must be satisfied or dissatisfied
    }
}

/// If !A then 0 else B. Evaluates B only if A is true
fn interpret_and_casc<P>(
    secp: &secp256k1::Secp256k1<VerifyOnly>,
    stack: &mut Vec<StackElement>,
    sighash: &secp256k1::Message,
    age: u32,
    left: &AstElem<P>,
    right: &AstElem<P>,
) -> Result<Primitives, Error >
    where P: ToPublicKey + Clone,
{
    let mut res = left.interpret(secp, stack, sighash, age)?;
    let left_res = stack.pop().expect("Witness stack has at least one element");
    match left_res {
        StackElement::Dissatisfied => {
            stack.push(StackElement::Dissatisfied);
            Ok(Primitives { pks: vec![], hashlocks: vec![], timelocks: vec![] })
        }
        StackElement::Satisfied => {
            //right is F, will push 1 on stack
            res.join(&right.interpret(secp, stack, sighash, age)?);
            Ok(res)
        }
        _ => unreachable!() //Left res must be satisfied or dissatisfied
    }
}

///A or B. Evaluates both A and B and then computes BOOLAND
fn interpret_or_bool<P>(
    secp: &secp256k1::Secp256k1<VerifyOnly>,
    stack: &mut Vec<StackElement>,
    sighash: &secp256k1::Message,
    age: u32,
    left: &AstElem<P>,
    right: &AstElem<P>,
) -> Result<Primitives, Error >
    where P: ToPublicKey + Clone,
{
    let mut res = left.interpret(secp, stack, sighash, age)?;
    res.join(&right.interpret(secp, stack, sighash, age)?);

    let left_res = stack.pop().expect("Witness stack has at least one element");
    let right_res = stack.pop().expect("Witness stack has at least one element");
    match (left_res, right_res) {
        (StackElement::Dissatisfied, StackElement::Dissatisfied) => {
            stack.push(StackElement::Dissatisfied);
            Ok(Primitives { pks: vec![], hashlocks: vec![], timelocks: vec![] })
        }
        (StackElement::Satisfied, StackElement::Dissatisfied) |
        (StackElement::Dissatisfied, StackElement::Satisfied) |
        (StackElement::Satisfied, StackElement::Satisfied) => {
            //If the script evaluates to false, all primitives inside it are ignored.
            stack.push(StackElement::Satisfied);
            Ok(res)
        }
        _ => unreachable!() //Both expressions must be satisfied or dissatisfied
    }
}

///if A then 1 else B
fn interpret_or_casc<P>(
    secp: &secp256k1::Secp256k1<VerifyOnly>,
    stack: &mut Vec<StackElement>,
    sighash: &secp256k1::Message,
    age: u32,
    left: &AstElem<P>,
    right: &AstElem<P>,
) -> Result<Primitives, Error >
    where P: ToPublicKey + Clone,
{
    let res = left.interpret(secp, stack, sighash, age)?;
    let left_res = stack.pop().expect("Witness stack has at least one element");
    match left_res {
        StackElement::Satisfied => {
            stack.push(StackElement::Satisfied);
            Ok(res)
        }
        StackElement::Dissatisfied => {
            //right is either E or T, so it will push Sat/Dissat. We ignore all Primitives from left
            //since that is Dissatisfied
            let res = right.interpret(secp, stack, sighash, age)?;
            let len = stack.len();
            let right_res = match stack.len() {
                0 => &StackElement::Satisfied, // In the case of OR_Cont, when right is F
                _ => stack.get(len - 1).expect("Right result")
            };
            match *right_res{
                StackElement::Dissatisfied =>
                    Ok(Primitives { pks: vec![], hashlocks: vec![], timelocks: vec![] }),
                StackElement::Satisfied => Ok(res),
                StackElement::Witness(..) => unreachable!() //Result of E or T cannot be witness bytes
            }
        }
        _ => unreachable!() //Left res must be satisfied or dissatisfied
    }
}

/// If c then left else right
fn interpret_or_if<P>(
    secp: &secp256k1::Secp256k1<VerifyOnly>,
    stack: &mut Vec<StackElement>,
    sighash: &secp256k1::Message,
    age: u32,
    left: &AstElem<P>,
    right: &AstElem<P>,
) -> Result<Primitives, Error >
    where P: ToPublicKey + Clone,
{
    let c = stack.pop().expect("Witness stack has at least one element");
    match c {
        StackElement::Satisfied => left.interpret(secp, stack, sighash, age),
        StackElement::Dissatisfied => right.interpret(secp, stack, sighash, age),
        _ => Err(Error::CouldnotEvaluate)
    }
}

///if c then A else B CHECKSIG
/// or_if followed by CHECKSIG
fn interpret_or_key<P>(
    secp: &secp256k1::Secp256k1<VerifyOnly>,
    stack: &mut Vec<StackElement>,
    sighash: &secp256k1::Message,
    age: u32,
    left: &AstElem<P>,
    right: &AstElem<P>,
) -> Result<Primitives, Error >
    where P: ToPublicKey + Clone,
{
    let mut res = interpret_or_if(secp, stack, sighash, age, left, right)?;
    let pk = stack
        .pop()
        .expect("Pubkey expected")
        .is_witness_or_err()?;
    let sig = stack
        .pop()
        .expect("Witness stack has at least one element");
    let pk = bitcoin::PublicKey::from_slice(&pk).expect("Public parse error");
    match sig{
        StackElement::Dissatisfied => {
            stack.push(StackElement::Dissatisfied);
            Ok(Primitives { pks: vec![], hashlocks: vec![], timelocks: vec![] })
        }
        StackElement::Witness(sig) => {
            verify_sersig(secp, sighash, &pk, &sig)?;
            stack.push(StackElement::Satisfied);
            res.join(&Primitives{ pks: vec![pk.clone()], hashlocks: vec![], timelocks: vec![]});
            Ok(res)
        }
        _ => Err(Error::CouldnotEvaluate)
    }
}

///A + B + ... = k. Evalutes all the subexpressions and checks if EXACTLY k of them are satisfied.
fn evaluate_thres<P>(
    secp: &secp256k1::Secp256k1<VerifyOnly>,
    stack: &mut Vec<StackElement>,
    sighash: &secp256k1::Message,
    age: u32,
    k: usize,
    subs: &[AstElem<P>],
) -> Result<Primitives, Error >
    where P: ToPublicKey + Clone,
{
    let mut res = Primitives{pks: vec![], hashlocks:vec![], timelocks:vec![]};

    if k == 0 {
        stack.push(StackElement::Satisfied);
        return Ok(res);
    }

    let mut satisfied = 0;

    for sub in subs.iter() {
        res.join(&sub.interpret(secp, stack, sighash, age)?);
        let top = stack.pop().expect("Expression result");
        match top{
            StackElement::Satisfied => satisfied += 1,
            StackElement::Dissatisfied => {}
            _ => unreachable!() //All Subexpressions must evaluate either true or false
        }
    }

    if satisfied == k {
        stack.push(StackElement::Satisfied);
        return Ok(res)
    }else {
        stack.push(StackElement::Dissatisfied);
        Err(Error::CouldnotEvaluate)
    }
}