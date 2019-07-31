
use bitcoin_hashes::{Hash, hash160, sha256, sha256d, ripemd160};
use Terminal;
use secp256k1::{self, Signature, VerifyOnly};
use ::{Descriptor};
use ::{bitcoin};
use ::{error, Miniscript};
use ::{MiniscriptKey, ToPublicKey};
use fmt;
use ToHash160;
/// Detailed Error type for Interpreter
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Unexpected Stack End, caused by popping extra elements from stack
    UnexpectedStackEnd,
    /// Unexpected Stack Push `StackElement::Push` element when the interpreter
    /// was expecting a stack boolean `StackElement::Satisfied` or
    /// `StackElement::Dissatisfied`
    UnexpectedStackElementPush,
    /// Verify expects stack top element exactly to be `StackElement::Satisfied`.
    /// This error is raised even if the stack top is `StackElement::Push`.
    VerifyFailed,
    /// MultiSig missing at least `1` witness elements out of `k + 1` required
    InsufficientSignaturesMultiSig,
    /// MultiSig requires 1 extra zero element apart from the `k` signatures
    MissingExtraZeroMultiSig,
    /// Script abortion because of incorrect dissatisfaction for multisig.
    /// Any input witness apart from sat(0 sig ...) or nsat(0 0 ..) leads to
    /// this error. This is network standardness assumption and miniscript only
    /// supports standard scripts
    MultiSigEvaluationError,
    /// General Interpreter error.
    CouldNotEvaluate,
    /// Script abortion because of incorrect dissatisfaction for Checksig.
    /// Any input witness apart from sat(sig) or nsat(0) leads to
    /// this error. This is network standardness assumption and miniscript only
    /// supports standard scripts
    PkEvaluationError(bitcoin::PublicKey),
    /// Miniscript requires the entire top level script to be satisfied.
    ScriptSatisfactionError,
    /// The Public Key hash check for the given pubkey. This occurs in `PkH`
    /// node when the given key does not match to Hash in script.
    PkHashVerifyFail(hash160::Hash),
    /// Parse Error while parsing a `StackElement::Push` as a Pubkey. Both
    /// 33 byte and 65 bytes are supported.
    PubkeyParseError,
    /// The preimage to the hash function must be exactly 32 bytes.
    HashPreimageLengthMismatch,
    /// Got `StackElement::Satisfied` or `StackElement::Dissatisfied` when the
    /// interpreter was expecting `StackElement::Push`
    UnexpectedStackBoolean,
    /// Could not satisfy, relative locktime not met
    RelativeLocktimeNotMet(u32),
    /// Could not satisfy, absolute locktime not met
    AbsoluteLocktimeNotMet(u32),
    /// Forward-secp related errors
    Secp(secp256k1::Error),
}

impl error::Error for Error {
    fn description(&self) -> &str {
        ""
    }
    fn cause(&self) -> Option<&error::Error> {
        match *self{
            Error::Secp(ref err) => Some(err),
            ref x => Some(x),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::UnexpectedStackEnd => f.write_str("Unexpected Stack End"),
            Error::UnexpectedStackElementPush =>
                write!(f, "Got {}, expected Stack Boolean", 1),
            Error::VerifyFailed =>
                f.write_str("Expected Satisfied Boolean at stack top for VERIFY"),
            Error::InsufficientSignaturesMultiSig =>
                f.write_str("Insufficient signatures for CMS"),
            Error::MissingExtraZeroMultiSig =>
                f.write_str("CMS missing extra zero"),
            Error::MultiSigEvaluationError =>
                f.write_str("CMS script aborted, incorrect satisfaction/dissatisfaction"),
            Error::CouldNotEvaluate =>
                f.write_str("Interpreter Error: Could not evaluate"),
            Error::PkEvaluationError(ref key) =>
                write!(f, "Incorrect Signature for pk {}", key),
            Error::ScriptSatisfactionError =>
                f.write_str("Top level script must be satisfied"),
            Error::PkHashVerifyFail(ref hash) =>
                write!(f, "Pubkey Hash check failed {}", hash),
            Error::PubkeyParseError =>
                f.write_str( "Error in parsing pubkey {}"),
            Error::HashPreimageLengthMismatch =>
                f.write_str("Hash preimage should be 32 bytes"),
            Error::UnexpectedStackBoolean =>
                f.write_str("Expected Stack Push operation, found stack bool"),
            Error::RelativeLocktimeNotMet(n) =>
                write!(f, "required relative locktime CSV of {} blocks, not met", n),
            Error::AbsoluteLocktimeNotMet(n) =>
                write!(f, "required absolute locktime CLTV of {} blocks, not met", n),
            Error::Secp(ref e) => fmt::Display::fmt(e, f),
        }
    }
}

/// Definition of Stack Element of the Stack used for interpretation of Miniscript.
/// All stack elements with vec![] go to Dissatisfied and vec![1] are marked to Satisfied.
/// Others are directly pushed as witness
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum StackElement<'stack> {
    /// Result of a satisfied Miniscript fragment
    /// Translated from `vec![1]` from input stack
    Satisfied,
    /// Result of a dissatisfied Miniscript fragment
    /// Translated from `vec![]` from input stack
    Dissatisfied,
    /// Input from the witness stack
    Push(&'stack [u8]),
}

impl<'stack> StackElement<'stack>{

    /// Convert witness stack to StackElement
    pub fn from(v: &'stack [u8]) -> StackElement<'stack> {
        if *v == [1]{
            StackElement::Satisfied
        } else if *v == [] {
            StackElement::Dissatisfied
        } else {
            StackElement::Push(v)
        }
    }
}

/// Type of HashLock used for SatisfiedConstraint structure
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum HashLockType<'desc>{
    ///SHA 256 hashlock
    Sha256(&'desc sha256::Hash),
    ///Hash 256 hashlock
    Hash256(&'desc sha256d::Hash),
    ///Hash160 hashlock
    Hash160(&'desc hash160::Hash),
    ///Ripemd160 hashlock
    Ripemd160(&'desc ripemd160::Hash),
}

/// A satisfied Miniscript condition (Signature, Hashlock, Timelock)
/// 'desc represents the lifetime of descriptor and `stack represents
/// the lifetime of witness
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SatisfiedConstraint<'desc, 'stack, Pk: 'desc + MiniscriptKey> {
    ///Public key and corresponding signature
    PublicKey {
        key: &'desc Pk,
        sig: secp256k1::Signature,
    },
    ///PublicKeyHash, corresponding pubkey and signature
    PublicKeyHash {
        keyhash: &'desc Pk::Hash,
        key: bitcoin::PublicKey,
        sig: secp256k1::Signature,
    },
    ///Hashlock and preimage for SHA256
    HashLock {
        hash: HashLockType<'desc>,
        preimage: &'stack [u8],
    },
    ///Relative Timelock for CSV.
    RelativeTimeLock {
        time: &'desc u32,
    },
    ///Absolute Timelock for CLTV.
    AbsoluteTimeLock {
        time: &'desc u32,
    },
}

///This is used by the interpreter to know which evaluation state a AstemElem is.
///This is required because whenever a same node(for eg. OrB) appears on the stack, we don't
///know if the left child has been evaluated or not. And based on the result on
///the top of the stack, we need to decide whether to execute right child or not.
///This is also useful for wrappers and thresholds which push a value on the stack
///depending on evaluation of the children.
struct NodeEvaluationState<'desc, Pk: 'desc + MiniscriptKey> {
    ///The node which is being evaluated
    node: &'desc Miniscript<Pk>,
    ///number of children evaluated
    n_evaluated: usize,
    ///number of children satisfied
    n_satisfied: usize,
}

/// An iterator over all the satisfied constraints satisfied by a given
/// descriptor/scriptSig/witness stack tuple. This returns all the redundant
/// satisfied constraints even if they were not required for the entire
/// satisfaction. For example, and_b(Pk,false) would return the witness for
/// Pk if it was satisfied even if the entire and_b could have failed.
/// In case the script would abort on the given witness stack OR if the entire
/// script is dissatisfied, this would return keep on returning values
/// until Error. Recommended to use collect() on this iterator and check for
/// Error
pub struct SatisfiedConstraints<'secp, 'desc, 'stack, Pk: 'desc + MiniscriptKey> {
    secp: &'secp secp256k1::Secp256k1<VerifyOnly>,
    sighash: secp256k1::Message,
    public_key: Option<&'desc Pk>,
    state : Vec <NodeEvaluationState<'desc, Pk>>,
    stack : Stack<'stack>,
    age: u32,
    height: u32,
}

/// Stack Data structure representing the stack input to Miniscript. This Stack
/// is created from the combination of ScriptSig and Witness stack.
pub struct Stack<'stack>(pub Vec<StackElement<'stack>>);

impl<'secp, 'desc, 'stack, Pk> SatisfiedConstraints<'secp, 'desc, 'stack, Pk>
where Pk: MiniscriptKey
{
    /// Helper function to push a NodeEvaluationState on state stack
    fn push_evaluation_state(
        &mut self,
        node: &'desc Miniscript<Pk>,
        n_evaluated: usize,
        n_satisfied: usize
    ) -> ()
    {
        self.state.push(NodeEvaluationState{node, n_evaluated, n_satisfied})
    }

    /// This returns all the redundant
    /// satisfied constraints even if they were not required for the entire
    /// satisfaction. For example, and_b(Pk,false) would return the witness for
    /// Pk if it was satisfied even if the entire and_b could have failed.
    pub fn from_descriptor(
        secp: &'secp secp256k1::Secp256k1<VerifyOnly>,
        sighash: secp256k1::Message,
        des: &'desc Descriptor<Pk>,
        stack: Vec<StackElement<'stack>>,
        age: u32,
        height: u32,
    ) -> SatisfiedConstraints<'secp, 'desc, 'stack, Pk>
    {
        match des {
            &Descriptor::Pk(ref pk) |
            &Descriptor::Pkh(ref pk) |
            &Descriptor::ShWpkh(ref pk) |
            &Descriptor::Wpkh(ref pk) => SatisfiedConstraints{
                secp,
                sighash,
                public_key: Some(pk),
                state : vec![],
                stack: Stack(stack),
                age,
                height,
            },
            &Descriptor::Sh(ref miniscript) |
            &Descriptor::Bare(ref miniscript) |
            &Descriptor::ShWsh(ref miniscript) |
            &Descriptor::Wsh(ref miniscript) => SatisfiedConstraints{
                secp,
                sighash,
                public_key: None,
                state : vec![NodeEvaluationState{
                    node: miniscript,
                    n_evaluated:0,
                    n_satisfied:0
                }],
                stack: Stack(stack),
                age,
                height,
            }
        }
    }
}

///Iterator for SatisfiedConstraints
impl<'secp, 'desc, 'stack, Pk> Iterator for SatisfiedConstraints<'secp, 'desc, 'stack, Pk>
where Pk: MiniscriptKey + ToPublicKey, Pk::Hash: ToHash160,
{
    type Item = Result<SatisfiedConstraint<'desc, 'stack, Pk>, Error>;

    fn next(&mut self) -> Option< Result<SatisfiedConstraint<'desc, 'stack, Pk>, Error>> {
        while let Some(node_state) = self.state.pop() {//non-empty stack
            match node_state.node.node {
                Terminal::True => {
                    debug_assert_eq!(node_state.n_evaluated, 0);
                    debug_assert_eq!(node_state.n_satisfied, 0);
                    self.stack.push(StackElement::Satisfied);
                }
                Terminal::False => {
                    debug_assert_eq!(node_state.n_evaluated, 0);
                    debug_assert_eq!(node_state.n_satisfied, 0);
                    self.stack.push(StackElement::Dissatisfied);
                }
                Terminal::Pk(ref pk) => {
                    debug_assert_eq!(node_state.n_evaluated, 0);
                    debug_assert_eq!(node_state.n_satisfied, 0);
                    let res = self.stack.evaluate_pk(self.secp, self.sighash, pk);
                    if res.is_some(){
                        return res;
                    }
                }
                Terminal::PkH(ref pkh) => {
                    debug_assert_eq!(node_state.n_evaluated, 0);
                    debug_assert_eq!(node_state.n_satisfied, 0);
                    let res = self.stack.evaluate_pkh(self.secp, self.sighash, pkh);
                    if res.is_some(){
                        return res;
                    }
                }
                Terminal::After(ref n) => {
                    debug_assert_eq!(node_state.n_evaluated, 0);
                    debug_assert_eq!(node_state.n_satisfied, 0);
                    let res = self.stack.evaluate_after(n, self.age);
                    if res.is_some(){
                        return res;
                    }
                }
                Terminal::Older(ref n) => {
                    debug_assert_eq!(node_state.n_evaluated, 0);
                    debug_assert_eq!(node_state.n_satisfied, 0);
                    let res = self.stack.evaluate_older(n, self.height);
                    if res.is_some(){
                        return res;
                    }
                }
                Terminal::Sha256(ref hash) => {
                    debug_assert_eq!(node_state.n_evaluated, 0);
                    debug_assert_eq!(node_state.n_satisfied, 0);
                    let res = self.stack.evaluate_sha256(hash);
                    if res.is_some(){
                        return res;
                    }
                }
                Terminal::Hash256(ref hash) => {
                    debug_assert_eq!(node_state.n_evaluated, 0);
                    debug_assert_eq!(node_state.n_satisfied, 0);
                    let res = self.stack.evaluate_hash256(hash);
                    if res.is_some() {
                        return res;
                    }
                }
                Terminal::Hash160(ref hash) =>{
                    debug_assert_eq!(node_state.n_evaluated, 0);
                    debug_assert_eq!(node_state.n_satisfied, 0);
                    let res = self.stack.evaluate_hash160(hash);
                    if res.is_some(){
                        return res;
                    }
                }
                Terminal::Ripemd160(ref hash) => {
                    debug_assert_eq!(node_state.n_evaluated, 0);
                    debug_assert_eq!(node_state.n_satisfied, 0);
                    let res = self.stack.evaluate_ripemd160(hash);
                    if res.is_some(){
                        return res;
                    }
                }
                Terminal::Alt(ref sub) |
                Terminal::Swap(ref sub) |
                Terminal::Check(ref sub) => {
                    debug_assert_eq!(node_state.n_evaluated, 0);
                    debug_assert_eq!(node_state.n_satisfied, 0);
                    self.push_evaluation_state(sub, 0, 0);
                }
                Terminal::DupIf(ref sub)  if node_state.n_evaluated == 0 => {
                    match self.stack.pop() {
                        Some(StackElement::Dissatisfied) => {
                            self.stack.push(StackElement::Dissatisfied);
                        }
                        Some(StackElement::Satisfied) => {
                            self.push_evaluation_state(node_state.node, 1, 1);
                            self.push_evaluation_state(sub, 0, 0);
                        }
                        Some(StackElement::Push(_v)) =>
                            return Some(Err(Error::UnexpectedStackElementPush)),
                        None => return Some(Err(Error::UnexpectedStackEnd))
                    }
                }
                Terminal::DupIf(ref _sub)  if node_state.n_evaluated == 1 => {
                    self.stack.push(StackElement::Satisfied);
                }
                Terminal::ZeroNotEqual(ref sub) |
                Terminal::Verify(ref sub) if node_state.n_evaluated == 0 => {
                    self.push_evaluation_state(node_state.node, 1, 0);
                    self.push_evaluation_state(sub, 0, 0);
                }
                Terminal::Verify(ref _sub) if node_state.n_evaluated == 1 => {
                    match self.stack.pop() {
                        Some(StackElement::Satisfied) => (),
                        Some(_) => return Some(Err(Error::VerifyFailed)),
                        None => return Some(Err(Error::UnexpectedStackEnd))
                    }
                }
                Terminal::ZeroNotEqual(ref _sub) if node_state.n_evaluated == 1 => {
                    match self.stack.pop() {
                        Some(StackElement::Dissatisfied) => self.stack.push(StackElement::Dissatisfied),
                        Some(_) => self.stack.push(StackElement::Satisfied),
                        None => return Some(Err(Error::UnexpectedStackEnd))
                    }
                }
                Terminal::NonZero(ref sub) => {
                    debug_assert_eq!(node_state.n_evaluated, 0);
                    debug_assert_eq!(node_state.n_satisfied, 0);
                    match self.stack.last() {
                        Some(&StackElement::Dissatisfied) => (),
                        Some(_) =>
                            self.push_evaluation_state(sub, 0, 0),
                        None => return Some(Err(Error::UnexpectedStackEnd))
                    }
                }
                Terminal::AndV(ref left, ref right) => {
                    debug_assert_eq!(node_state.n_evaluated, 0);
                    debug_assert_eq!(node_state.n_satisfied, 0);
                    self.push_evaluation_state(right, 0, 0);
                    self.push_evaluation_state(left, 0, 0);
                }
                Terminal::OrB(ref left, ref _right) |
                Terminal::AndB(ref left, ref _right) if node_state.n_evaluated == 0 => {
                    self.push_evaluation_state(node_state.node, 1, 0);
                    self.push_evaluation_state(left, 0, 0);
                }
                Terminal::OrB(ref _left, ref right) |
                Terminal::AndB(ref _left, ref right) if node_state.n_evaluated == 1 => {
                    match self.stack.pop() {
                        Some(StackElement::Dissatisfied) => {
                            self.push_evaluation_state(node_state.node, 2, 0);
                            self.push_evaluation_state(right, 0, 0);
                        }
                        Some(StackElement::Satisfied) => {
                            self.push_evaluation_state(node_state.node, 2, 1);
                            self.push_evaluation_state(right, 0, 0);
                        }
                        Some(StackElement::Push(_v)) =>
                            return Some(Err(Error::UnexpectedStackElementPush)),
                        None => return Some(Err(Error::UnexpectedStackEnd))
                    }
                }
                Terminal::AndB(ref _left, ref _right) if node_state.n_evaluated == 2 => {
                    match self.stack.pop() {
                        Some(StackElement::Satisfied) if node_state.n_satisfied == 1 =>
                            self.stack.push(StackElement::Satisfied),
                        Some(_) => self.stack.push(StackElement::Dissatisfied),
                        None => return Some(Err(Error::UnexpectedStackEnd))
                    }
                }
                Terminal::AndOr(ref left, ref _right, _) |
                Terminal::OrC(ref left, ref _right) |
                Terminal::OrD(ref left, ref _right) if node_state.n_evaluated == 0 => {
                    self.push_evaluation_state(node_state.node, 1, 0);
                    self.push_evaluation_state(left, 0, 0);
                }
                Terminal::OrB(ref _left, ref _right) if node_state.n_evaluated == 2 => {
                    match self.stack.pop() {
                        Some(StackElement::Dissatisfied) if node_state.n_satisfied == 0 =>
                            self.stack.push(StackElement::Dissatisfied),
                        Some(_) => {
                            self.stack.push(StackElement::Satisfied);
                        }
                        None => return Some(Err(Error::UnexpectedStackEnd))
                    }
                }
                Terminal::OrC(ref _left, ref right) if node_state.n_evaluated == 1 => {
                    match self.stack.pop() {
                            Some(StackElement::Satisfied) => (),
                            Some(StackElement::Dissatisfied) =>
                                self.push_evaluation_state(right, 0, 0),
                            Some(StackElement::Push(_v)) =>
                                return Some(Err(Error::UnexpectedStackElementPush)),
                            None => return Some(Err(Error::UnexpectedStackEnd))
                    }
                }
                Terminal::OrD(ref _left, ref right) if node_state.n_evaluated == 1 => {
                    match self.stack.pop() {
                        Some(StackElement::Satisfied) =>
                            self.stack.push(StackElement::Satisfied),
                        Some(StackElement::Dissatisfied) =>
                            self.push_evaluation_state(right, 0, 0),
                        Some(StackElement::Push(_v)) =>
                            return Some(Err(Error::UnexpectedStackElementPush)),
                        None => return Some(Err(Error::UnexpectedStackEnd))
                    }
                }
                Terminal::AndOr(_, ref left, ref right) |
                Terminal::OrI(ref left, ref right) => {
                    match self.stack.pop() {
                            Some(StackElement::Satisfied) =>
                                self.push_evaluation_state(left, 0, 0),
                            Some(StackElement::Dissatisfied) =>
                                self.push_evaluation_state(right, 0, 0),
                            Some(StackElement::Push(_v)) =>
                                return Some(Err(Error::UnexpectedStackElementPush)),
                            None => return Some(Err(Error::UnexpectedStackEnd))
                    }
                }
                Terminal::Thresh(ref _k, ref subs) if node_state.n_evaluated == 0 => {
                    self.push_evaluation_state(node_state.node,1, 0);
                    self.push_evaluation_state(&subs[0], 0, 0);
                }
                Terminal::Thresh(k, ref subs) if node_state.n_evaluated == subs.len() => {
                    match self.stack.pop() {
                            Some(StackElement::Dissatisfied) if node_state.n_satisfied == k =>
                                self.stack.push(StackElement::Satisfied),
                            Some(StackElement::Satisfied) if node_state.n_satisfied == k - 1 =>
                                self.stack.push(StackElement::Satisfied),
                            Some(StackElement::Satisfied) | Some(StackElement::Dissatisfied) =>
                                self.stack.push(StackElement::Dissatisfied),
                            Some(StackElement::Push(_v)) =>
                                return Some(Err(Error::UnexpectedStackElementPush)),
                            None => return Some(Err(Error::UnexpectedStackEnd))
                    }
                }
                Terminal::Thresh(ref _k, ref subs) if node_state.n_evaluated != 0 => {
                    match self.stack.pop() {
                        Some(StackElement::Dissatisfied) => {
                            self.push_evaluation_state(
                                node_state.node,
                                node_state.n_evaluated + 1,
                                node_state.n_satisfied
                            );
                            self.push_evaluation_state(&subs[node_state.n_evaluated],0 , 0);
                        }
                        Some(StackElement::Satisfied) => {
                            self.push_evaluation_state(
                                node_state.node,
                                node_state.n_evaluated + 1,
                                node_state.n_satisfied + 1
                            );
                            self.push_evaluation_state(&subs[node_state.n_evaluated],0 , 0);
                        }
                        Some(StackElement::Push(_v)) =>
                            return Some(Err(Error::UnexpectedStackElementPush)),
                        None => return Some(Err(Error::UnexpectedStackEnd)),
                    }
                }
                Terminal::ThreshM(ref k, ref subs) if node_state.n_evaluated == 0 => {
                    let len = self.stack.len();
                    if len < k + 1 {
                        return Some(Err(Error::InsufficientSignaturesMultiSig))
                    } else {
                        //Non-sat case. If the first sig is empty, others k elements must
                        //be empty.
                        match self.stack.last() {
                            Some(&StackElement::Dissatisfied) => {
                                //Remove the extra zero from multi-sig check
                                let sigs = self.stack.split_off(len - (k + 1));
                                let nonsat = sigs.iter().
                                    map(|sig| *sig == StackElement::Dissatisfied).
                                    filter(|empty| *empty).count();
                                if nonsat == *k {
                                    self.stack.push(StackElement::Dissatisfied);
                                } else {
                                    return Some(Err(Error::MissingExtraZeroMultiSig))
                                }
                            }
                            None => return Some(Err(Error::UnexpectedStackEnd)),
                            _ => {
                                match self.stack.evaluate_thresh_m(self.secp, self.sighash, &subs[0]) {
                                    Some(Ok(x)) => {
                                        self.push_evaluation_state(
                                            node_state.node,
                                            node_state.n_evaluated + 1,
                                            node_state.n_satisfied + 1
                                        );
                                        return Some(Ok(x))
                                    }
                                    None => self.push_evaluation_state(
                                            node_state.node,
                                            node_state.n_evaluated + 1,
                                            node_state.n_satisfied
                                        ),
                                    x => return x //forward errors as is
                                }
                            }
                        }
                    }
                }
                Terminal::ThreshM(k, ref subs) => {
                    if node_state.n_satisfied == k {
                        //multi-sig bug: Pop extra 0
                        if let Some(StackElement::Dissatisfied) = self.stack.pop() {
                            self.stack.push(StackElement::Satisfied);
                        } else {
                            return Some(Err(Error::MissingExtraZeroMultiSig))
                        }
                    } else if node_state.n_evaluated == subs.len() {
                        return Some(Err(Error::MultiSigEvaluationError))
                    } else {
                        match self.stack.evaluate_thresh_m(self.secp, self.sighash, &subs[node_state.n_evaluated]) {
                            Some(Ok(x)) => {
                                self.push_evaluation_state(
                                    node_state.node,
                                    node_state.n_evaluated + 1,
                                    node_state.n_satisfied + 1
                                );
                                return Some(Ok(x))
                            }
                            None => self.push_evaluation_state(
                                node_state.node,
                                node_state.n_evaluated + 1,
                                node_state.n_satisfied
                            ),
                            x => return x //forward errors as is
                        }
                    }
                }
                //All other match patterns should not be reached in any valid
                //type checked Miniscript
                _ => return Some(Err(Error::CouldNotEvaluate))
            };
        }

        //state empty implies that either the execution has terminated or we have a
        //Pk based descriptor
        if let Some(pk) = self.public_key{
            if let Some(StackElement::Push(sig)) = self.stack.pop(){
                if let Ok(sig) = verify_sersig(self.secp, self.sighash, &pk.to_public_key(), sig){
                    //Signature check successful, set public_key to None to
                    //terminate the next() function in the subsequent call
                    self.public_key = None;
                    self.stack.push(StackElement::Satisfied);
                    return Some(Ok(SatisfiedConstraint::PublicKey { key: pk, sig }))
                } else{
                    return Some(Err(Error::PkEvaluationError(pk.clone().to_public_key())))
                }
            } else{
                return Some(Err(Error::UnexpectedStackEnd))
            }
        } else {
            //All the script has been executed.
            //Check that the stack must contain exactly 1 satisfied element
            if self.stack.pop() == Some(StackElement::Satisfied)
                && self.stack.is_empty() {
                return None
            } else {
                return Some(Err(
                    Error::ScriptSatisfactionError))
            }
        }
    }
}

/// Helper function to verify serialized signature
pub fn verify_sersig<'stack>(
    secp: &secp256k1::Secp256k1<VerifyOnly>,
    sighash: secp256k1::Message,
    pk: &bitcoin::PublicKey,
    sigser: &[u8],
) -> Result<secp256k1::Signature, Error>
{
    if let Some((_sighashtype, sig)) = sigser.split_last() {
        match Signature::from_der(sig) {
            Ok(sig ) => {
                match secp.verify(&sighash, &sig, &pk.key) {
                    Ok(()) => Ok(sig),
                    Err(e) => Err(Error::Secp(e))
                }
            }
            Err(e) => Err(Error::Secp(e))
        }
    }else{
        return Err(Error::PkEvaluationError(pk.clone().to_public_key()))
    }
}

impl<'stack> Stack<'stack>
{
    ///wrapper for self.0.is_empty()
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    ///wrapper for self.0.len()
    fn len(&mut self, ) -> usize {
        self.0.len()
    }

    ///wrapper for self.0.pop()
    fn pop(&mut self, ) -> Option<StackElement<'stack>> {
        self.0.pop()
    }

    ///wrapper for self.0.push()
    fn push(&mut self, elem: StackElement<'stack>) -> () {
        self.0.push(elem);
    }

    ///wrapper for self.0.split_off()
    fn split_off(&mut self, k: usize) -> Vec<StackElement<'stack>> {
        self.0.split_off(k)
    }

    ///wrapper for self.0.last()
    fn last(&self) -> Option<&StackElement<'stack>> {
        self.0.last()
    }

    /// Helper function to evaluate a Pk Node which takes the
    /// top of the stack as input signature and validates it.
    /// Sat: If the signature witness is correct, 1 is pushed
    /// Unsat: For empty witness a 0 is pushed
    /// Err: All of other witness result in errors.
    /// `pk` CHECKSIG
    fn evaluate_pk<'desc, Pk>(
        &mut self,
        secp: &secp256k1::Secp256k1<VerifyOnly>,
        sighash: secp256k1::Message,
        pk: &'desc Pk,
    ) -> Option<Result<SatisfiedConstraint<'desc, 'stack, Pk>, Error>>
        where Pk: MiniscriptKey + ToPublicKey,
    {
        if let Some(sigser) = self.pop() {
            match sigser {
                StackElement::Dissatisfied => {
                    self.push(StackElement::Dissatisfied);
                    None
                },
                StackElement::Push(sigser) => {
                    let sig = verify_sersig(
                        secp,
                        sighash,
                        &pk.to_public_key(),
                        &sigser);
                    match sig {
                        Ok(sig) => {
                            self.push(StackElement::Satisfied);
                            Some(Ok(SatisfiedConstraint::PublicKey { key: pk, sig }))
                        }
                        Err(e) => {
                            return Some(Err(e))
                        }
                    }
                }
                StackElement::Satisfied =>
                    return Some(Err(Error::PkEvaluationError(pk.clone().to_public_key())))
            }
        } else {
            Some(Err(Error::UnexpectedStackEnd))
        }
    }

    /// Helper function to evaluate a Pkh Node. Takes input as pubkey and sig
    /// from the top of the stack and outputs Sat if the pubkey, sig is valid
    /// Sat: If the pubkey hash matches and signature witness is correct,
    /// Unsat: For an empty witness
    /// Err: All of other witness result in errors.
    /// `DUP HASH160 <keyhash> EQUALVERIY CHECKSIG`
    fn evaluate_pkh<'desc, Pk>(
        &mut self,
        secp: &secp256k1::Secp256k1<VerifyOnly>,
        sighash: secp256k1::Message,
        pkh: &'desc Pk::Hash,
    ) -> Option<Result<SatisfiedConstraint<'desc, 'stack, Pk>, Error>>
        where Pk: MiniscriptKey + ToPublicKey, Pk::Hash: ToHash160,
    {
        if let Some(StackElement::Push(pk)) = self.pop() {
            let pk_hash = hash160::Hash::hash(pk);
            if pk_hash != pkh.to_hash160() {
                return Some(Err(Error::PkHashVerifyFail(
                    pkh.to_hash160()
                )))
            };
            match bitcoin::PublicKey::from_slice(pk) {
                Ok(pk) => {
                    if let Some(sigser) = self.pop() {
                        match sigser {
                            StackElement::Dissatisfied => {
                                self.push(StackElement::Dissatisfied);
                                None
                            },
                            StackElement::Push(sigser) => {
                                let sig = verify_sersig(
                                    secp,
                                    sighash,
                                    &pk.to_public_key(),
                                    &sigser);
                                match sig {
                                    Ok(sig) => {
                                        self.push(StackElement::Satisfied);
                                        Some(Ok(SatisfiedConstraint::PublicKeyHash {
                                            keyhash: pkh,
                                            key: pk,
                                            sig
                                        }))
                                    }
                                    Err(e) => {
                                        return Some(Err(e))
                                    }
                                }
                            }
                            StackElement::Satisfied =>
                                return Some(Err
                                    (Error::PkEvaluationError
                                        (pk.clone().to_public_key())))
                        }
                    } else {
                        Some(Err(Error::UnexpectedStackEnd))
                    }
                }
                Err(..) => Some(Err(Error::PubkeyParseError))
            }
        } else {
            Some(Err(Error::UnexpectedStackEnd))
        }
    }

    /// Helper function to evaluate a After Node. Takes no arugment from stack
    /// `n CHECKSEQUENCEVERIFY 0NOTEQUAL` and `n CHECKSEQUENCEVERIFY`
    /// Ideally this should return int value as n: build_scriptint(t as i64)),
    /// The reason we don't need to copy the Script semantics is that
    /// Miniscript never evaluates integers and it is safe to treat them as
    /// booleans
    fn evaluate_after<'desc, Pk>(
        &mut self,
        n: &'desc u32,
        age: u32,
    ) -> Option<Result<SatisfiedConstraint<'desc, 'stack, Pk>, Error>>
        where Pk: MiniscriptKey + ToPublicKey,
    {
        if age >= *n {
            self.push(StackElement::Satisfied);
            Some(Ok(SatisfiedConstraint::RelativeTimeLock { time: n }))
        } else {
            Some(Err(Error::RelativeLocktimeNotMet(*n)))
        }
    }

    /// Helper function to evaluate a Older Node. Takes no arugment from stack
    /// `n CHECKLOCKTIMEVERIFY 0NOTEQUAL` and `n CHECKLOCKTIMEVERIFY`
    /// Ideally this should return int value as n: build_scriptint(t as i64)),
    /// The reason we don't need to copy the Script semantics is that
    /// Miniscript never evaluates integers and it is safe to treat them as
    /// booleans
    fn evaluate_older<'desc, Pk>(
        &mut self,
        n: &'desc u32,
        height: u32,
    ) -> Option<Result<SatisfiedConstraint<'desc, 'stack, Pk>, Error>>
        where Pk: MiniscriptKey + ToPublicKey,
    {
        if height >= *n {
            self.push(StackElement::Satisfied);
            Some(Ok(SatisfiedConstraint::AbsoluteTimeLock { time: n }))
        } else {
            Some(Err(Error::AbsoluteLocktimeNotMet(*n)))
        }
    }

    /// Helper function to evaluate a Sha256 Node.
    /// `SIZE 32 EQUALVERIFY SHA256 h EQUAL`
    fn evaluate_sha256<'desc, Pk>(
        &mut self,
        hash: &'desc sha256::Hash,
    ) -> Option<Result<SatisfiedConstraint<'desc, 'stack, Pk>, Error>>
        where Pk: MiniscriptKey + ToPublicKey,
    {
        if let Some(StackElement::Push(preimage)) = self.pop() {
            if preimage.len() != 32 {
                return Some(Err(Error::HashPreimageLengthMismatch))
            }
            if sha256::Hash::hash(preimage) == *hash {
                self.push(StackElement::Satisfied);
                Some(Ok(SatisfiedConstraint::HashLock {
                    hash: HashLockType::Sha256(hash),
                    preimage,
                }))
            } else {
                self.push(StackElement::Dissatisfied);
                None
            }
        } else {
            Some(Err(Error::UnexpectedStackEnd))
        }
    }

    /// Helper function to evaluate a Hash256 Node.
    /// `SIZE 32 EQUALVERIFY HASH256 h EQUAL`
    fn evaluate_hash256<'desc, Pk>(
        &mut self,
        hash: &'desc sha256d::Hash,
    ) -> Option<Result<SatisfiedConstraint<'desc, 'stack, Pk>, Error>>
        where Pk: MiniscriptKey + ToPublicKey,
    {
        if let Some(StackElement::Push(preimage)) = self.pop() {
            if preimage.len() != 32 {
                return Some(Err(Error::HashPreimageLengthMismatch))
            }
            if sha256d::Hash::hash(preimage) == *hash {
                self.push(StackElement::Satisfied);
                Some(Ok(SatisfiedConstraint::HashLock {
                    hash: HashLockType::Hash256(hash),
                    preimage,
                }))
            } else {
                self.push(StackElement::Dissatisfied);
                None
            }
        } else {
            Some(Err(Error::UnexpectedStackEnd))
        }
    }

    /// Helper function to evaluate a Hash160 Node.
    /// `SIZE 32 EQUALVERIFY HASH160 h EQUAL`
    fn evaluate_hash160<'desc, Pk>(
        &mut self,
        hash: &'desc hash160::Hash,
    ) -> Option<Result<SatisfiedConstraint<'desc, 'stack, Pk>, Error>>
        where Pk: MiniscriptKey + ToPublicKey,
    {
        if let Some(StackElement::Push(preimage)) = self.pop() {
            if preimage.len() != 32 {
                return Some(Err(Error::HashPreimageLengthMismatch))
            }
            if hash160::Hash::hash(preimage) == *hash {
                self.push(StackElement::Satisfied);
                Some(Ok(SatisfiedConstraint::HashLock {
                    hash: HashLockType::Hash160(hash),
                    preimage,
                }))
            } else {
                self.push(StackElement::Dissatisfied);
                None
            }
        } else {
            Some(Err(Error::UnexpectedStackEnd))
        }
    }

    /// Helper function to evaluate a RipeMd160 Node.
    /// `SIZE 32 EQUALVERIFY RIPEMD160 h EQUAL`
    fn evaluate_ripemd160<'desc, Pk>(
        &mut self,
        hash: &'desc ripemd160::Hash,
    ) -> Option<Result<SatisfiedConstraint<'desc, 'stack, Pk>, Error>>
        where Pk: MiniscriptKey + ToPublicKey,
    {
        if let Some(StackElement::Push(preimage)) = self.pop() {
            if preimage.len() != 32 {
                return Some(Err(Error::HashPreimageLengthMismatch))
            }
            if ripemd160::Hash::hash(preimage) == *hash {
                self.push(StackElement::Satisfied);
                Some(Ok(SatisfiedConstraint::HashLock {
                    hash: HashLockType::Ripemd160(hash),
                    preimage,
                }))
            } else {
                self.push(StackElement::Dissatisfied);
                None
            }
        } else {
            Some(Err(Error::UnexpectedStackEnd))
        }
    }

    /// Helper function to evaluate a checkmultisig which takes the top of the
    /// stack as input signatures and validates it in order of pubkeys.
    /// For example, if the first signature is satisfied by second public key,
    /// other signatures are not checked against the first pubkey.
    /// `thresh_m(2,pk1,pk2)` would be satisfied by `[0 sig2 sig1]` and Err on
    /// `[0 sig2 sig1]`
    fn evaluate_thresh_m<'desc, Pk>(
        &mut self,
        secp: &secp256k1::Secp256k1<VerifyOnly>,
        sighash: secp256k1::Message,
        pk: &'desc Pk,
    ) -> Option<Result<SatisfiedConstraint<'desc, 'stack, Pk>, Error>>
        where Pk: MiniscriptKey + ToPublicKey,
    {
        if let Some(witness_sig) = self.pop()
        {
            if let StackElement::Push(sigser) = witness_sig {
                let sig = verify_sersig(
                    secp,
                    sighash,
                    &pk.to_public_key(),
                    &sigser);
                match sig {
                    Ok(sig) => {
                        return Some(Ok(SatisfiedConstraint::PublicKey { key: pk, sig }))
                    }
                    Err(..) => {
                        self.push(witness_sig);
                        return None
                    }
                }
            }
            else{
                Some(Err(Error::UnexpectedStackBoolean))
            }
        }else{
            Some(Err(Error::UnexpectedStackEnd))
        }
    }
}

#[cfg(test)]
mod tests {

    use bitcoin;
    use MiniscriptKey;
    use ToPublicKey;
    use bitcoin_hashes::{Hash, hash160, sha256, sha256d, ripemd160};
    use secp256k1::{self, VerifyOnly, Secp256k1};
    use descriptor::satisfied_contraints::{Error, Stack, StackElement, SatisfiedConstraints, SatisfiedConstraint, HashLockType, NodeEvaluationState};
    use ::{Miniscript};
    use std::str::FromStr;

    fn setup_keys_sigs(n: usize) -> (
        Vec<bitcoin::PublicKey>,
        Vec<Vec<u8> >,
        Vec<secp256k1::Signature>,
        secp256k1::Message,
        Secp256k1<VerifyOnly>,
    ) {
        let secp_sign = secp256k1::Secp256k1::signing_only();
        let secp_verify = secp256k1::Secp256k1::verification_only();
        let msg = secp256k1::Message::from_slice(
            &b"Yoda: btc, I trust. HODL I must!"[..]
        ).expect("32 bytes");
        let mut pks = vec![];
        let mut secp_sigs = vec![];
        let mut der_sigs = vec![];
        let mut sk = [0; 32];
        for i in 1..n+1 {
            sk[0] = i as u8;
            sk[1] = (i >> 8) as u8;
            sk[2] = (i >> 16) as u8;

            let sk = secp256k1::SecretKey::from_slice(&sk[..]).expect("secret key");
            let pk = bitcoin::PublicKey {
                key: secp256k1::PublicKey::from_secret_key(
                    &secp_sign,
                    &sk,
                ),
                compressed: true,
            };
            let sig = secp_sign.sign(&msg, &sk);
            secp_sigs.push(sig);
            let mut sigser = sig.serialize_der();
            sigser.push(0x01); // sighash_all
            pks.push(pk);
            der_sigs.push(sigser);
        }
        (pks, der_sigs, secp_sigs, msg, secp_verify)
    }

    #[test]
    fn sat_contraints(){
        let (pks, der_sigs, secp_sigs, sighash, secp) = setup_keys_sigs(10);

        let pk = ms_str!("c:pk({})", pks[0]);
        let pkh = ms_str!("c:pk_h({})", pks[1].to_pubkeyhash());
        //Time
        let after = ms_str!("after({})", 1000);
        let older = ms_str!("older({})", 1000);
        //Hashes
        let preimage = vec![0xab as u8; 32];
        let sha256_hash = sha256::Hash::hash(&preimage);
        let sha256 = ms_str!("sha256({})", sha256_hash);
        let sha256d_hash = sha256d::Hash::hash(&preimage);
        let hash256 = ms_str!("hash256({})", sha256d_hash);
        let hash160_hash = hash160::Hash::hash(&preimage);
        let hash160 = ms_str!("hash160({})", hash160_hash);
        let ripemd160_hash = ripemd160::Hash::hash(&preimage);
        let ripemd160 = ms_str!("ripemd160({})", ripemd160_hash);

        let stack = vec![StackElement::Push(&der_sigs[0])];

        let constraints = SatisfiedConstraints{
            secp: &secp,
            sighash: sighash,
            stack: Stack(stack),
            public_key: None,
            state: vec![NodeEvaluationState{node: &pk, n_evaluated:0, n_satisfied:0}],
            age: 0,
            height: 0,
        };
        let pk_satisfied : Result<Vec<SatisfiedConstraint<bitcoin::PublicKey>>,
            Error> = constraints.collect();
        assert_eq!(pk_satisfied.unwrap(),
                   vec![SatisfiedConstraint::PublicKey {
                       key: &pks[0],
                       sig: secp_sigs[0].clone(),
                       }]);

        //Check Pk failure with wrong signature
        let stack = vec![StackElement::Dissatisfied];

        let constraints = SatisfiedConstraints{
            secp: &secp,
            sighash: sighash,
            stack: Stack(stack),
            public_key: None,
            state: vec![NodeEvaluationState{node: &pk, n_evaluated:0, n_satisfied:0}],
            age: 0,
            height: 0,
        };
        let pk_err : Result<Vec<SatisfiedConstraint<bitcoin::PublicKey>>,
            Error> = constraints.collect();
        assert!(pk_err.is_err());

        //Check Pkh
        let pk_bytes = pks[1].to_public_key().to_bytes();
        let stack = vec![
            StackElement::Push(&der_sigs[1]),
            StackElement::Push(&pk_bytes),
        ];

        let constraints = SatisfiedConstraints{
            secp: &secp,
            sighash: sighash,
            stack: Stack(stack),
            public_key: None,
            state: vec![NodeEvaluationState{node: &pkh, n_evaluated:0, n_satisfied:0}],
            age: 0,
            height: 0,
        };
        let pkh_satisfied : Result<Vec<SatisfiedConstraint<bitcoin::PublicKey>>,
            Error> = constraints.collect();
        assert_eq!(pkh_satisfied.unwrap(),
                   vec![SatisfiedConstraint::PublicKeyHash {
                       keyhash: &pks[1].to_pubkeyhash(),
                       key: pks[1].clone(),
                       sig: secp_sigs[1].clone(),
                   }]);

        //Check After
        let stack = vec![];

        let constraints = SatisfiedConstraints{
            secp: &secp,
            sighash: sighash,
            stack: Stack(stack),
            public_key: None,
            state: vec![NodeEvaluationState{node: &after, n_evaluated:0, n_satisfied:0}],
            age: 1002,
            height: 0,
        };
        let after_satisfied : Result<Vec<SatisfiedConstraint<bitcoin::PublicKey>>,
            Error> = constraints.collect();
        assert_eq!(after_satisfied.unwrap(),
                   vec![SatisfiedConstraint::RelativeTimeLock {
                       time: &1000,
                   }]);

        //Check Older
        let stack = vec![];
        let constraints = SatisfiedConstraints{
            secp: &secp,
            sighash: sighash,
            stack: Stack(stack),
            public_key: None,
            state: vec![NodeEvaluationState{node: &older, n_evaluated:0, n_satisfied:0}],
            age: 0,
            height: 1002,
        };
        let older_satisfied : Result<Vec<SatisfiedConstraint<bitcoin::PublicKey>>,
            Error> = constraints.collect();
        assert_eq!(older_satisfied.unwrap(),
                   vec![SatisfiedConstraint::AbsoluteTimeLock {
                       time: &1000,
                   }]);

        //Check Sha256
        let stack = vec![StackElement::Push(&preimage)];
        let constraints = SatisfiedConstraints{
            secp: &secp,
            sighash: sighash,
            stack: Stack(stack),
            public_key: None,
            state: vec![NodeEvaluationState{node: &sha256, n_evaluated:0, n_satisfied:0}],
            age: 0,
            height: 0,
        };
        let sah256_satisfied : Result<Vec<SatisfiedConstraint<bitcoin::PublicKey>>,
            Error> = constraints.collect();
        assert_eq!(sah256_satisfied.unwrap(),
                   vec![SatisfiedConstraint::HashLock {
                       hash: HashLockType::Sha256(&sha256_hash),
                       preimage: &preimage,
                   }]);

        //Check Shad256
        let stack = vec![StackElement::Push(&preimage)];

        let constraints = SatisfiedConstraints{
            secp: &secp,
            sighash: sighash,
            stack: Stack(stack),
            public_key: None,
            state: vec![NodeEvaluationState{node: &hash256, n_evaluated:0, n_satisfied:0}],
            age: 0,
            height: 0,
        };
        let sha256d_satisfied : Result<Vec<SatisfiedConstraint<bitcoin::PublicKey>>,
            Error> = constraints.collect();
        assert_eq!(sha256d_satisfied.unwrap(),
                   vec![SatisfiedConstraint::HashLock {
                       hash: HashLockType::Hash256(&sha256d_hash),
                       preimage: &preimage,
                   }]);

        //Check hash160
        let stack = vec![StackElement::Push(&preimage)];

        let constraints = SatisfiedConstraints{
            secp: &secp,
            sighash: sighash,
            stack: Stack(stack),
            public_key: None,
            state: vec![NodeEvaluationState{node: &hash160, n_evaluated:0, n_satisfied:0}],
            age: 0,
            height: 0,
        };
        let hash160_satisfied : Result<Vec<SatisfiedConstraint<bitcoin::PublicKey>>,
            Error> = constraints.collect();
        assert_eq!(hash160_satisfied.unwrap(),
                   vec![SatisfiedConstraint::HashLock {
                       hash: HashLockType::Hash160(&hash160_hash),
                       preimage: &preimage,
                   }]);

        //Check ripemd160
        let stack = vec![StackElement::Push(&preimage)];

        let constraints = SatisfiedConstraints{
            secp: &secp,
            sighash: sighash,
            stack: Stack(stack),
            public_key: None,
            state: vec![NodeEvaluationState{node: &ripemd160, n_evaluated:0, n_satisfied:0}],
            age: 0,
            height: 0,
        };
        let ripemd160_satisfied : Result<Vec<SatisfiedConstraint<bitcoin::PublicKey>>,
            Error> = constraints.collect();
        assert_eq!(ripemd160_satisfied.unwrap(),
                   vec![SatisfiedConstraint::HashLock {
                       hash: HashLockType::Ripemd160(&ripemd160_hash),
                       preimage: &preimage
                   }]);

        //Check AndV
        let pk_bytes = pks[1].to_public_key().to_bytes();
        let stack = vec![
            StackElement::Push(&der_sigs[1]),
            StackElement::Push(&pk_bytes),
        StackElement::Push(&der_sigs[0])];
        let elem = ms_str!("and_v(vc:pk({}),c:pk_h({}))",
                     pks[0], pks[1].to_pubkeyhash());

        let constraints = SatisfiedConstraints{
            secp: &secp,
            sighash: sighash,
            stack: Stack(stack),
            public_key: None,
            state: vec![NodeEvaluationState{node: &elem, n_evaluated:0, n_satisfied:0}],
            age: 0,
            height: 0,
        };
        let and_v_satisfied : Result<Vec<SatisfiedConstraint<bitcoin::PublicKey>>,
            Error> = constraints.collect();
        assert_eq!(and_v_satisfied.unwrap(),
                   vec![SatisfiedConstraint::PublicKey {
                       key: &pks[0],
                       sig: secp_sigs[0].clone(),
                   }, SatisfiedConstraint::PublicKeyHash {
                       keyhash : &pks[1].to_pubkeyhash(),
                       key: pks[1].clone(),
                       sig: secp_sigs[1].clone(),
                   }]);

        //Check AndB
        let stack = vec![
            StackElement::Push(&preimage),
            StackElement::Push(&der_sigs[0])];
        let elem = ms_str!("and_b(c:pk({}),sj:and_v(v:sha256({}),true))",
                     pks[0], sha256_hash);

        let constraints = SatisfiedConstraints{
            secp: &secp,
            sighash: sighash,
            stack: Stack(stack),
            public_key: None,
            state: vec![NodeEvaluationState{node: &elem, n_evaluated:0, n_satisfied:0}],
            age: 0,
            height: 0,
        };
        let and_b_satisfied : Result<Vec<SatisfiedConstraint<bitcoin::PublicKey>>,
            Error> = constraints.collect();
        assert_eq!(and_b_satisfied.unwrap(),
                   vec![SatisfiedConstraint::PublicKey {
                       key: &pks[0],
                       sig: secp_sigs[0].clone(),
                   }, SatisfiedConstraint::HashLock {
                       hash: HashLockType::Sha256(&sha256_hash),
                       preimage: &preimage,
                   }]);

        //Check AndOr
        let stack = vec![
            StackElement::Push(&preimage),
            StackElement::Push(&der_sigs[0])];
        let elem = ms_str!("and_or(c:pk({}),c:pk_h({}),j:and_v(v:sha256({}),true))",
                     pks[0], pks[1].to_pubkeyhash(), sha256_hash);

        let constraints = SatisfiedConstraints{
            secp: &secp,
            sighash: sighash,
            stack: Stack(stack),
            public_key: None,
            state: vec![NodeEvaluationState{node: &elem, n_evaluated:0, n_satisfied:0}],
            age: 0,
            height: 0,
        };
        let and_or_satisfied : Result<Vec<SatisfiedConstraint<bitcoin::PublicKey>>,
            Error> = constraints.collect();
        assert_eq!(and_or_satisfied.unwrap(),
                   vec![SatisfiedConstraint::PublicKey {
                       key: &pks[0],
                       sig: secp_sigs[0].clone(),
                   }, SatisfiedConstraint::HashLock {
                       hash: HashLockType::Sha256(&sha256_hash),
                       preimage: &preimage,
                   }]);

        //AndOr second satisfaction path
        let pk_bytes = pks[1].to_public_key().to_bytes();
        let stack = vec![
            StackElement::Push(&der_sigs[1]),
            StackElement::Push(&pk_bytes),
            StackElement::Dissatisfied];

        let constraints = SatisfiedConstraints{
            secp: &secp,
            sighash: sighash,
            stack: Stack(stack),
            public_key: None,
            state: vec![NodeEvaluationState{node: &elem, n_evaluated:0, n_satisfied:0}],
            age: 0,
            height: 0,
        };
        let and_or_satisfied : Result<Vec<SatisfiedConstraint<bitcoin::PublicKey>>,
            Error> = constraints.collect();
        assert_eq!(and_or_satisfied.unwrap(),
                   vec![SatisfiedConstraint::PublicKeyHash {
                       keyhash : &pks[1].to_pubkeyhash(),
                       key: pks[1].clone(),
                       sig: secp_sigs[1].clone(),
                   }]);

        //Check OrB
        let stack = vec![
            StackElement::Push(&preimage),
            StackElement::Dissatisfied];
        let elem = ms_str!("or_b(c:pk({}),sj:and_v(v:sha256({}),true))",
                     pks[0], sha256_hash);

        let constraints = SatisfiedConstraints{
            secp: &secp,
            sighash: sighash,
            stack: Stack(stack),
            public_key: None,
            state: vec![NodeEvaluationState{node: &elem, n_evaluated:0, n_satisfied:0}],
            age: 0,
            height: 0,
        };
        let or_b_satisfied : Result<Vec<SatisfiedConstraint<bitcoin::PublicKey>>,
            Error> = constraints.collect();
        assert_eq!(or_b_satisfied.unwrap(),
                   vec![SatisfiedConstraint::HashLock {
                       hash: HashLockType::Sha256(&sha256_hash),
                       preimage: &preimage,
                   }]);

        //Check OrD
        let stack = vec![
            StackElement::Push(&der_sigs[0])];

        let elem = ms_str!("or_d(c:pk({}),j:and_v(v:sha256({}),true))",
                     pks[0], sha256_hash);

        let constraints = SatisfiedConstraints{
            secp: &secp,
            sighash: sighash,
            stack: Stack(stack),
            public_key: None,
            state: vec![NodeEvaluationState{node: &elem, n_evaluated:0, n_satisfied:0}],
            age: 0,
            height: 0,
        };
        let or_d_satisfied : Result<Vec<SatisfiedConstraint<bitcoin::PublicKey>>,
            Error> = constraints.collect();
        assert_eq!(or_d_satisfied.unwrap(),
                   vec![SatisfiedConstraint::PublicKey {
                       key: &pks[0],
                       sig: secp_sigs[0].clone(),
                   }]);

        //Check OrC
        let stack = vec![
            StackElement::Push(&der_sigs[0]),
            StackElement::Dissatisfied];
        let elem = ms_str!("and_v(or_c(j:and_v(v:sha256({}),true),vc:pk({})),true)",
                     sha256_hash, pks[0]);

        let constraints = SatisfiedConstraints{
            secp: &secp,
            sighash: sighash,
            stack: Stack(stack),
            public_key: None,
            state: vec![NodeEvaluationState{node: &elem, n_evaluated:0, n_satisfied:0}],
            age: 0,
            height: 0,
        };
        let or_c_satisfied : Result<Vec<SatisfiedConstraint<bitcoin::PublicKey>>,
            Error> = constraints.collect();
        assert_eq!(or_c_satisfied.unwrap(),
                   vec![SatisfiedConstraint::PublicKey {
                       key: &pks[0],
                       sig: secp_sigs[0].clone(),
                   }]);

        //Check OrI
        let stack = vec![
            StackElement::Push(&der_sigs[0]),
            StackElement::Dissatisfied];
        let elem = ms_str!("or_i(j:and_v(v:sha256({}),true),c:pk({}))",
                     sha256_hash, pks[0]);

        let constraints = SatisfiedConstraints{
            secp: &secp,
            sighash: sighash,
            stack: Stack(stack),
            public_key: None,
            state: vec![NodeEvaluationState{node: &elem, n_evaluated:0, n_satisfied:0}],
            age: 0,
            height: 0,
        };
        let or_i_satisfied : Result<Vec<SatisfiedConstraint<bitcoin::PublicKey>>,
            Error> = constraints.collect();
        assert_eq!(or_i_satisfied.unwrap(),
                   vec![SatisfiedConstraint::PublicKey {
                       key: &pks[0],
                       sig: secp_sigs[0].clone(),
                   }]);

        //Check Thres
        let stack = vec![
            StackElement::Push(&der_sigs[0]),
            StackElement::Push(&der_sigs[1]),
            StackElement::Push(&der_sigs[2]),
            StackElement::Dissatisfied,
            StackElement::Dissatisfied];
        let elem = ms_str!("thresh(3,c:pk({}),sc:pk({}),sc:pk({}),sc:pk({}),sc:pk({}))",
                     pks[4],pks[3],pks[2],pks[1],pks[0],);

        let constraints = SatisfiedConstraints{
            secp: &secp,
            sighash: sighash,
            stack: Stack(stack),
            public_key: None,
            state: vec![NodeEvaluationState{node: &elem, n_evaluated:0, n_satisfied:0}],
            age: 0,
            height: 0,
        };
        let thresh_satisfied : Result<Vec<SatisfiedConstraint<bitcoin::PublicKey>>,
            Error> = constraints.collect();
        assert_eq!(thresh_satisfied.unwrap(),
                   vec![SatisfiedConstraint::PublicKey {
                       key: &pks[2],
                       sig: secp_sigs[2].clone(),
                   }, SatisfiedConstraint::PublicKey {
                       key: &pks[1],
                       sig: secp_sigs[1].clone(),
                   }, SatisfiedConstraint::PublicKey {
                            key: &pks[0],
                            sig: secp_sigs[0].clone(),
                   }]);

        //Check ThresM
        let stack = vec![
            StackElement::Dissatisfied,
            StackElement::Push(&der_sigs[0]),
            StackElement::Push(&der_sigs[1]),
            StackElement::Push(&der_sigs[2])];
        let elem = ms_str!("thresh_m(3,{},{},{},{},{})",
                     pks[4],pks[3],pks[2],pks[1],pks[0],);

        let constraints = SatisfiedConstraints{
            secp: &secp,
            sighash: sighash,
            stack: Stack(stack),
            public_key: None,
            state: vec![NodeEvaluationState{node: &elem, n_evaluated:0, n_satisfied:0}],
            age: 0,
            height: 0,
        };
        let thresh_m_satisfied : Result<Vec<SatisfiedConstraint<bitcoin::PublicKey>>,
            Error> = constraints.collect();
        assert_eq!(thresh_m_satisfied.unwrap(),
                   vec![SatisfiedConstraint::PublicKey {
                       key: &pks[2],
                       sig: secp_sigs[2].clone(),
                   }, SatisfiedConstraint::PublicKey {
                       key: &pks[1],
                       sig: secp_sigs[1].clone(),
                   }, SatisfiedConstraint::PublicKey {
                       key: &pks[0],
                       sig: secp_sigs[0].clone(),
                   }]);

        //Error ThresM: Invalid order of sigs
        let stack = vec![
            StackElement::Dissatisfied,
            StackElement::Push(&der_sigs[0]),
            StackElement::Push(&der_sigs[2]),
            StackElement::Push(&der_sigs[1])];
        let elem = ms_str!("thresh_m(3,{},{},{},{},{})",
                     pks[4],pks[3],pks[2],pks[1],pks[0],);

        let constraints = SatisfiedConstraints{
            secp: &secp,
            sighash: sighash,
            stack: Stack(stack),
            public_key: None,
            state: vec![NodeEvaluationState{node: &elem, n_evaluated:0, n_satisfied:0}],
            age: 0,
            height: 0,
        };
        let thresh_m_error : Result<Vec<SatisfiedConstraint<bitcoin::PublicKey>>,
            Error> = constraints.collect();
        assert!(thresh_m_error.is_err());
    }
}
