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

use bitcoin::hashes::{hash160, ripemd160, sha256, sha256d, Hash};
use bitcoin::{self, secp256k1};
use fmt;
use miniscript::context::Any;
use miniscript::ScriptContext;
use Descriptor;
use Terminal;
use {error, Miniscript};
use {BitcoinSig, ToPublicKey};

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
    /// Signature failed to verify
    InvalidSignature(bitcoin::PublicKey),
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

#[doc(hidden)]
impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Error {
        Error::Secp(e)
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        ""
    }
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::Secp(ref err) => Some(err),
            ref x => Some(x),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::UnexpectedStackEnd => f.write_str("Unexpected Stack End"),
            Error::UnexpectedStackElementPush => write!(f, "Got {}, expected Stack Boolean", 1),
            Error::VerifyFailed => {
                f.write_str("Expected Satisfied Boolean at stack top for VERIFY")
            }
            Error::InsufficientSignaturesMultiSig => f.write_str("Insufficient signatures for CMS"),
            Error::MissingExtraZeroMultiSig => f.write_str("CMS missing extra zero"),
            Error::MultiSigEvaluationError => {
                f.write_str("CMS script aborted, incorrect satisfaction/dissatisfaction")
            }
            Error::InvalidSignature(pk) => write!(f, "bad signature with pk {}", pk),
            Error::CouldNotEvaluate => f.write_str("Interpreter Error: Could not evaluate"),
            Error::PkEvaluationError(ref key) => write!(f, "Incorrect Signature for pk {}", key),
            Error::ScriptSatisfactionError => f.write_str("Top level script must be satisfied"),
            Error::PkHashVerifyFail(ref hash) => write!(f, "Pubkey Hash check failed {}", hash),
            Error::PubkeyParseError => f.write_str("Error in parsing pubkey {}"),
            Error::HashPreimageLengthMismatch => f.write_str("Hash preimage should be 32 bytes"),
            Error::UnexpectedStackBoolean => {
                f.write_str("Expected Stack Push operation, found stack bool")
            }
            Error::RelativeLocktimeNotMet(n) => {
                write!(f, "required relative locktime CSV of {} blocks, not met", n)
            }
            Error::AbsoluteLocktimeNotMet(n) => write!(
                f,
                "required absolute locktime CLTV of {} blocks, not met",
                n
            ),
            Error::Secp(ref e) => fmt::Display::fmt(e, f),
        }
    }
}

/// Definition of Stack Element of the Stack used for interpretation of Miniscript.
/// All stack elements with vec![] go to Dissatisfied and vec![1] are marked to Satisfied.
/// Others are directly pushed as witness
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
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

impl<'stack> StackElement<'stack> {
    /// Convert witness stack to StackElement
    pub fn from(v: &'stack [u8]) -> StackElement<'stack> {
        if *v == [1] {
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
pub enum HashLockType<'desc> {
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
pub enum SatisfiedConstraint<'desc, 'stack> {
    ///Public key and corresponding signature
    PublicKey {
        key: &'desc bitcoin::PublicKey,
        sig: secp256k1::Signature,
    },
    ///PublicKeyHash, corresponding pubkey and signature
    PublicKeyHash {
        keyhash: &'desc hash160::Hash,
        key: bitcoin::PublicKey,
        sig: secp256k1::Signature,
    },
    ///Hashlock and preimage for SHA256
    HashLock {
        hash: HashLockType<'desc>,
        preimage: &'stack [u8],
    },
    ///Relative Timelock for CSV.
    RelativeTimeLock { time: &'desc u32 },
    ///Absolute Timelock for CLTV.
    AbsoluteTimeLock { time: &'desc u32 },
}

///This is used by the interpreter to know which evaluation state a AstemElem is.
///This is required because whenever a same node(for eg. OrB) appears on the stack, we don't
///know if the left child has been evaluated or not. And based on the result on
///the top of the stack, we need to decide whether to execute right child or not.
///This is also useful for wrappers and thresholds which push a value on the stack
///depending on evaluation of the children.
struct NodeEvaluationState<'desc> {
    ///The node which is being evaluated
    node: &'desc Miniscript<bitcoin::PublicKey, Any>,
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
///_until_Error.
pub struct SatisfiedConstraints<'desc, 'stack, F: FnMut(&bitcoin::PublicKey, BitcoinSig) -> bool> {
    verify_sig: F,
    public_key: Option<&'desc bitcoin::PublicKey>,
    state: Vec<NodeEvaluationState<'desc>>,
    stack: Stack<'stack>,
    age: u32,
    height: u32,
    has_errored: bool,
}

/// Stack Data structure representing the stack input to Miniscript. This Stack
/// is created from the combination of ScriptSig and Witness stack.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Stack<'stack>(pub Vec<StackElement<'stack>>);

///Iterator for SatisfiedConstraints
impl<'desc, 'stack, F> Iterator for SatisfiedConstraints<'desc, 'stack, F>
where
    Any: ScriptContext,
    F: FnMut(&bitcoin::PublicKey, BitcoinSig) -> bool,
{
    type Item = Result<SatisfiedConstraint<'desc, 'stack>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.has_errored {
            // Stop yielding values after the first error
            None
        } else {
            let res = self.iter_next();
            if let Some(Err(_)) = res {
                self.has_errored = true;
            }
            res
        }
    }
}

impl<'desc, 'stack, F> SatisfiedConstraints<'desc, 'stack, F>
where
    F: FnMut(&bitcoin::PublicKey, BitcoinSig) -> bool,
{
    // Creates a new iterator over all constraints satisfied for a given
    /// descriptor by a given witness stack. Because this iterator is lazy,
    /// it may return satisfied constraints even if these turn out to be
    /// irrelevant to the final (dis)satisfaction of the descriptor.
    pub fn from_descriptor(
        des: &'desc Descriptor<bitcoin::PublicKey>,
        stack: Stack<'stack>,
        verify_sig: F,
        age: u32,
        height: u32,
    ) -> SatisfiedConstraints<'desc, 'stack, F> {
        match des {
            &Descriptor::Pk(ref pk) | &Descriptor::Pkh(ref pk) => SatisfiedConstraints {
                verify_sig: verify_sig,
                public_key: Some(pk),
                state: vec![],
                stack: stack,
                age,
                height,
                has_errored: false,
            },
            &Descriptor::ShWpkh(ref pk) | &Descriptor::Wpkh(ref pk) => SatisfiedConstraints {
                verify_sig: verify_sig,
                public_key: Some(pk),
                state: vec![],
                stack: stack,
                age,
                height,
                has_errored: false,
            },
            &Descriptor::Wsh(ref miniscript) | &Descriptor::ShWsh(ref miniscript) => {
                SatisfiedConstraints {
                    verify_sig: verify_sig,
                    public_key: None,
                    state: vec![NodeEvaluationState {
                        node: Any::from_segwitv0(miniscript),
                        n_evaluated: 0,
                        n_satisfied: 0,
                    }],
                    stack: stack,
                    age,
                    height,
                    has_errored: false,
                }
            }
            &Descriptor::Sh(ref miniscript) | &Descriptor::Bare(ref miniscript) => {
                SatisfiedConstraints {
                    verify_sig: verify_sig,
                    public_key: None,
                    state: vec![NodeEvaluationState {
                        node: Any::from_legacy(miniscript),
                        n_evaluated: 0,
                        n_satisfied: 0,
                    }],
                    stack: stack,
                    age,
                    height,
                    has_errored: false,
                }
            }
        }
    }
}

impl<'desc, 'stack, F> SatisfiedConstraints<'desc, 'stack, F>
where
    Any: ScriptContext,
    F: FnMut(&bitcoin::PublicKey, BitcoinSig) -> bool,
{
    /// Helper function to push a NodeEvaluationState on state stack
    fn push_evaluation_state(
        &mut self,
        node: &'desc Miniscript<bitcoin::PublicKey, Any>,
        n_evaluated: usize,
        n_satisfied: usize,
    ) -> () {
        self.state.push(NodeEvaluationState {
            node,
            n_evaluated,
            n_satisfied,
        })
    }

    /// Helper function to step the iterator
    fn iter_next(&mut self) -> Option<Result<SatisfiedConstraint<'desc, 'stack>, Error>> {
        while let Some(node_state) = self.state.pop() {
            //non-empty stack
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
                Terminal::PkK(ref pk) => {
                    debug_assert_eq!(node_state.n_evaluated, 0);
                    debug_assert_eq!(node_state.n_satisfied, 0);
                    let res = self.stack.evaluate_pk(&mut self.verify_sig, pk);
                    if res.is_some() {
                        return res;
                    }
                }
                Terminal::PkH(ref pkh) => {
                    debug_assert_eq!(node_state.n_evaluated, 0);
                    debug_assert_eq!(node_state.n_satisfied, 0);
                    let res = self.stack.evaluate_pkh(&mut self.verify_sig, pkh);
                    if res.is_some() {
                        return res;
                    }
                }
                Terminal::After(ref n) => {
                    debug_assert_eq!(node_state.n_evaluated, 0);
                    debug_assert_eq!(node_state.n_satisfied, 0);
                    let res = self.stack.evaluate_after(n, self.age);
                    if res.is_some() {
                        return res;
                    }
                }
                Terminal::Older(ref n) => {
                    debug_assert_eq!(node_state.n_evaluated, 0);
                    debug_assert_eq!(node_state.n_satisfied, 0);
                    let res = self.stack.evaluate_older(n, self.height);
                    if res.is_some() {
                        return res;
                    }
                }
                Terminal::Sha256(ref hash) => {
                    debug_assert_eq!(node_state.n_evaluated, 0);
                    debug_assert_eq!(node_state.n_satisfied, 0);
                    let res = self.stack.evaluate_sha256(hash);
                    if res.is_some() {
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
                Terminal::Hash160(ref hash) => {
                    debug_assert_eq!(node_state.n_evaluated, 0);
                    debug_assert_eq!(node_state.n_satisfied, 0);
                    let res = self.stack.evaluate_hash160(hash);
                    if res.is_some() {
                        return res;
                    }
                }
                Terminal::Ripemd160(ref hash) => {
                    debug_assert_eq!(node_state.n_evaluated, 0);
                    debug_assert_eq!(node_state.n_satisfied, 0);
                    let res = self.stack.evaluate_ripemd160(hash);
                    if res.is_some() {
                        return res;
                    }
                }
                Terminal::Alt(ref sub) | Terminal::Swap(ref sub) | Terminal::Check(ref sub) => {
                    debug_assert_eq!(node_state.n_evaluated, 0);
                    debug_assert_eq!(node_state.n_satisfied, 0);
                    self.push_evaluation_state(sub, 0, 0);
                }
                Terminal::DupIf(ref sub) if node_state.n_evaluated == 0 => match self.stack.pop() {
                    Some(StackElement::Dissatisfied) => {
                        self.stack.push(StackElement::Dissatisfied);
                    }
                    Some(StackElement::Satisfied) => {
                        self.push_evaluation_state(node_state.node, 1, 1);
                        self.push_evaluation_state(sub, 0, 0);
                    }
                    Some(StackElement::Push(_v)) => {
                        return Some(Err(Error::UnexpectedStackElementPush))
                    }
                    None => return Some(Err(Error::UnexpectedStackEnd)),
                },
                Terminal::DupIf(ref _sub) if node_state.n_evaluated == 1 => {
                    self.stack.push(StackElement::Satisfied);
                }
                Terminal::ZeroNotEqual(ref sub) | Terminal::Verify(ref sub)
                    if node_state.n_evaluated == 0 =>
                {
                    self.push_evaluation_state(node_state.node, 1, 0);
                    self.push_evaluation_state(sub, 0, 0);
                }
                Terminal::Verify(ref _sub) if node_state.n_evaluated == 1 => {
                    match self.stack.pop() {
                        Some(StackElement::Satisfied) => (),
                        Some(_) => return Some(Err(Error::VerifyFailed)),
                        None => return Some(Err(Error::UnexpectedStackEnd)),
                    }
                }
                Terminal::ZeroNotEqual(ref _sub) if node_state.n_evaluated == 1 => {
                    match self.stack.pop() {
                        Some(StackElement::Dissatisfied) => {
                            self.stack.push(StackElement::Dissatisfied)
                        }
                        Some(_) => self.stack.push(StackElement::Satisfied),
                        None => return Some(Err(Error::UnexpectedStackEnd)),
                    }
                }
                Terminal::NonZero(ref sub) => {
                    debug_assert_eq!(node_state.n_evaluated, 0);
                    debug_assert_eq!(node_state.n_satisfied, 0);
                    match self.stack.last() {
                        Some(&StackElement::Dissatisfied) => (),
                        Some(_) => self.push_evaluation_state(sub, 0, 0),
                        None => return Some(Err(Error::UnexpectedStackEnd)),
                    }
                }
                Terminal::AndV(ref left, ref right) => {
                    debug_assert_eq!(node_state.n_evaluated, 0);
                    debug_assert_eq!(node_state.n_satisfied, 0);
                    self.push_evaluation_state(right, 0, 0);
                    self.push_evaluation_state(left, 0, 0);
                }
                Terminal::OrB(ref left, ref _right) | Terminal::AndB(ref left, ref _right)
                    if node_state.n_evaluated == 0 =>
                {
                    self.push_evaluation_state(node_state.node, 1, 0);
                    self.push_evaluation_state(left, 0, 0);
                }
                Terminal::OrB(ref _left, ref right) | Terminal::AndB(ref _left, ref right)
                    if node_state.n_evaluated == 1 =>
                {
                    match self.stack.pop() {
                        Some(StackElement::Dissatisfied) => {
                            self.push_evaluation_state(node_state.node, 2, 0);
                            self.push_evaluation_state(right, 0, 0);
                        }
                        Some(StackElement::Satisfied) => {
                            self.push_evaluation_state(node_state.node, 2, 1);
                            self.push_evaluation_state(right, 0, 0);
                        }
                        Some(StackElement::Push(_v)) => {
                            return Some(Err(Error::UnexpectedStackElementPush))
                        }
                        None => return Some(Err(Error::UnexpectedStackEnd)),
                    }
                }
                Terminal::AndB(ref _left, ref _right) if node_state.n_evaluated == 2 => {
                    match self.stack.pop() {
                        Some(StackElement::Satisfied) if node_state.n_satisfied == 1 => {
                            self.stack.push(StackElement::Satisfied)
                        }
                        Some(_) => self.stack.push(StackElement::Dissatisfied),
                        None => return Some(Err(Error::UnexpectedStackEnd)),
                    }
                }
                Terminal::AndOr(ref left, ref _right, _)
                | Terminal::OrC(ref left, ref _right)
                | Terminal::OrD(ref left, ref _right)
                    if node_state.n_evaluated == 0 =>
                {
                    self.push_evaluation_state(node_state.node, 1, 0);
                    self.push_evaluation_state(left, 0, 0);
                }
                Terminal::OrB(ref _left, ref _right) if node_state.n_evaluated == 2 => {
                    match self.stack.pop() {
                        Some(StackElement::Dissatisfied) if node_state.n_satisfied == 0 => {
                            self.stack.push(StackElement::Dissatisfied)
                        }
                        Some(_) => {
                            self.stack.push(StackElement::Satisfied);
                        }
                        None => return Some(Err(Error::UnexpectedStackEnd)),
                    }
                }
                Terminal::OrC(ref _left, ref right) if node_state.n_evaluated == 1 => {
                    match self.stack.pop() {
                        Some(StackElement::Satisfied) => (),
                        Some(StackElement::Dissatisfied) => self.push_evaluation_state(right, 0, 0),
                        Some(StackElement::Push(_v)) => {
                            return Some(Err(Error::UnexpectedStackElementPush))
                        }
                        None => return Some(Err(Error::UnexpectedStackEnd)),
                    }
                }
                Terminal::OrD(ref _left, ref right) if node_state.n_evaluated == 1 => {
                    match self.stack.pop() {
                        Some(StackElement::Satisfied) => self.stack.push(StackElement::Satisfied),
                        Some(StackElement::Dissatisfied) => self.push_evaluation_state(right, 0, 0),
                        Some(StackElement::Push(_v)) => {
                            return Some(Err(Error::UnexpectedStackElementPush))
                        }
                        None => return Some(Err(Error::UnexpectedStackEnd)),
                    }
                }
                Terminal::AndOr(_, ref left, ref right) | Terminal::OrI(ref left, ref right) => {
                    match self.stack.pop() {
                        Some(StackElement::Satisfied) => self.push_evaluation_state(left, 0, 0),
                        Some(StackElement::Dissatisfied) => self.push_evaluation_state(right, 0, 0),
                        Some(StackElement::Push(_v)) => {
                            return Some(Err(Error::UnexpectedStackElementPush))
                        }
                        None => return Some(Err(Error::UnexpectedStackEnd)),
                    }
                }
                Terminal::Thresh(ref _k, ref subs) if node_state.n_evaluated == 0 => {
                    self.push_evaluation_state(node_state.node, 1, 0);
                    self.push_evaluation_state(&subs[0], 0, 0);
                }
                Terminal::Thresh(k, ref subs) if node_state.n_evaluated == subs.len() => {
                    match self.stack.pop() {
                        Some(StackElement::Dissatisfied) if node_state.n_satisfied == k => {
                            self.stack.push(StackElement::Satisfied)
                        }
                        Some(StackElement::Satisfied) if node_state.n_satisfied == k - 1 => {
                            self.stack.push(StackElement::Satisfied)
                        }
                        Some(StackElement::Satisfied) | Some(StackElement::Dissatisfied) => {
                            self.stack.push(StackElement::Dissatisfied)
                        }
                        Some(StackElement::Push(_v)) => {
                            return Some(Err(Error::UnexpectedStackElementPush))
                        }
                        None => return Some(Err(Error::UnexpectedStackEnd)),
                    }
                }
                Terminal::Thresh(ref _k, ref subs) if node_state.n_evaluated != 0 => {
                    match self.stack.pop() {
                        Some(StackElement::Dissatisfied) => {
                            self.push_evaluation_state(
                                node_state.node,
                                node_state.n_evaluated + 1,
                                node_state.n_satisfied,
                            );
                            self.push_evaluation_state(&subs[node_state.n_evaluated], 0, 0);
                        }
                        Some(StackElement::Satisfied) => {
                            self.push_evaluation_state(
                                node_state.node,
                                node_state.n_evaluated + 1,
                                node_state.n_satisfied + 1,
                            );
                            self.push_evaluation_state(&subs[node_state.n_evaluated], 0, 0);
                        }
                        Some(StackElement::Push(_v)) => {
                            return Some(Err(Error::UnexpectedStackElementPush))
                        }
                        None => return Some(Err(Error::UnexpectedStackEnd)),
                    }
                }
                Terminal::Multi(ref k, ref subs) if node_state.n_evaluated == 0 => {
                    let len = self.stack.len();
                    if len < k + 1 {
                        return Some(Err(Error::InsufficientSignaturesMultiSig));
                    } else {
                        //Non-sat case. If the first sig is empty, others k elements must
                        //be empty.
                        match self.stack.last() {
                            Some(&StackElement::Dissatisfied) => {
                                //Remove the extra zero from multi-sig check
                                let sigs = self.stack.split_off(len - (k + 1));
                                let nonsat = sigs
                                    .iter()
                                    .map(|sig| *sig == StackElement::Dissatisfied)
                                    .filter(|empty| *empty)
                                    .count();
                                if nonsat == *k {
                                    self.stack.push(StackElement::Dissatisfied);
                                } else {
                                    return Some(Err(Error::MissingExtraZeroMultiSig));
                                }
                            }
                            None => return Some(Err(Error::UnexpectedStackEnd)),
                            _ => {
                                match self
                                    .stack
                                    .evaluate_multi(&mut self.verify_sig, &subs[subs.len() - 1])
                                {
                                    Some(Ok(x)) => {
                                        self.push_evaluation_state(
                                            node_state.node,
                                            node_state.n_evaluated + 1,
                                            node_state.n_satisfied + 1,
                                        );
                                        return Some(Ok(x));
                                    }
                                    None => self.push_evaluation_state(
                                        node_state.node,
                                        node_state.n_evaluated + 1,
                                        node_state.n_satisfied,
                                    ),
                                    x => return x, //forward errors as is
                                }
                            }
                        }
                    }
                }
                Terminal::Multi(k, ref subs) => {
                    if node_state.n_satisfied == k {
                        //multi-sig bug: Pop extra 0
                        if let Some(StackElement::Dissatisfied) = self.stack.pop() {
                            self.stack.push(StackElement::Satisfied);
                        } else {
                            return Some(Err(Error::MissingExtraZeroMultiSig));
                        }
                    } else if node_state.n_evaluated == subs.len() {
                        return Some(Err(Error::MultiSigEvaluationError));
                    } else {
                        match self.stack.evaluate_multi(
                            &mut self.verify_sig,
                            &subs[subs.len() - node_state.n_evaluated - 1],
                        ) {
                            Some(Ok(x)) => {
                                self.push_evaluation_state(
                                    node_state.node,
                                    node_state.n_evaluated + 1,
                                    node_state.n_satisfied + 1,
                                );
                                return Some(Ok(x));
                            }
                            None => self.push_evaluation_state(
                                node_state.node,
                                node_state.n_evaluated + 1,
                                node_state.n_satisfied,
                            ),
                            x => return x, //forward errors as is
                        }
                    }
                }
                //All other match patterns should not be reached in any valid
                //type checked Miniscript
                _ => return Some(Err(Error::CouldNotEvaluate)),
            };
        }

        //state empty implies that either the execution has terminated or we have a
        //Pk based descriptor
        if let Some(pk) = self.public_key {
            if let Some(StackElement::Push(sig)) = self.stack.pop() {
                if let Ok(sig) = verify_sersig(&mut self.verify_sig, &pk, &sig) {
                    //Signature check successful, set public_key to None to
                    //terminate the next() function in the subsequent call
                    self.public_key = None;
                    self.stack.push(StackElement::Satisfied);
                    return Some(Ok(SatisfiedConstraint::PublicKey { key: pk, sig }));
                } else {
                    return Some(Err(Error::PkEvaluationError(pk.clone().to_public_key())));
                }
            } else {
                return Some(Err(Error::UnexpectedStackEnd));
            }
        } else {
            //All the script has been executed.
            //Check that the stack must contain exactly 1 satisfied element
            if self.stack.pop() == Some(StackElement::Satisfied) && self.stack.is_empty() {
                return None;
            } else {
                return Some(Err(Error::ScriptSatisfactionError));
            }
        }
    }
}

/// Helper function to verify serialized signature
fn verify_sersig<'stack, F>(
    verify_sig: F,
    pk: &bitcoin::PublicKey,
    sigser: &[u8],
) -> Result<secp256k1::Signature, Error>
where
    F: FnOnce(&bitcoin::PublicKey, BitcoinSig) -> bool,
{
    if let Some((sighash_byte, sig)) = sigser.split_last() {
        let sighashtype = bitcoin::SigHashType::from_u32(*sighash_byte as u32);
        let sig = secp256k1::Signature::from_der(sig)?;
        if verify_sig(pk, (sig, sighashtype)) {
            Ok(sig)
        } else {
            Err(Error::InvalidSignature(*pk))
        }
    } else {
        Err(Error::PkEvaluationError(*pk))
    }
}

impl<'stack> Stack<'stack> {
    ///wrapper for self.0.is_empty()
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    ///wrapper for self.0.len()
    fn len(&mut self) -> usize {
        self.0.len()
    }

    ///wrapper for self.0.pop()
    fn pop(&mut self) -> Option<StackElement<'stack>> {
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
    fn evaluate_pk<'desc, F>(
        &mut self,
        verify_sig: F,
        pk: &'desc bitcoin::PublicKey,
    ) -> Option<Result<SatisfiedConstraint<'desc, 'stack>, Error>>
    where
        F: FnMut(&bitcoin::PublicKey, BitcoinSig) -> bool,
    {
        if let Some(sigser) = self.pop() {
            match sigser {
                StackElement::Dissatisfied => {
                    self.push(StackElement::Dissatisfied);
                    None
                }
                StackElement::Push(ref sigser) => {
                    let sig = verify_sersig(verify_sig, pk, sigser);
                    match sig {
                        Ok(sig) => {
                            self.push(StackElement::Satisfied);
                            Some(Ok(SatisfiedConstraint::PublicKey { key: pk, sig }))
                        }
                        Err(e) => return Some(Err(e)),
                    }
                }
                StackElement::Satisfied => {
                    return Some(Err(Error::PkEvaluationError(pk.clone().to_public_key())))
                }
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
    fn evaluate_pkh<'desc, F>(
        &mut self,
        verify_sig: F,
        pkh: &'desc hash160::Hash,
    ) -> Option<Result<SatisfiedConstraint<'desc, 'stack>, Error>>
    where
        F: FnOnce(&bitcoin::PublicKey, BitcoinSig) -> bool,
    {
        if let Some(StackElement::Push(pk)) = self.pop() {
            let pk_hash = hash160::Hash::hash(pk);
            if pk_hash != *pkh {
                return Some(Err(Error::PkHashVerifyFail(*pkh)));
            }
            match bitcoin::PublicKey::from_slice(pk) {
                Ok(pk) => {
                    if let Some(sigser) = self.pop() {
                        match sigser {
                            StackElement::Dissatisfied => {
                                self.push(StackElement::Dissatisfied);
                                None
                            }
                            StackElement::Push(sigser) => {
                                let sig = verify_sersig(verify_sig, &pk, sigser);
                                match sig {
                                    Ok(sig) => {
                                        self.push(StackElement::Satisfied);
                                        Some(Ok(SatisfiedConstraint::PublicKeyHash {
                                            keyhash: pkh,
                                            key: pk,
                                            sig,
                                        }))
                                    }
                                    Err(e) => return Some(Err(e)),
                                }
                            }
                            StackElement::Satisfied => {
                                return Some(Err(Error::PkEvaluationError(
                                    pk.clone().to_public_key(),
                                )))
                            }
                        }
                    } else {
                        Some(Err(Error::UnexpectedStackEnd))
                    }
                }
                Err(..) => Some(Err(Error::PubkeyParseError)),
            }
        } else {
            Some(Err(Error::UnexpectedStackEnd))
        }
    }

    /// Helper function to evaluate a After Node. Takes no argument from stack
    /// `n CHECKSEQUENCEVERIFY 0NOTEQUAL` and `n CHECKSEQUENCEVERIFY`
    /// Ideally this should return int value as n: build_scriptint(t as i64)),
    /// The reason we don't need to copy the Script semantics is that
    /// Miniscript never evaluates integers and it is safe to treat them as
    /// booleans
    fn evaluate_after<'desc>(
        &mut self,
        n: &'desc u32,
        age: u32,
    ) -> Option<Result<SatisfiedConstraint<'desc, 'stack>, Error>> {
        if age >= *n {
            self.push(StackElement::Satisfied);
            Some(Ok(SatisfiedConstraint::RelativeTimeLock { time: n }))
        } else {
            Some(Err(Error::AbsoluteLocktimeNotMet(*n)))
        }
    }

    /// Helper function to evaluate a Older Node. Takes no argument from stack
    /// `n CHECKLOCKTIMEVERIFY 0NOTEQUAL` and `n CHECKLOCKTIMEVERIFY`
    /// Ideally this should return int value as n: build_scriptint(t as i64)),
    /// The reason we don't need to copy the Script semantics is that
    /// Miniscript never evaluates integers and it is safe to treat them as
    /// booleans
    fn evaluate_older<'desc>(
        &mut self,
        n: &'desc u32,
        height: u32,
    ) -> Option<Result<SatisfiedConstraint<'desc, 'stack>, Error>> {
        if height >= *n {
            self.push(StackElement::Satisfied);
            Some(Ok(SatisfiedConstraint::AbsoluteTimeLock { time: n }))
        } else {
            Some(Err(Error::RelativeLocktimeNotMet(*n)))
        }
    }

    /// Helper function to evaluate a Sha256 Node.
    /// `SIZE 32 EQUALVERIFY SHA256 h EQUAL`
    fn evaluate_sha256<'desc>(
        &mut self,
        hash: &'desc sha256::Hash,
    ) -> Option<Result<SatisfiedConstraint<'desc, 'stack>, Error>> {
        if let Some(StackElement::Push(preimage)) = self.pop() {
            if preimage.len() != 32 {
                return Some(Err(Error::HashPreimageLengthMismatch));
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
    fn evaluate_hash256<'desc>(
        &mut self,
        hash: &'desc sha256d::Hash,
    ) -> Option<Result<SatisfiedConstraint<'desc, 'stack>, Error>> {
        if let Some(StackElement::Push(preimage)) = self.pop() {
            if preimage.len() != 32 {
                return Some(Err(Error::HashPreimageLengthMismatch));
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
    fn evaluate_hash160<'desc>(
        &mut self,
        hash: &'desc hash160::Hash,
    ) -> Option<Result<SatisfiedConstraint<'desc, 'stack>, Error>> {
        if let Some(StackElement::Push(preimage)) = self.pop() {
            if preimage.len() != 32 {
                return Some(Err(Error::HashPreimageLengthMismatch));
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
    fn evaluate_ripemd160<'desc>(
        &mut self,
        hash: &'desc ripemd160::Hash,
    ) -> Option<Result<SatisfiedConstraint<'desc, 'stack>, Error>> {
        if let Some(StackElement::Push(preimage)) = self.pop() {
            if preimage.len() != 32 {
                return Some(Err(Error::HashPreimageLengthMismatch));
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
    /// `multi(2,pk1,pk2)` would be satisfied by `[0 sig2 sig1]` and Err on
    /// `[0 sig2 sig1]`
    fn evaluate_multi<'desc, F>(
        &mut self,
        verify_sig: F,
        pk: &'desc bitcoin::PublicKey,
    ) -> Option<Result<SatisfiedConstraint<'desc, 'stack>, Error>>
    where
        F: FnOnce(&bitcoin::PublicKey, BitcoinSig) -> bool,
    {
        if let Some(witness_sig) = self.pop() {
            if let StackElement::Push(sigser) = witness_sig {
                let sig = verify_sersig(verify_sig, pk, sigser);
                match sig {
                    Ok(sig) => return Some(Ok(SatisfiedConstraint::PublicKey { key: pk, sig })),
                    Err(..) => {
                        self.push(witness_sig);
                        return None;
                    }
                }
            } else {
                Some(Err(Error::UnexpectedStackBoolean))
            }
        } else {
            Some(Err(Error::UnexpectedStackEnd))
        }
    }
}

#[cfg(test)]
mod tests {

    use bitcoin;
    use bitcoin::hashes::{hash160, ripemd160, sha256, sha256d, Hash};
    use bitcoin::secp256k1::{self, Secp256k1, VerifyOnly};
    use descriptor::satisfied_constraints::{
        Error, HashLockType, NodeEvaluationState, SatisfiedConstraint, SatisfiedConstraints, Stack,
        StackElement,
    };
    use miniscript::context::{Any, Legacy};
    use std::str::FromStr;
    use BitcoinSig;
    use Miniscript;
    use MiniscriptKey;
    use ToPublicKey;

    fn setup_keys_sigs(
        n: usize,
    ) -> (
        Vec<bitcoin::PublicKey>,
        Vec<Vec<u8>>,
        Vec<secp256k1::Signature>,
        secp256k1::Message,
        Secp256k1<VerifyOnly>,
    ) {
        let secp_sign = secp256k1::Secp256k1::signing_only();
        let secp_verify = secp256k1::Secp256k1::verification_only();
        let msg = secp256k1::Message::from_slice(&b"Yoda: btc, I trust. HODL I must!"[..])
            .expect("32 bytes");
        let mut pks = vec![];
        let mut secp_sigs = vec![];
        let mut der_sigs = vec![];
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
            secp_sigs.push(sig);
            let mut sigser = sig.serialize_der().to_vec();
            sigser.push(0x01); // sighash_all
            pks.push(pk);
            der_sigs.push(sigser);
        }
        (pks, der_sigs, secp_sigs, msg, secp_verify)
    }

    #[test]
    fn sat_constraints() {
        let (pks, der_sigs, secp_sigs, sighash, secp) = setup_keys_sigs(10);
        let vfyfn =
            |pk: &bitcoin::PublicKey, (sig, _)| secp.verify(&sighash, &sig, &pk.key).is_ok();

        fn from_stack<'stack, 'elem, F>(
            verify_fn: F,
            stack: Stack<'stack>,
            ms: &'elem Miniscript<bitcoin::PublicKey, Legacy>,
        ) -> SatisfiedConstraints<'elem, 'stack, F>
        where
            F: FnMut(&bitcoin::PublicKey, BitcoinSig) -> bool,
        {
            SatisfiedConstraints {
                verify_sig: verify_fn,
                stack: stack,
                public_key: None,
                state: vec![NodeEvaluationState {
                    node: Any::from_legacy(ms),
                    n_evaluated: 0,
                    n_satisfied: 0,
                }],
                age: 1002,
                height: 1002,
                has_errored: false,
            }
        };

        let pk = ms_str!("c:pk_k({})", pks[0]);
        let pkh = ms_str!("c:pk_h({})", pks[1].to_pubkeyhash());
        //Time
        let after = ms_str!("after({})", 1000);
        let older = ms_str!("older({})", 1000);
        //Hashes
        let preimage = vec![0xab as u8; 32];
        let sha256_hash = sha256::Hash::hash(&preimage);
        let sha256 = ms_str!("sha256({})", sha256_hash);
        let sha256d_hash_rev = sha256d::Hash::hash(&preimage);
        let mut sha256d_hash_bytes = sha256d_hash_rev.clone().into_inner();
        sha256d_hash_bytes.reverse();
        let sha256d_hash = sha256d::Hash::from_inner(sha256d_hash_bytes);
        let hash256 = ms_str!("hash256({})", sha256d_hash);
        let hash160_hash = hash160::Hash::hash(&preimage);
        let hash160 = ms_str!("hash160({})", hash160_hash);
        let ripemd160_hash = ripemd160::Hash::hash(&preimage);
        let ripemd160 = ms_str!("ripemd160({})", ripemd160_hash);

        let stack = Stack(vec![StackElement::Push(&der_sigs[0])]);
        let constraints = from_stack(&vfyfn, stack, &pk);
        let pk_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            pk_satisfied.unwrap(),
            vec![SatisfiedConstraint::PublicKey {
                key: &pks[0],
                sig: secp_sigs[0].clone(),
            }]
        );

        //Check Pk failure with wrong signature
        let stack = Stack(vec![StackElement::Dissatisfied]);
        let constraints = from_stack(&vfyfn, stack, &pk);
        let pk_err: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert!(pk_err.is_err());

        //Check Pkh
        let pk_bytes = pks[1].to_public_key().to_bytes();
        let stack = Stack(vec![
            StackElement::Push(&der_sigs[1]),
            StackElement::Push(&pk_bytes),
        ]);
        let constraints = from_stack(&vfyfn, stack, &pkh);
        let pkh_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            pkh_satisfied.unwrap(),
            vec![SatisfiedConstraint::PublicKeyHash {
                keyhash: &pks[1].to_pubkeyhash(),
                key: pks[1].clone(),
                sig: secp_sigs[1].clone(),
            }]
        );

        //Check After
        let stack = Stack(vec![]);
        let constraints = from_stack(&vfyfn, stack, &after);
        let after_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            after_satisfied.unwrap(),
            vec![SatisfiedConstraint::RelativeTimeLock { time: &1000 }]
        );

        //Check Older
        let stack = Stack(vec![]);
        let constraints = from_stack(&vfyfn, stack, &older);
        let older_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            older_satisfied.unwrap(),
            vec![SatisfiedConstraint::AbsoluteTimeLock { time: &1000 }]
        );

        //Check Sha256
        let stack = Stack(vec![StackElement::Push(&preimage)]);
        let constraints = from_stack(&vfyfn, stack, &sha256);
        let sah256_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            sah256_satisfied.unwrap(),
            vec![SatisfiedConstraint::HashLock {
                hash: HashLockType::Sha256(&sha256_hash),
                preimage: &preimage,
            }]
        );

        //Check Shad256
        let stack = Stack(vec![StackElement::Push(&preimage)]);
        let constraints = from_stack(&vfyfn, stack, &hash256);
        let sha256d_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            sha256d_satisfied.unwrap(),
            vec![SatisfiedConstraint::HashLock {
                hash: HashLockType::Hash256(&sha256d_hash_rev),
                preimage: &preimage,
            }]
        );

        //Check hash160
        let stack = Stack(vec![StackElement::Push(&preimage)]);
        let constraints = from_stack(&vfyfn, stack, &hash160);
        let hash160_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            hash160_satisfied.unwrap(),
            vec![SatisfiedConstraint::HashLock {
                hash: HashLockType::Hash160(&hash160_hash),
                preimage: &preimage,
            }]
        );

        //Check ripemd160
        let stack = Stack(vec![StackElement::Push(&preimage)]);
        let constraints = from_stack(&vfyfn, stack, &ripemd160);
        let ripemd160_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            ripemd160_satisfied.unwrap(),
            vec![SatisfiedConstraint::HashLock {
                hash: HashLockType::Ripemd160(&ripemd160_hash),
                preimage: &preimage
            }]
        );

        //Check AndV
        let pk_bytes = pks[1].to_public_key().to_bytes();
        let stack = Stack(vec![
            StackElement::Push(&der_sigs[1]),
            StackElement::Push(&pk_bytes),
            StackElement::Push(&der_sigs[0]),
        ]);
        let elem = ms_str!(
            "and_v(vc:pk_k({}),c:pk_h({}))",
            pks[0],
            pks[1].to_pubkeyhash()
        );
        let constraints = from_stack(&vfyfn, stack, &elem);

        let and_v_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            and_v_satisfied.unwrap(),
            vec![
                SatisfiedConstraint::PublicKey {
                    key: &pks[0],
                    sig: secp_sigs[0].clone(),
                },
                SatisfiedConstraint::PublicKeyHash {
                    keyhash: &pks[1].to_pubkeyhash(),
                    key: pks[1].clone(),
                    sig: secp_sigs[1].clone(),
                }
            ]
        );

        //Check AndB
        let stack = Stack(vec![
            StackElement::Push(&preimage),
            StackElement::Push(&der_sigs[0]),
        ]);
        let elem = ms_str!("and_b(c:pk_k({}),sjtv:sha256({}))", pks[0], sha256_hash);
        let constraints = from_stack(&vfyfn, stack, &elem);

        let and_b_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            and_b_satisfied.unwrap(),
            vec![
                SatisfiedConstraint::PublicKey {
                    key: &pks[0],
                    sig: secp_sigs[0].clone(),
                },
                SatisfiedConstraint::HashLock {
                    hash: HashLockType::Sha256(&sha256_hash),
                    preimage: &preimage,
                }
            ]
        );

        //Check AndOr
        let stack = Stack(vec![
            StackElement::Push(&preimage),
            StackElement::Push(&der_sigs[0]),
        ]);
        let elem = ms_str!(
            "andor(c:pk_k({}),jtv:sha256({}),c:pk_h({}))",
            pks[0],
            sha256_hash,
            pks[1].to_pubkeyhash(),
        );
        let constraints = from_stack(&vfyfn, stack, &elem);

        let and_or_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            and_or_satisfied.unwrap(),
            vec![
                SatisfiedConstraint::PublicKey {
                    key: &pks[0],
                    sig: secp_sigs[0].clone(),
                },
                SatisfiedConstraint::HashLock {
                    hash: HashLockType::Sha256(&sha256_hash),
                    preimage: &preimage,
                }
            ]
        );

        //AndOr second satisfaction path
        let pk_bytes = pks[1].to_public_key().to_bytes();
        let stack = Stack(vec![
            StackElement::Push(&der_sigs[1]),
            StackElement::Push(&pk_bytes),
            StackElement::Dissatisfied,
        ]);
        let constraints = from_stack(&vfyfn, stack, &elem);

        let and_or_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            and_or_satisfied.unwrap(),
            vec![SatisfiedConstraint::PublicKeyHash {
                keyhash: &pks[1].to_pubkeyhash(),
                key: pks[1].clone(),
                sig: secp_sigs[1].clone(),
            }]
        );

        //Check OrB
        let stack = Stack(vec![
            StackElement::Push(&preimage),
            StackElement::Dissatisfied,
        ]);
        let elem = ms_str!("or_b(c:pk_k({}),sjtv:sha256({}))", pks[0], sha256_hash);
        let constraints = from_stack(&vfyfn, stack, &elem);

        let or_b_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            or_b_satisfied.unwrap(),
            vec![SatisfiedConstraint::HashLock {
                hash: HashLockType::Sha256(&sha256_hash),
                preimage: &preimage,
            }]
        );

        //Check OrD
        let stack = Stack(vec![StackElement::Push(&der_sigs[0])]);
        let elem = ms_str!("or_d(c:pk_k({}),jtv:sha256({}))", pks[0], sha256_hash);
        let constraints = from_stack(&vfyfn, stack, &elem);

        let or_d_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            or_d_satisfied.unwrap(),
            vec![SatisfiedConstraint::PublicKey {
                key: &pks[0],
                sig: secp_sigs[0].clone(),
            }]
        );

        //Check OrC
        let stack = Stack(vec![
            StackElement::Push(&der_sigs[0]),
            StackElement::Dissatisfied,
        ]);
        let elem = ms_str!("t:or_c(jtv:sha256({}),vc:pk_k({}))", sha256_hash, pks[0]);
        let constraints = from_stack(&vfyfn, stack, &elem);

        let or_c_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            or_c_satisfied.unwrap(),
            vec![SatisfiedConstraint::PublicKey {
                key: &pks[0],
                sig: secp_sigs[0].clone(),
            }]
        );

        //Check OrI
        let stack = Stack(vec![
            StackElement::Push(&der_sigs[0]),
            StackElement::Dissatisfied,
        ]);
        let elem = ms_str!("or_i(jtv:sha256({}),c:pk_k({}))", sha256_hash, pks[0]);
        let constraints = from_stack(&vfyfn, stack, &elem);

        let or_i_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            or_i_satisfied.unwrap(),
            vec![SatisfiedConstraint::PublicKey {
                key: &pks[0],
                sig: secp_sigs[0].clone(),
            }]
        );

        //Check Thres
        let stack = Stack(vec![
            StackElement::Push(&der_sigs[0]),
            StackElement::Push(&der_sigs[1]),
            StackElement::Push(&der_sigs[2]),
            StackElement::Dissatisfied,
            StackElement::Dissatisfied,
        ]);
        let elem = ms_str!(
            "thresh(3,c:pk_k({}),sc:pk_k({}),sc:pk_k({}),sc:pk_k({}),sc:pk_k({}))",
            pks[4],
            pks[3],
            pks[2],
            pks[1],
            pks[0],
        );
        let constraints = from_stack(&vfyfn, stack, &elem);

        let thresh_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            thresh_satisfied.unwrap(),
            vec![
                SatisfiedConstraint::PublicKey {
                    key: &pks[2],
                    sig: secp_sigs[2].clone(),
                },
                SatisfiedConstraint::PublicKey {
                    key: &pks[1],
                    sig: secp_sigs[1].clone(),
                },
                SatisfiedConstraint::PublicKey {
                    key: &pks[0],
                    sig: secp_sigs[0].clone(),
                }
            ]
        );

        //Check ThresM
        let stack = Stack(vec![
            StackElement::Dissatisfied,
            StackElement::Push(&der_sigs[2]),
            StackElement::Push(&der_sigs[1]),
            StackElement::Push(&der_sigs[0]),
        ]);
        let elem = ms_str!(
            "multi(3,{},{},{},{},{})",
            pks[4],
            pks[3],
            pks[2],
            pks[1],
            pks[0],
        );
        let constraints = from_stack(&vfyfn, stack, &elem);

        let multi_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            multi_satisfied.unwrap(),
            vec![
                SatisfiedConstraint::PublicKey {
                    key: &pks[0],
                    sig: secp_sigs[0].clone(),
                },
                SatisfiedConstraint::PublicKey {
                    key: &pks[1],
                    sig: secp_sigs[1].clone(),
                },
                SatisfiedConstraint::PublicKey {
                    key: &pks[2],
                    sig: secp_sigs[2].clone(),
                },
            ]
        );

        //Error ThresM: Invalid order of sigs
        let stack = Stack(vec![
            StackElement::Dissatisfied,
            StackElement::Push(&der_sigs[0]),
            StackElement::Push(&der_sigs[2]),
            StackElement::Push(&der_sigs[1]),
        ]);
        let elem = ms_str!(
            "multi(3,{},{},{},{},{})",
            pks[4],
            pks[3],
            pks[2],
            pks[1],
            pks[0],
        );
        let constraints = from_stack(&vfyfn, stack, &elem);

        let multi_error: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert!(multi_error.is_err());
    }
}
