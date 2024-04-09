// Written in 2019 by Sanket Kanjular and Andrew Poelstra
// SPDX-License-Identifier: CC0-1.0

//! Interpreter
//!
//! Provides a Miniscript-based script interpreter which can be used to
//! iterate over the set of conditions satisfied by a spending transaction,
//! assuming that the spent coin was descriptor controlled.
//!

use core::fmt;
use core::str::FromStr;

use bitcoin::hashes::{hash160, ripemd160, sha256, Hash};
use bitcoin::{absolute, relative, secp256k1, sighash, taproot, Sequence, TxOut, Witness};

use crate::miniscript::context::{NoChecks, SigType};
use crate::miniscript::ScriptContext;
use crate::prelude::*;
use crate::{hash256, Descriptor, Miniscript, Terminal, ToPublicKey};

mod error;
mod inner;
mod stack;

pub use self::error::Error;
use self::error::PkEvalErrInner;
use self::stack::Stack;
use crate::MiniscriptKey;

/// An iterable Miniscript-structured representation of the spending of a coin
pub struct Interpreter<'txin> {
    inner: inner::Inner,
    stack: Stack<'txin>,
    /// For non-Taproot spends, the scriptCode; for Taproot script-spends, this
    /// is the leaf script; for key-spends it is `None`.
    script_code: Option<bitcoin::ScriptBuf>,
    sequence: Sequence,
    lock_time: absolute::LockTime,
}

// A type representing functions for checking signatures that accept both
// Ecdsa and Schnorr signatures

/// A type for representing signatures supported as of bitcoin core 22.0
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeySigPair {
    /// A Full public key and corresponding Ecdsa signature
    Ecdsa(bitcoin::PublicKey, bitcoin::ecdsa::Signature),
    /// A x-only key and corresponding Schnorr signature
    Schnorr(bitcoin::key::XOnlyPublicKey, bitcoin::taproot::Signature),
}

impl KeySigPair {
    /// Obtain a pair of ([`bitcoin::PublicKey`], [`bitcoin::ecdsa::Signature`]) from [`KeySigPair`]
    pub fn as_ecdsa(&self) -> Option<(bitcoin::PublicKey, bitcoin::ecdsa::Signature)> {
        match self {
            KeySigPair::Ecdsa(pk, sig) => Some((*pk, *sig)),
            KeySigPair::Schnorr(_, _) => None,
        }
    }

    /// Obtain a pair of ([`bitcoin::secp256k1::XOnlyPublicKey`], [`bitcoin::taproot::Signature`]) from [`KeySigPair`]
    pub fn as_schnorr(
        &self,
    ) -> Option<(bitcoin::key::XOnlyPublicKey, bitcoin::taproot::Signature)> {
        match self {
            KeySigPair::Ecdsa(_, _) => None,
            KeySigPair::Schnorr(pk, sig) => Some((*pk, *sig)),
        }
    }
}

// Internally used enum for different types of bitcoin keys
// Even though we implement MiniscriptKey for BitcoinKey, we make sure that there
// are little mis-use
// - The only constructors for this are only called in from_txdata that take care
//   using the correct enum variant
// - This does not implement ToPublicKey to avoid context dependant encoding/decoding of 33/32
//   byte keys. This allows us to keep a single NoChecks context instead of a context for
//   for NoChecksSchnorr/NoChecksEcdsa.
// Long term TODO: There really should be not be any need for Miniscript<Pk: MiniscriptKey> struct
// to have the Pk: MiniscriptKey bound. The bound should be on all of it's methods. That would
// require changing Miniscript struct to three generics Miniscript<Pk, Pkh, Ctx> and bound on
// all of the methods of Miniscript to ensure that Pkh = Pk::Hash
#[derive(Hash, Eq, Ord, PartialEq, PartialOrd, Clone, Copy, Debug)]
enum BitcoinKey {
    // Full key
    Fullkey(bitcoin::PublicKey),
    // Xonly key
    XOnlyPublicKey(bitcoin::key::XOnlyPublicKey),
}

impl BitcoinKey {
    fn to_pubkeyhash(self, sig_type: SigType) -> hash160::Hash {
        match self {
            BitcoinKey::Fullkey(pk) => pk.to_pubkeyhash(sig_type),
            BitcoinKey::XOnlyPublicKey(pk) => pk.to_pubkeyhash(sig_type),
        }
    }
}

// Displayed in full 33 byte representation. X-only keys are displayed with 0x02 prefix
impl fmt::Display for BitcoinKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BitcoinKey::Fullkey(pk) => pk.to_public_key().fmt(f),
            BitcoinKey::XOnlyPublicKey(pk) => pk.to_public_key().fmt(f),
        }
    }
}

impl From<bitcoin::PublicKey> for BitcoinKey {
    fn from(pk: bitcoin::PublicKey) -> Self { BitcoinKey::Fullkey(pk) }
}

impl From<bitcoin::key::XOnlyPublicKey> for BitcoinKey {
    fn from(xpk: bitcoin::key::XOnlyPublicKey) -> Self { BitcoinKey::XOnlyPublicKey(xpk) }
}

impl MiniscriptKey for BitcoinKey {
    type Sha256 = sha256::Hash;
    type Hash256 = hash256::Hash;
    type Ripemd160 = ripemd160::Hash;
    type Hash160 = hash160::Hash;

    fn is_uncompressed(&self) -> bool {
        match *self {
            BitcoinKey::Fullkey(pk) => !pk.compressed,
            BitcoinKey::XOnlyPublicKey(_) => false,
        }
    }
}

impl<'txin> Interpreter<'txin> {
    /// Constructs an interpreter from the data of a spending transaction
    ///
    /// Accepts a signature-validating function. If you are willing to trust
    /// that ECSDA signatures are valid, this can be set to the constant true
    /// function; otherwise, it should be a closure containing a sighash and
    /// secp context, which can actually verify a given signature.
    pub fn from_txdata(
        spk: &bitcoin::ScriptBuf,
        script_sig: &'txin bitcoin::Script,
        witness: &'txin Witness,
        sequence: Sequence,            // CSV, relative lock time.
        lock_time: absolute::LockTime, // CLTV, absolute lock time.
    ) -> Result<Self, Error> {
        let (inner, stack, script_code) = inner::from_txdata(spk, script_sig, witness)?;
        Ok(Interpreter { inner, stack, script_code, sequence, lock_time })
    }

    /// Same as [`Interpreter::iter`], but allows for a custom verification function.
    /// See [Self::iter_assume_sigs] for a simpler API without information about Prevouts
    /// but skips the signature verification
    pub fn iter_custom<'iter>(
        &'iter self,
        verify_sig: Box<dyn FnMut(&KeySigPair) -> bool + 'iter>,
    ) -> Iter<'txin, 'iter> {
        Iter {
            verify_sig,
            public_key: if let inner::Inner::PublicKey(ref pk, _) = self.inner {
                Some(pk)
            } else {
                None
            },
            state: if let inner::Inner::Script(ref script, _) = self.inner {
                vec![NodeEvaluationState { node: script, n_evaluated: 0, n_satisfied: 0 }]
            } else {
                vec![]
            },
            // Cloning the references to elements of stack should be fine as it allows
            // call interpreter.iter() without mutating interpreter
            stack: self.stack.clone(),
            sequence: self.sequence,
            lock_time: self.lock_time,
            has_errored: false,
            sig_type: self.sig_type(),
        }
    }

    /// Verify a signature for a given transaction and prevout information
    /// This is a low level API, [`Interpreter::iter`] or [`Interpreter::iter_assume_sigs`]
    /// should satisfy most use-cases.
    /// Returns false if
    /// - the signature verification fails
    /// - the input index is out of range
    /// - Insufficient sighash information is present
    /// - sighash single without corresponding output
    // TODO: Create a good first isse to change this to error
    // TODO: Requires refactor to remove the script_code logic in order to use the new sighash API.
    #[allow(deprecated)] // For segwit_signature_hash
    pub fn verify_sig<C: secp256k1::Verification, T: Borrow<TxOut>>(
        &self,
        secp: &secp256k1::Secp256k1<C>,
        tx: &bitcoin::Transaction,
        input_idx: usize,
        prevouts: &sighash::Prevouts<T>,
        sig: &KeySigPair,
    ) -> bool {
        fn get_prevout<'u, T: Borrow<TxOut>>(
            prevouts: &'u sighash::Prevouts<'u, T>,
            input_index: usize,
        ) -> Option<&'u T> {
            match prevouts {
                sighash::Prevouts::One(index, prevout) => {
                    if input_index == *index {
                        Some(prevout)
                    } else {
                        None
                    }
                }
                sighash::Prevouts::All(prevouts) => prevouts.get(input_index),
            }
        }
        let mut cache = bitcoin::sighash::SighashCache::new(tx);
        match sig {
            KeySigPair::Ecdsa(key, ecdsa_sig) => {
                let script_pubkey = self.script_code.as_ref().expect("Legacy have script code");
                let msg = if self.is_legacy() {
                    let sighash_u32 = ecdsa_sig.sighash_type.to_u32();
                    let sighash =
                        cache.legacy_signature_hash(input_idx, script_pubkey, sighash_u32);
                    sighash.map(|hash| secp256k1::Message::from_digest(hash.to_byte_array()))
                } else if self.is_segwit_v0() {
                    let amt = match get_prevout(prevouts, input_idx) {
                        Some(txout) => txout.borrow().value,
                        None => return false,
                    };
                    // TODO: Don't manually handle the script code.
                    let sighash = cache.p2wsh_signature_hash(
                        input_idx,
                        script_pubkey,
                        amt,
                        ecdsa_sig.sighash_type,
                    );
                    sighash.map(|hash| secp256k1::Message::from_digest(hash.to_byte_array()))
                } else {
                    // taproot(or future) signatures in segwitv0 context
                    return false;
                };

                let success = msg.map(|msg| {
                    secp.verify_ecdsa(&msg, &ecdsa_sig.signature, &key.inner)
                        .is_ok()
                });
                success.unwrap_or(false) // unwrap_or checks for errors, while success would have checksig results
            }
            KeySigPair::Schnorr(xpk, schnorr_sig) => {
                let sighash_msg = if self.is_taproot_v1_key_spend() {
                    cache.taproot_key_spend_signature_hash(
                        input_idx,
                        prevouts,
                        schnorr_sig.sighash_type,
                    )
                } else if self.is_taproot_v1_script_spend() {
                    let tap_script = self.script_code.as_ref().expect(
                        "Internal Hack: Saving leaf script instead\
                        of script code for script spend",
                    );
                    let leaf_hash = taproot::TapLeafHash::from_script(
                        tap_script,
                        taproot::LeafVersion::TapScript,
                    );
                    cache.taproot_script_spend_signature_hash(
                        input_idx,
                        prevouts,
                        leaf_hash,
                        schnorr_sig.sighash_type,
                    )
                } else {
                    // schnorr sigs in ecdsa descriptors
                    return false;
                };
                let msg =
                    sighash_msg.map(|hash| secp256k1::Message::from_digest(hash.to_byte_array()));
                let success = msg.map(|msg| {
                    secp.verify_schnorr(&schnorr_sig.signature, &msg, xpk)
                        .is_ok()
                });
                success.unwrap_or(false) // unwrap_or_default checks for errors, while success would have checksig results
            }
        }
    }

    /// Creates an iterator over the satisfied spending conditions
    ///
    /// Returns all satisfied constraints, even if they were redundant (i.e. did
    /// not contribute to the script being satisfied). For example, if a signature
    /// were provided for an `and_b(Pk,false)` fragment, that signature will be
    /// returned, even though the entire and_b must have failed and must not have
    /// been used.
    ///
    /// In case the script is actually dissatisfied, this may return several values
    /// before ultimately returning an error.
    ///
    /// Not all fields are used by legacy/segwitv0 descriptors; if you are sure this is a legacy
    /// spend (you can check with the `is_legacy\is_segwitv0` method) you can provide dummy data for
    /// the amount/prevouts.
    /// - For legacy outputs, no information about prevouts is required
    /// - For segwitv0 outputs, prevout at corresponding index with correct amount must be provided
    /// - For taproot outputs, information about all prevouts must be supplied
    pub fn iter<'iter, C: secp256k1::Verification, T: Borrow<TxOut>>(
        &'iter self,
        secp: &'iter secp256k1::Secp256k1<C>,
        tx: &'txin bitcoin::Transaction,
        input_idx: usize,
        prevouts: &'iter sighash::Prevouts<T>, // actually a 'prevouts, but 'prevouts: 'iter
    ) -> Iter<'txin, 'iter> {
        self.iter_custom(Box::new(move |sig| self.verify_sig(secp, tx, input_idx, prevouts, sig)))
    }

    /// Creates an iterator over the satisfied spending conditions without checking signatures
    pub fn iter_assume_sigs<'iter>(&'iter self) -> Iter<'txin, 'iter> {
        self.iter_custom(Box::new(|_| true))
    }

    /// Outputs a "descriptor" string which reproduces the spent coins
    ///
    /// This may not represent the original descriptor used to produce the transaction,
    /// since it cannot distinguish between sorted and unsorted multisigs (and anyway
    /// it can only see the final keys, keyorigin info is lost in serializing to Bitcoin).
    ///
    /// If you are using the interpreter as a sanity check on a transaction,
    /// it is worthwhile to try to parse this as a descriptor using `from_str`
    /// which will check standardness and consensus limits, which the interpreter
    /// does not do on its own. Or use the `inferred_descriptor` method which
    /// does this for you.
    pub fn inferred_descriptor_string(&self) -> String {
        match self.inner {
            inner::Inner::PublicKey(ref pk, inner::PubkeyType::Pk) => format!("pk({})", pk),
            inner::Inner::PublicKey(ref pk, inner::PubkeyType::Pkh) => format!("pkh({})", pk),
            inner::Inner::PublicKey(ref pk, inner::PubkeyType::Wpkh) => format!("wpkh({})", pk),
            inner::Inner::PublicKey(ref pk, inner::PubkeyType::ShWpkh) => {
                format!("sh(wpkh({}))", pk)
            }
            inner::Inner::PublicKey(ref pk, inner::PubkeyType::Tr) => {
                // In tr descriptors, normally the internal key is represented inside the tr part
                // But there is no way to infer the internal key from output descriptor status
                // instead we infer a rawtr.
                // Note that rawtr is parsing is currently not supported.
                format!("rawtr_not_supported_yet({})", pk)
            }
            inner::Inner::Script(ref ms, inner::ScriptType::Bare) => format!("{}", ms),
            inner::Inner::Script(ref ms, inner::ScriptType::Sh) => format!("sh({})", ms),
            inner::Inner::Script(ref ms, inner::ScriptType::Wsh) => format!("wsh({})", ms),
            inner::Inner::Script(ref ms, inner::ScriptType::ShWsh) => format!("sh(wsh({}))", ms),
            inner::Inner::Script(ref ms, inner::ScriptType::Tr) => {
                // Hidden paths are still under discussion, once the spec is finalized, we can support
                // rawnode and raw leaf.
                format!("tr(hidden_paths_not_yet_supported,{})", ms)
            }
        }
    }

    /// Whether this is a pre-segwit spend
    pub fn is_legacy(&self) -> bool {
        match self.inner {
            inner::Inner::PublicKey(_, inner::PubkeyType::Pk) => true,
            inner::Inner::PublicKey(_, inner::PubkeyType::Pkh) => true,
            inner::Inner::PublicKey(_, inner::PubkeyType::Wpkh) => false,
            inner::Inner::PublicKey(_, inner::PubkeyType::ShWpkh) => false, // lol "sorta"
            inner::Inner::PublicKey(_, inner::PubkeyType::Tr) => false,     // lol "sorta"
            inner::Inner::Script(_, inner::ScriptType::Bare) => true,
            inner::Inner::Script(_, inner::ScriptType::Sh) => true,
            inner::Inner::Script(_, inner::ScriptType::Wsh) => false,
            inner::Inner::Script(_, inner::ScriptType::ShWsh) => false, // lol "sorta"
            inner::Inner::Script(_, inner::ScriptType::Tr) => false,
        }
    }

    /// Whether this is a segwit v0 spend (wrapped or native)
    pub fn is_segwit_v0(&self) -> bool {
        match self.inner {
            inner::Inner::PublicKey(_, inner::PubkeyType::Pk) => false,
            inner::Inner::PublicKey(_, inner::PubkeyType::Pkh) => false,
            inner::Inner::PublicKey(_, inner::PubkeyType::Wpkh) => true,
            inner::Inner::PublicKey(_, inner::PubkeyType::ShWpkh) => true, // lol "sorta"
            inner::Inner::PublicKey(_, inner::PubkeyType::Tr) => false,
            inner::Inner::Script(_, inner::ScriptType::Bare) => false,
            inner::Inner::Script(_, inner::ScriptType::Sh) => false,
            inner::Inner::Script(_, inner::ScriptType::Wsh) => true,
            inner::Inner::Script(_, inner::ScriptType::ShWsh) => true, // lol "sorta"
            inner::Inner::Script(_, inner::ScriptType::Tr) => false,
        }
    }

    /// Whether this is a taproot key spend
    pub fn is_taproot_v1_key_spend(&self) -> bool {
        match self.inner {
            inner::Inner::PublicKey(_, inner::PubkeyType::Pk) => false,
            inner::Inner::PublicKey(_, inner::PubkeyType::Pkh) => false,
            inner::Inner::PublicKey(_, inner::PubkeyType::Wpkh) => false,
            inner::Inner::PublicKey(_, inner::PubkeyType::ShWpkh) => false,
            inner::Inner::PublicKey(_, inner::PubkeyType::Tr) => true,
            inner::Inner::Script(_, inner::ScriptType::Bare) => false,
            inner::Inner::Script(_, inner::ScriptType::Sh) => false,
            inner::Inner::Script(_, inner::ScriptType::Wsh) => false,
            inner::Inner::Script(_, inner::ScriptType::ShWsh) => false,
            inner::Inner::Script(_, inner::ScriptType::Tr) => false,
        }
    }

    /// Whether this is a taproot script spend
    pub fn is_taproot_v1_script_spend(&self) -> bool {
        match self.inner {
            inner::Inner::PublicKey(_, inner::PubkeyType::Pk) => false,
            inner::Inner::PublicKey(_, inner::PubkeyType::Pkh) => false,
            inner::Inner::PublicKey(_, inner::PubkeyType::Wpkh) => false,
            inner::Inner::PublicKey(_, inner::PubkeyType::ShWpkh) => false,
            inner::Inner::PublicKey(_, inner::PubkeyType::Tr) => false,
            inner::Inner::Script(_, inner::ScriptType::Bare) => false,
            inner::Inner::Script(_, inner::ScriptType::Sh) => false,
            inner::Inner::Script(_, inner::ScriptType::Wsh) => false,
            inner::Inner::Script(_, inner::ScriptType::ShWsh) => false,
            inner::Inner::Script(_, inner::ScriptType::Tr) => true,
        }
    }

    /// Signature type of the spend
    pub fn sig_type(&self) -> SigType {
        match self.inner {
            inner::Inner::PublicKey(_, inner::PubkeyType::Tr) => SigType::Schnorr,
            inner::Inner::Script(_, inner::ScriptType::Tr) => SigType::Schnorr,
            inner::Inner::PublicKey(_, inner::PubkeyType::Pk)
            | inner::Inner::PublicKey(_, inner::PubkeyType::Pkh)
            | inner::Inner::PublicKey(_, inner::PubkeyType::Wpkh)
            | inner::Inner::PublicKey(_, inner::PubkeyType::ShWpkh)
            | inner::Inner::Script(_, inner::ScriptType::Bare)
            | inner::Inner::Script(_, inner::ScriptType::Sh)
            | inner::Inner::Script(_, inner::ScriptType::Wsh)
            | inner::Inner::Script(_, inner::ScriptType::ShWsh) => SigType::Ecdsa,
        }
    }

    /// Outputs a "descriptor" which reproduces the spent coins
    ///
    /// This may not represent the original descriptor used to produce the transaction,
    /// since it cannot distinguish between sorted and unsorted multisigs (and anyway
    /// it can only see the final keys, keyorigin info is lost in serializing to Bitcoin).
    /// x-only keys are translated to [`bitcoin::PublicKey`] with 0x02 prefix.
    pub fn inferred_descriptor(&self) -> Result<Descriptor<bitcoin::PublicKey>, crate::Error> {
        Descriptor::from_str(&self.inferred_descriptor_string())
    }
}

/// Type of HashLock used for SatisfiedConstraint structure
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum HashLockType {
    ///SHA 256 hashlock
    Sha256(sha256::Hash),
    ///Hash 256 hashlock
    Hash256(hash256::Hash),
    ///Hash160 hashlock
    Hash160(hash160::Hash),
    ///Ripemd160 hashlock
    Ripemd160(ripemd160::Hash),
}

/// A satisfied Miniscript condition (Signature, Hashlock, Timelock)
/// 'intp represents the lifetime of descriptor and `stack represents
/// the lifetime of witness
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum SatisfiedConstraint {
    ///Public key and corresponding signature
    PublicKey {
        /// KeySig pair
        key_sig: KeySigPair,
    },
    ///PublicKeyHash, corresponding pubkey and signature
    PublicKeyHash {
        /// The pubkey hash
        keyhash: hash160::Hash,
        /// public key and signature
        key_sig: KeySigPair,
    },
    ///Hashlock and preimage for SHA256
    HashLock {
        /// The type of Hashlock
        hash: HashLockType,
        /// The preimage used for satisfaction
        preimage: [u8; 32],
    },
    ///Relative Timelock for CSV.
    RelativeTimelock {
        /// The value of RelativeTimelock
        n: relative::LockTime,
    },
    ///Absolute Timelock for CLTV.
    AbsoluteTimelock {
        /// The value of Absolute timelock
        n: absolute::LockTime,
    },
}

///This is used by the interpreter to know which evaluation state a AstemElem is.
///This is required because whenever a same node(for eg. OrB) appears on the stack, we don't
///know if the left child has been evaluated or not. And based on the result on
///the top of the stack, we need to decide whether to execute right child or not.
///This is also useful for wrappers and thresholds which push a value on the stack
///depending on evaluation of the children.
struct NodeEvaluationState<'intp> {
    ///The node which is being evaluated
    node: &'intp Miniscript<BitcoinKey, NoChecks>,
    ///number of children evaluated
    n_evaluated: usize,
    ///number of children satisfied
    n_satisfied: usize,
}

/// Iterator over all the constraints satisfied by a completed scriptPubKey
/// and witness stack
///
/// Returns all satisfied constraints, even if they were redundant (i.e. did
/// not contribute to the script being satisfied). For example, if a signature
/// were provided for an `and_b(Pk,false)` fragment, that signature will be
/// returned, even though the entire and_b must have failed and must not have
/// been used.
///
/// In case the script is actually dissatisfied, this may return several values
/// before ultimately returning an error.
pub struct Iter<'intp, 'txin: 'intp> {
    verify_sig: Box<dyn FnMut(&KeySigPair) -> bool + 'intp>,
    public_key: Option<&'intp BitcoinKey>,
    state: Vec<NodeEvaluationState<'intp>>,
    stack: Stack<'txin>,
    sequence: Sequence,
    lock_time: absolute::LockTime,
    has_errored: bool,
    sig_type: SigType,
}

///Iterator for Iter
impl<'intp, 'txin: 'intp> Iterator for Iter<'intp, 'txin>
where
    NoChecks: ScriptContext,
{
    type Item = Result<SatisfiedConstraint, Error>;

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

impl<'intp, 'txin: 'intp> Iter<'intp, 'txin>
where
    NoChecks: ScriptContext,
{
    /// Helper function to push a NodeEvaluationState on state stack
    fn push_evaluation_state(
        &mut self,
        node: &'intp Miniscript<BitcoinKey, NoChecks>,
        n_evaluated: usize,
        n_satisfied: usize,
    ) {
        self.state
            .push(NodeEvaluationState { node, n_evaluated, n_satisfied })
    }

    /// Helper function to step the iterator
    fn iter_next(&mut self) -> Option<Result<SatisfiedConstraint, Error>> {
        while let Some(node_state) = self.state.pop() {
            //non-empty stack
            match node_state.node.node {
                Terminal::True => {
                    debug_assert_eq!(node_state.n_evaluated, 0);
                    debug_assert_eq!(node_state.n_satisfied, 0);
                    self.stack.push(stack::Element::Satisfied);
                }
                Terminal::False => {
                    debug_assert_eq!(node_state.n_evaluated, 0);
                    debug_assert_eq!(node_state.n_satisfied, 0);
                    self.stack.push(stack::Element::Dissatisfied);
                }
                Terminal::PkK(ref pk) => {
                    debug_assert_eq!(node_state.n_evaluated, 0);
                    debug_assert_eq!(node_state.n_satisfied, 0);
                    let res = self.stack.evaluate_pk(&mut self.verify_sig, *pk);
                    if res.is_some() {
                        return res;
                    }
                }
                Terminal::PkH(ref pk) => {
                    debug_assert_eq!(node_state.n_evaluated, 0);
                    debug_assert_eq!(node_state.n_satisfied, 0);
                    let res = self.stack.evaluate_pkh(
                        &mut self.verify_sig,
                        pk.to_pubkeyhash(self.sig_type),
                        self.sig_type,
                    );
                    if res.is_some() {
                        return res;
                    }
                }
                Terminal::RawPkH(ref pkh) => {
                    debug_assert_eq!(node_state.n_evaluated, 0);
                    debug_assert_eq!(node_state.n_satisfied, 0);
                    let res = self
                        .stack
                        .evaluate_pkh(&mut self.verify_sig, *pkh, self.sig_type);
                    if res.is_some() {
                        return res;
                    }
                }
                Terminal::After(ref n) => {
                    debug_assert_eq!(node_state.n_evaluated, 0);
                    debug_assert_eq!(node_state.n_satisfied, 0);
                    let res = self
                        .stack
                        .evaluate_after(&absolute::LockTime::from(*n), self.lock_time);
                    if res.is_some() {
                        return res;
                    }
                }
                Terminal::Older(ref n) => {
                    debug_assert_eq!(node_state.n_evaluated, 0);
                    debug_assert_eq!(node_state.n_satisfied, 0);
                    let res = self.stack.evaluate_older(&(*n).into(), self.sequence);
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
                    Some(stack::Element::Dissatisfied) => {
                        self.stack.push(stack::Element::Dissatisfied);
                    }
                    Some(stack::Element::Satisfied) => {
                        self.push_evaluation_state(node_state.node, 1, 1);
                        self.push_evaluation_state(sub, 0, 0);
                    }
                    Some(stack::Element::Push(_v)) => {
                        return Some(Err(Error::UnexpectedStackElementPush))
                    }
                    None => return Some(Err(Error::UnexpectedStackEnd)),
                },
                Terminal::DupIf(ref _sub) if node_state.n_evaluated == 1 => {
                    self.stack.push(stack::Element::Satisfied);
                }
                Terminal::ZeroNotEqual(ref sub) | Terminal::Verify(ref sub)
                    if node_state.n_evaluated == 0 =>
                {
                    self.push_evaluation_state(node_state.node, 1, 0);
                    self.push_evaluation_state(sub, 0, 0);
                }
                Terminal::Verify(ref _sub) if node_state.n_evaluated == 1 => {
                    match self.stack.pop() {
                        Some(stack::Element::Satisfied) => (),
                        Some(_) => return Some(Err(Error::VerifyFailed)),
                        None => return Some(Err(Error::UnexpectedStackEnd)),
                    }
                }
                Terminal::ZeroNotEqual(ref _sub) if node_state.n_evaluated == 1 => {
                    match self.stack.pop() {
                        Some(stack::Element::Dissatisfied) => {
                            self.stack.push(stack::Element::Dissatisfied)
                        }
                        Some(_) => self.stack.push(stack::Element::Satisfied),
                        None => return Some(Err(Error::UnexpectedStackEnd)),
                    }
                }
                Terminal::NonZero(ref sub) => {
                    debug_assert_eq!(node_state.n_evaluated, 0);
                    debug_assert_eq!(node_state.n_satisfied, 0);
                    match self.stack.last() {
                        Some(&stack::Element::Dissatisfied) => (),
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
                        Some(stack::Element::Dissatisfied) => {
                            self.push_evaluation_state(node_state.node, 2, 0);
                            self.push_evaluation_state(right, 0, 0);
                        }
                        Some(stack::Element::Satisfied) => {
                            self.push_evaluation_state(node_state.node, 2, 1);
                            self.push_evaluation_state(right, 0, 0);
                        }
                        Some(stack::Element::Push(_v)) => {
                            return Some(Err(Error::UnexpectedStackElementPush))
                        }
                        None => return Some(Err(Error::UnexpectedStackEnd)),
                    }
                }
                Terminal::AndB(ref _left, ref _right) if node_state.n_evaluated == 2 => {
                    match self.stack.pop() {
                        Some(stack::Element::Satisfied) if node_state.n_satisfied == 1 => {
                            self.stack.push(stack::Element::Satisfied)
                        }
                        Some(_) => self.stack.push(stack::Element::Dissatisfied),
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
                        Some(stack::Element::Dissatisfied) if node_state.n_satisfied == 0 => {
                            self.stack.push(stack::Element::Dissatisfied)
                        }
                        Some(_) => {
                            self.stack.push(stack::Element::Satisfied);
                        }
                        None => return Some(Err(Error::UnexpectedStackEnd)),
                    }
                }
                Terminal::OrC(ref _left, ref right) if node_state.n_evaluated == 1 => {
                    match self.stack.pop() {
                        Some(stack::Element::Satisfied) => (),
                        Some(stack::Element::Dissatisfied) => {
                            self.push_evaluation_state(right, 0, 0)
                        }
                        Some(stack::Element::Push(_v)) => {
                            return Some(Err(Error::UnexpectedStackElementPush))
                        }
                        None => return Some(Err(Error::UnexpectedStackEnd)),
                    }
                }
                Terminal::OrD(ref _left, ref right) if node_state.n_evaluated == 1 => {
                    match self.stack.pop() {
                        Some(stack::Element::Satisfied) => {
                            self.stack.push(stack::Element::Satisfied)
                        }
                        Some(stack::Element::Dissatisfied) => {
                            self.push_evaluation_state(right, 0, 0)
                        }
                        Some(stack::Element::Push(_v)) => {
                            return Some(Err(Error::UnexpectedStackElementPush))
                        }
                        None => return Some(Err(Error::UnexpectedStackEnd)),
                    }
                }
                Terminal::AndOr(_, ref left, ref right) | Terminal::OrI(ref left, ref right) => {
                    match self.stack.pop() {
                        Some(stack::Element::Satisfied) => self.push_evaluation_state(left, 0, 0),
                        Some(stack::Element::Dissatisfied) => {
                            self.push_evaluation_state(right, 0, 0)
                        }
                        Some(stack::Element::Push(_v)) => {
                            return Some(Err(Error::UnexpectedStackElementPush))
                        }
                        None => return Some(Err(Error::UnexpectedStackEnd)),
                    }
                }
                Terminal::Thresh(ref thresh) if node_state.n_evaluated == 0 => {
                    self.push_evaluation_state(node_state.node, 1, 0);
                    self.push_evaluation_state(&thresh.data()[0], 0, 0);
                }
                Terminal::Thresh(ref thresh) if node_state.n_evaluated == thresh.n() => {
                    match self.stack.pop() {
                        Some(stack::Element::Dissatisfied)
                            if node_state.n_satisfied == thresh.k() =>
                        {
                            self.stack.push(stack::Element::Satisfied)
                        }
                        Some(stack::Element::Satisfied)
                            if node_state.n_satisfied == thresh.k() - 1 =>
                        {
                            self.stack.push(stack::Element::Satisfied)
                        }
                        Some(stack::Element::Satisfied) | Some(stack::Element::Dissatisfied) => {
                            self.stack.push(stack::Element::Dissatisfied)
                        }
                        Some(stack::Element::Push(_v)) => {
                            return Some(Err(Error::UnexpectedStackElementPush))
                        }
                        None => return Some(Err(Error::UnexpectedStackEnd)),
                    }
                }
                Terminal::Thresh(ref thresh) if node_state.n_evaluated != 0 => {
                    match self.stack.pop() {
                        Some(stack::Element::Dissatisfied) => {
                            self.push_evaluation_state(
                                node_state.node,
                                node_state.n_evaluated + 1,
                                node_state.n_satisfied,
                            );
                            self.push_evaluation_state(
                                &thresh.data()[node_state.n_evaluated],
                                0,
                                0,
                            );
                        }
                        Some(stack::Element::Satisfied) => {
                            self.push_evaluation_state(
                                node_state.node,
                                node_state.n_evaluated + 1,
                                node_state.n_satisfied + 1,
                            );
                            self.push_evaluation_state(
                                &thresh.data()[node_state.n_evaluated],
                                0,
                                0,
                            );
                        }
                        Some(stack::Element::Push(_v)) => {
                            return Some(Err(Error::UnexpectedStackElementPush))
                        }
                        None => return Some(Err(Error::UnexpectedStackEnd)),
                    }
                }
                Terminal::MultiA(ref thresh) => {
                    if node_state.n_evaluated == thresh.n() {
                        if node_state.n_satisfied == thresh.k() {
                            self.stack.push(stack::Element::Satisfied);
                        } else {
                            self.stack.push(stack::Element::Dissatisfied);
                        }
                    } else {
                        // evaluate each key with as a pk
                        // note that evaluate_pk will error on non-empty incorrect sigs
                        // push 1 on satisfied sigs and push 0 on empty sigs
                        match self.stack.evaluate_pk(
                            &mut self.verify_sig,
                            thresh.data()[node_state.n_evaluated],
                        ) {
                            Some(Ok(x)) => {
                                self.push_evaluation_state(
                                    node_state.node,
                                    node_state.n_evaluated + 1,
                                    node_state.n_satisfied + 1,
                                );
                                match self.stack.pop() {
                                    Some(..) => return Some(Ok(x)),
                                    None => return Some(Err(Error::UnexpectedStackEnd)),
                                }
                            }
                            None => {
                                self.push_evaluation_state(
                                    node_state.node,
                                    node_state.n_evaluated + 1,
                                    node_state.n_satisfied,
                                );
                                match self.stack.pop() {
                                    Some(..) => {} // not-satisfied, look for next key
                                    None => return Some(Err(Error::UnexpectedStackEnd)),
                                }
                            }
                            x => return x, //forward errors as is
                        }
                    }
                }
                Terminal::Multi(ref thresh) if node_state.n_evaluated == 0 => {
                    let len = self.stack.len();
                    if len < thresh.k() + 1 {
                        return Some(Err(Error::InsufficientSignaturesMultiSig));
                    } else {
                        //Non-sat case. If the first sig is empty, others k elements must
                        //be empty.
                        match self.stack.last() {
                            Some(&stack::Element::Dissatisfied) => {
                                //Remove the extra zero from multi-sig check
                                let sigs = self.stack.split_off(len - (thresh.k() + 1));
                                let nonsat = sigs
                                    .iter()
                                    .map(|sig| *sig == stack::Element::Dissatisfied)
                                    .filter(|empty| *empty)
                                    .count();
                                if nonsat == thresh.k() + 1 {
                                    self.stack.push(stack::Element::Dissatisfied);
                                } else {
                                    return Some(Err(Error::MissingExtraZeroMultiSig));
                                }
                            }
                            None => return Some(Err(Error::UnexpectedStackEnd)),
                            _ => {
                                match self.stack.evaluate_multi(
                                    &mut self.verify_sig,
                                    &thresh.data()[thresh.n() - 1],
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
                    }
                }
                Terminal::Multi(ref thresh) => {
                    if node_state.n_satisfied == thresh.k() {
                        //multi-sig bug: Pop extra 0
                        if let Some(stack::Element::Dissatisfied) = self.stack.pop() {
                            self.stack.push(stack::Element::Satisfied);
                        } else {
                            return Some(Err(Error::MissingExtraZeroMultiSig));
                        }
                    } else if node_state.n_evaluated == thresh.n() {
                        return Some(Err(Error::MultiSigEvaluationError));
                    } else {
                        match self.stack.evaluate_multi(
                            &mut self.verify_sig,
                            &thresh.data()[thresh.n() - node_state.n_evaluated - 1],
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
            if let Some(stack::Element::Push(sig)) = self.stack.pop() {
                if let Ok(key_sig) = verify_sersig(&mut self.verify_sig, pk, sig) {
                    //Signature check successful, set public_key to None to
                    //terminate the next() function in the subsequent call
                    self.public_key = None;
                    self.stack.push(stack::Element::Satisfied);
                    Some(Ok(SatisfiedConstraint::PublicKey { key_sig }))
                } else {
                    Some(Err(Error::PkEvaluationError(PkEvalErrInner::from(*pk))))
                }
            } else {
                Some(Err(Error::UnexpectedStackEnd))
            }
        } else {
            //All the script has been executed.
            //Check that the stack must contain exactly 1 satisfied element
            if self.stack.pop() == Some(stack::Element::Satisfied) && self.stack.is_empty() {
                None
            } else {
                Some(Err(Error::ScriptSatisfactionError))
            }
        }
    }
}

/// Helper function to verify serialized signature
fn verify_sersig<'txin>(
    verify_sig: &mut Box<dyn FnMut(&KeySigPair) -> bool + 'txin>,
    pk: &BitcoinKey,
    sigser: &[u8],
) -> Result<KeySigPair, Error> {
    match pk {
        BitcoinKey::Fullkey(pk) => {
            let ecdsa_sig = bitcoin::ecdsa::Signature::from_slice(sigser)?;
            let key_sig_pair = KeySigPair::Ecdsa(*pk, ecdsa_sig);
            if verify_sig(&key_sig_pair) {
                Ok(key_sig_pair)
            } else {
                Err(Error::InvalidEcdsaSignature(*pk))
            }
        }
        BitcoinKey::XOnlyPublicKey(x_only_pk) => {
            let schnorr_sig = bitcoin::taproot::Signature::from_slice(sigser)?;
            let key_sig_pair = KeySigPair::Schnorr(*x_only_pk, schnorr_sig);
            if verify_sig(&key_sig_pair) {
                Ok(key_sig_pair)
            } else {
                Err(Error::InvalidSchnorrSignature(*x_only_pk))
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use bitcoin::secp256k1::Secp256k1;

    use super::inner::ToNoChecks;
    use super::*;
    use crate::miniscript::analyzable::ExtParams;

    #[allow(clippy::type_complexity)]
    fn setup_keys_sigs(
        n: usize,
    ) -> (
        Vec<bitcoin::PublicKey>,
        Vec<Vec<u8>>,
        Vec<bitcoin::ecdsa::Signature>,
        secp256k1::Message,
        Secp256k1<secp256k1::All>,
        Vec<bitcoin::key::XOnlyPublicKey>,
        Vec<bitcoin::taproot::Signature>,
        Vec<Vec<u8>>,
    ) {
        let secp = secp256k1::Secp256k1::new();
        let msg = secp256k1::Message::from_digest(*b"Yoda: btc, I trust. HODL I must!");
        let mut pks = vec![];
        let mut ecdsa_sigs = vec![];
        let mut der_sigs = vec![];
        let mut x_only_pks = vec![];
        let mut schnorr_sigs = vec![];
        let mut ser_schnorr_sigs = vec![];

        let mut sk = [0; 32];
        for i in 1..n + 1 {
            sk[0] = i as u8;
            sk[1] = (i >> 8) as u8;
            sk[2] = (i >> 16) as u8;

            let sk = secp256k1::SecretKey::from_slice(&sk[..]).expect("secret key");
            let pk = bitcoin::PublicKey {
                inner: secp256k1::PublicKey::from_secret_key(&secp, &sk),
                compressed: true,
            };
            let signature = secp.sign_ecdsa(&msg, &sk);
            ecdsa_sigs.push(bitcoin::ecdsa::Signature {
                signature,
                sighash_type: bitcoin::sighash::EcdsaSighashType::All,
            });
            let mut sigser = signature.serialize_der().to_vec();
            sigser.push(0x01); // sighash_all
            pks.push(pk);
            der_sigs.push(sigser);

            let keypair = bitcoin::key::Keypair::from_secret_key(&secp, &sk);
            let (x_only_pk, _parity) = bitcoin::key::XOnlyPublicKey::from_keypair(&keypair);
            x_only_pks.push(x_only_pk);
            let schnorr_sig = secp.sign_schnorr_with_aux_rand(&msg, &keypair, &[0u8; 32]);
            let schnorr_sig = bitcoin::taproot::Signature {
                signature: schnorr_sig,
                sighash_type: bitcoin::sighash::TapSighashType::Default,
            };
            ser_schnorr_sigs.push(schnorr_sig.to_vec());
            schnorr_sigs.push(schnorr_sig);
        }
        (pks, der_sigs, ecdsa_sigs, msg, secp, x_only_pks, schnorr_sigs, ser_schnorr_sigs)
    }

    #[test]
    fn sat_constraints() {
        let (pks, der_sigs, ecdsa_sigs, sighash, secp, xpks, schnorr_sigs, ser_schnorr_sigs) =
            setup_keys_sigs(10);
        let secp_ref = &secp;
        let vfyfn = |pksig: &KeySigPair| match pksig {
            KeySigPair::Ecdsa(pk, ecdsa_sig) => secp_ref
                .verify_ecdsa(&sighash, &ecdsa_sig.signature, &pk.inner)
                .is_ok(),
            KeySigPair::Schnorr(xpk, schnorr_sig) => secp_ref
                .verify_schnorr(&schnorr_sig.signature, &sighash, xpk)
                .is_ok(),
        };

        fn from_stack<'txin, 'elem>(
            verify_fn: Box<dyn FnMut(&KeySigPair) -> bool + 'elem>,
            stack: Stack<'txin>,
            ms: &'elem Miniscript<BitcoinKey, NoChecks>,
        ) -> Iter<'elem, 'txin> {
            Iter {
                verify_sig: verify_fn,
                stack,
                public_key: None,
                state: vec![NodeEvaluationState { node: ms, n_evaluated: 0, n_satisfied: 0 }],
                sequence: Sequence::from_height(1002),
                lock_time: absolute::LockTime::from_height(1002).unwrap(),
                has_errored: false,
                sig_type: SigType::Ecdsa,
            }
        }

        let pk = no_checks_ms(&format!("c:pk_k({})", pks[0]));
        let pkh = no_checks_ms(&format!("c:pk_h({})", pks[1]));
        //Time
        let after = no_checks_ms(&format!("after({})", 1000));
        let older = no_checks_ms(&format!("older({})", 1000));
        //Hashes
        let preimage = [0xab; 32];
        let sha256_hash = sha256::Hash::hash(&preimage);
        let sha256 = no_checks_ms(&format!("sha256({})", sha256_hash));
        let hash256_hash = hash256::Hash::hash(&preimage);
        let hash256 = no_checks_ms(&format!("hash256({})", hash256_hash));
        let hash160_hash = hash160::Hash::hash(&preimage);
        let hash160 = no_checks_ms(&format!("hash160({})", hash160_hash));
        let ripemd160_hash = ripemd160::Hash::hash(&preimage);
        let ripemd160 = no_checks_ms(&format!("ripemd160({})", ripemd160_hash));

        let stack = Stack::from(vec![stack::Element::Push(&der_sigs[0])]);
        let constraints = from_stack(Box::new(vfyfn), stack, &pk);
        let pk_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            pk_satisfied.unwrap(),
            vec![SatisfiedConstraint::PublicKey {
                key_sig: KeySigPair::Ecdsa(pks[0], ecdsa_sigs[0])
            }]
        );

        //Check Pk failure with wrong signature
        let stack = Stack::from(vec![stack::Element::Dissatisfied]);
        let constraints = from_stack(Box::new(vfyfn), stack, &pk);
        let pk_err: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert!(pk_err.is_err());

        //Check Pkh
        let pk_bytes = pks[1].to_public_key().to_bytes();
        let stack = Stack::from(vec![
            stack::Element::Push(&der_sigs[1]),
            stack::Element::Push(&pk_bytes),
        ]);
        let constraints = from_stack(Box::new(vfyfn), stack, &pkh);
        let pkh_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            pkh_satisfied.unwrap(),
            vec![SatisfiedConstraint::PublicKeyHash {
                keyhash: pks[1].to_pubkeyhash(SigType::Ecdsa),
                key_sig: KeySigPair::Ecdsa(pks[1], ecdsa_sigs[1])
            }]
        );

        //Check After
        let stack = Stack::from(vec![]);
        let constraints = from_stack(Box::new(vfyfn), stack, &after);
        let after_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            after_satisfied.unwrap(),
            vec![SatisfiedConstraint::AbsoluteTimelock {
                n: absolute::LockTime::from_height(1000).unwrap()
            }]
        );

        //Check Older
        let stack = Stack::from(vec![]);
        let constraints = from_stack(Box::new(vfyfn), stack, &older);
        let older_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            older_satisfied.unwrap(),
            vec![SatisfiedConstraint::RelativeTimelock {
                n: crate::RelLockTime::from_height(1000).into()
            }]
        );

        //Check Sha256
        let stack = Stack::from(vec![stack::Element::Push(&preimage)]);
        let constraints = from_stack(Box::new(vfyfn), stack, &sha256);
        let sah256_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            sah256_satisfied.unwrap(),
            vec![SatisfiedConstraint::HashLock {
                hash: HashLockType::Sha256(sha256_hash),
                preimage,
            }]
        );

        //Check Shad256
        let stack = Stack::from(vec![stack::Element::Push(&preimage)]);
        let constraints = from_stack(Box::new(vfyfn), stack, &hash256);
        let sha256d_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            sha256d_satisfied.unwrap(),
            vec![SatisfiedConstraint::HashLock {
                hash: HashLockType::Hash256(hash256_hash),
                preimage,
            }]
        );

        //Check hash160
        let stack = Stack::from(vec![stack::Element::Push(&preimage)]);
        let constraints = from_stack(Box::new(vfyfn), stack, &hash160);
        let hash160_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            hash160_satisfied.unwrap(),
            vec![SatisfiedConstraint::HashLock {
                hash: HashLockType::Hash160(hash160_hash),
                preimage,
            }]
        );

        //Check ripemd160
        let stack = Stack::from(vec![stack::Element::Push(&preimage)]);
        let constraints = from_stack(Box::new(vfyfn), stack, &ripemd160);
        let ripemd160_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            ripemd160_satisfied.unwrap(),
            vec![SatisfiedConstraint::HashLock {
                hash: HashLockType::Ripemd160(ripemd160_hash),
                preimage,
            }]
        );

        //Check AndV
        let pk_bytes = pks[1].to_public_key().to_bytes();
        let stack = Stack::from(vec![
            stack::Element::Push(&der_sigs[1]),
            stack::Element::Push(&pk_bytes),
            stack::Element::Push(&der_sigs[0]),
        ]);
        let elem = no_checks_ms(&format!("and_v(vc:pk_k({}),c:pk_h({}))", pks[0], pks[1]));
        let constraints = from_stack(Box::new(vfyfn), stack, &elem);

        let and_v_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            and_v_satisfied.unwrap(),
            vec![
                SatisfiedConstraint::PublicKey {
                    key_sig: KeySigPair::Ecdsa(pks[0], ecdsa_sigs[0])
                },
                SatisfiedConstraint::PublicKeyHash {
                    keyhash: pks[1].to_pubkeyhash(SigType::Ecdsa),
                    key_sig: KeySigPair::Ecdsa(pks[1], ecdsa_sigs[1])
                }
            ]
        );

        //Check AndB
        let stack = Stack::from(vec![
            stack::Element::Push(&preimage),
            stack::Element::Push(&der_sigs[0]),
        ]);
        let elem = no_checks_ms(&format!("and_b(c:pk_k({}),sjtv:sha256({}))", pks[0], sha256_hash));
        let constraints = from_stack(Box::new(vfyfn), stack, &elem);

        let and_b_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            and_b_satisfied.unwrap(),
            vec![
                SatisfiedConstraint::PublicKey {
                    key_sig: KeySigPair::Ecdsa(pks[0], ecdsa_sigs[0])
                },
                SatisfiedConstraint::HashLock { hash: HashLockType::Sha256(sha256_hash), preimage }
            ]
        );

        //Check AndOr
        let stack = Stack::from(vec![
            stack::Element::Push(&preimage),
            stack::Element::Push(&der_sigs[0]),
        ]);
        let elem = no_checks_ms(&format!(
            "andor(c:pk_k({}),jtv:sha256({}),c:pk_h({}))",
            pks[0], sha256_hash, pks[1],
        ));
        let constraints = from_stack(Box::new(vfyfn), stack, &elem);

        let and_or_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            and_or_satisfied.unwrap(),
            vec![
                SatisfiedConstraint::PublicKey {
                    key_sig: KeySigPair::Ecdsa(pks[0], ecdsa_sigs[0])
                },
                SatisfiedConstraint::HashLock { hash: HashLockType::Sha256(sha256_hash), preimage }
            ]
        );

        //AndOr second satisfaction path
        let pk_bytes = pks[1].to_public_key().to_bytes();
        let stack = Stack::from(vec![
            stack::Element::Push(&der_sigs[1]),
            stack::Element::Push(&pk_bytes),
            stack::Element::Dissatisfied,
        ]);
        let constraints = from_stack(Box::new(vfyfn), stack, &elem);

        let and_or_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            and_or_satisfied.unwrap(),
            vec![SatisfiedConstraint::PublicKeyHash {
                keyhash: pks[1].to_pubkeyhash(SigType::Ecdsa),
                key_sig: KeySigPair::Ecdsa(pks[1], ecdsa_sigs[1])
            }]
        );

        //Check OrB
        let stack = Stack::from(vec![
            stack::Element::Push(&preimage),
            stack::Element::Dissatisfied,
        ]);
        let elem = no_checks_ms(&format!("or_b(c:pk_k({}),sjtv:sha256({}))", pks[0], sha256_hash));
        let constraints = from_stack(Box::new(vfyfn), stack, &elem);

        let or_b_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            or_b_satisfied.unwrap(),
            vec![SatisfiedConstraint::HashLock {
                hash: HashLockType::Sha256(sha256_hash),
                preimage,
            }]
        );

        //Check OrD
        let stack = Stack::from(vec![stack::Element::Push(&der_sigs[0])]);
        let elem = no_checks_ms(&format!("or_d(c:pk_k({}),jtv:sha256({}))", pks[0], sha256_hash));
        let constraints = from_stack(Box::new(vfyfn), stack, &elem);

        let or_d_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            or_d_satisfied.unwrap(),
            vec![SatisfiedConstraint::PublicKey {
                key_sig: KeySigPair::Ecdsa(pks[0], ecdsa_sigs[0])
            }]
        );

        //Check OrC
        let stack = Stack::from(vec![
            stack::Element::Push(&der_sigs[0]),
            stack::Element::Dissatisfied,
        ]);
        let elem =
            no_checks_ms(&format!("t:or_c(jtv:sha256({}),vc:pk_k({}))", sha256_hash, pks[0]));
        let constraints = from_stack(Box::new(vfyfn), stack, &elem);

        let or_c_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            or_c_satisfied.unwrap(),
            vec![SatisfiedConstraint::PublicKey {
                key_sig: KeySigPair::Ecdsa(pks[0], ecdsa_sigs[0])
            }]
        );

        //Check OrI
        let stack = Stack::from(vec![
            stack::Element::Push(&der_sigs[0]),
            stack::Element::Dissatisfied,
        ]);
        let elem = no_checks_ms(&format!("or_i(jtv:sha256({}),c:pk_k({}))", sha256_hash, pks[0]));
        let constraints = from_stack(Box::new(vfyfn), stack, &elem);

        let or_i_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            or_i_satisfied.unwrap(),
            vec![SatisfiedConstraint::PublicKey {
                key_sig: KeySigPair::Ecdsa(pks[0], ecdsa_sigs[0])
            }]
        );

        //Check Thres
        let stack = Stack::from(vec![
            stack::Element::Push(&der_sigs[0]),
            stack::Element::Push(&der_sigs[1]),
            stack::Element::Push(&der_sigs[2]),
            stack::Element::Dissatisfied,
            stack::Element::Dissatisfied,
        ]);
        let elem = no_checks_ms(&format!(
            "thresh(3,c:pk_k({}),sc:pk_k({}),sc:pk_k({}),sc:pk_k({}),sc:pk_k({}))",
            pks[4], pks[3], pks[2], pks[1], pks[0],
        ));
        let constraints = from_stack(Box::new(vfyfn), stack, &elem);

        let thresh_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            thresh_satisfied.unwrap(),
            vec![
                SatisfiedConstraint::PublicKey {
                    key_sig: KeySigPair::Ecdsa(pks[2], ecdsa_sigs[2])
                },
                SatisfiedConstraint::PublicKey {
                    key_sig: KeySigPair::Ecdsa(pks[1], ecdsa_sigs[1])
                },
                SatisfiedConstraint::PublicKey {
                    key_sig: KeySigPair::Ecdsa(pks[0], ecdsa_sigs[0])
                }
            ]
        );

        // Check multi
        let stack = Stack::from(vec![
            stack::Element::Dissatisfied,
            stack::Element::Push(&der_sigs[2]),
            stack::Element::Push(&der_sigs[1]),
            stack::Element::Push(&der_sigs[0]),
        ]);
        let elem = no_checks_ms(&format!(
            "multi(3,{},{},{},{},{})",
            pks[4], pks[3], pks[2], pks[1], pks[0],
        ));
        let constraints = from_stack(Box::new(vfyfn), stack, &elem);

        let multi_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            multi_satisfied.unwrap(),
            vec![
                SatisfiedConstraint::PublicKey {
                    key_sig: KeySigPair::Ecdsa(pks[0], ecdsa_sigs[0])
                },
                SatisfiedConstraint::PublicKey {
                    key_sig: KeySigPair::Ecdsa(pks[1], ecdsa_sigs[1])
                },
                SatisfiedConstraint::PublicKey {
                    key_sig: KeySigPair::Ecdsa(pks[2], ecdsa_sigs[2])
                },
            ]
        );

        // Error multi: Invalid order of sigs
        let stack = Stack::from(vec![
            stack::Element::Dissatisfied,
            stack::Element::Push(&der_sigs[0]),
            stack::Element::Push(&der_sigs[2]),
            stack::Element::Push(&der_sigs[1]),
        ]);
        let elem = no_checks_ms(&format!(
            "multi(3,{},{},{},{},{})",
            pks[4], pks[3], pks[2], pks[1], pks[0],
        ));
        let constraints = from_stack(Box::new(vfyfn), stack, &elem);

        let multi_error: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert!(multi_error.is_err());

        // multi_a tests
        let stack = Stack::from(vec![
            stack::Element::Dissatisfied,
            stack::Element::Dissatisfied,
            stack::Element::Push(&ser_schnorr_sigs[2]),
            stack::Element::Push(&ser_schnorr_sigs[1]),
            stack::Element::Push(&ser_schnorr_sigs[0]),
        ]);

        let elem = x_only_no_checks_ms(&format!(
            "multi_a(3,{},{},{},{},{})",
            xpks[0], xpks[1], xpks[2], xpks[3], xpks[4],
        ));
        let constraints = from_stack(Box::new(vfyfn), stack, &elem);

        let multi_a_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert_eq!(
            multi_a_satisfied.unwrap(),
            vec![
                SatisfiedConstraint::PublicKey {
                    key_sig: KeySigPair::Schnorr(xpks[0], schnorr_sigs[0])
                },
                SatisfiedConstraint::PublicKey {
                    key_sig: KeySigPair::Schnorr(xpks[1], schnorr_sigs[1])
                },
                SatisfiedConstraint::PublicKey {
                    key_sig: KeySigPair::Schnorr(xpks[2], schnorr_sigs[2])
                },
            ]
        );

        // multi_a tests: wrong order of sigs
        let stack = Stack::from(vec![
            stack::Element::Dissatisfied,
            stack::Element::Push(&ser_schnorr_sigs[2]),
            stack::Element::Push(&ser_schnorr_sigs[1]),
            stack::Element::Push(&ser_schnorr_sigs[0]),
            stack::Element::Dissatisfied,
        ]);

        let elem = x_only_no_checks_ms(&format!(
            "multi_a(3,{},{},{},{},{})",
            xpks[0], xpks[1], xpks[2], xpks[3], xpks[4],
        ));
        let constraints = from_stack(Box::new(vfyfn), stack.clone(), &elem);

        let multi_a_error: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert!(multi_a_error.is_err());

        // multi_a wrong thresh: k = 2, but three sigs
        let elem = x_only_no_checks_ms(&format!(
            "multi_a(2,{},{},{},{},{})",
            xpks[0], xpks[1], xpks[2], xpks[3], xpks[4],
        ));
        let constraints = from_stack(Box::new(vfyfn), stack.clone(), &elem);

        let multi_a_error: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert!(multi_a_error.is_err());

        // multi_a correct thresh, but small stack
        let elem = x_only_no_checks_ms(&format!(
            "multi_a(3,{},{},{},{},{},{})",
            xpks[0], xpks[1], xpks[2], xpks[3], xpks[4], xpks[5]
        ));
        let constraints = from_stack(Box::new(vfyfn), stack, &elem);

        let multi_a_error: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
        assert!(multi_a_error.is_err());
    }

    // By design there is no support for parse a miniscript with BitcoinKey
    // because it does not implement FromStr
    fn no_checks_ms(ms: &str) -> Miniscript<BitcoinKey, NoChecks> {
        // Parsing should allow raw hashes in the interpreter
        let elem: Miniscript<bitcoin::PublicKey, NoChecks> =
            Miniscript::from_str_ext(ms, &ExtParams::allow_all()).unwrap();
        elem.to_no_checks_ms()
    }

    fn x_only_no_checks_ms(ms: &str) -> Miniscript<BitcoinKey, NoChecks> {
        let elem: Miniscript<bitcoin::key::XOnlyPublicKey, NoChecks> =
            Miniscript::from_str_ext(ms, &ExtParams::allow_all()).unwrap();
        elem.to_no_checks_ms()
    }
}
