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

use bitcoin::hashes::hash160;
use bitcoin::{self, secp256k1};
use std::{error, fmt};

/// Detailed Error type for Interpreter
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// We expected a push (including a `OP_1` but no other numeric pushes)
    ExpectedPush,
    /// An uncompressed public key was encountered in a context where it is
    /// disallowed (e.g. in a Segwit script or p2wpkh output)
    UncompressedPubkey,
    /// Unexpected Stack End, caused by popping extra elements from stack
    UnexpectedStackEnd,
    /// Unexpected Stack Push `stack::Element::Push` element when the interpreter
    /// was expecting a stack boolean `stack::Element::Satisfied` or
    /// `stack::Element::Dissatisfied`
    UnexpectedStackElementPush,
    /// Verify expects stack top element exactly to be `stack::Element::Satisfied`.
    /// This error is raised even if the stack top is `stack::Element::Push`.
    VerifyFailed,
    /// MultiSig missing at least `1` witness elements out of `k + 1` required
    InsufficientSignaturesMultiSig,
    /// MultiSig requires 1 extra zero element apart from the `k` signatures
    MissingExtraZeroMultiSig,
    /// Script abortion because of incorrect dissatisfaction for multisig.
    /// NoChecks input witness apart from sat(0 sig ...) or nsat(0 0 ..) leads to
    /// this error. This is network standardness assumption and miniscript only
    /// supports standard scripts
    MultiSigEvaluationError,
    /// Signature failed to verify
    InvalidSignature(bitcoin::PublicKey),
    /// General Interpreter error.
    CouldNotEvaluate,
    /// Script abortion because of incorrect dissatisfaction for Checksig.
    /// NoChecks input witness apart from sat(sig) or nsat(0) leads to
    /// this error. This is network standardness assumption and miniscript only
    /// supports standard scripts
    PkEvaluationError(bitcoin::PublicKey),
    /// Miniscript requires the entire top level script to be satisfied.
    ScriptSatisfactionError,
    /// The Public Key hash check for the given pubkey. This occurs in `PkH`
    /// node when the given key does not match to Hash in script.
    PkHashVerifyFail(hash160::Hash),
    /// Parse Error while parsing a `stack::Element::Push` as a Pubkey. Both
    /// 33 byte and 65 bytes are supported.
    PubkeyParseError,
    /// The preimage to the hash function must be exactly 32 bytes.
    HashPreimageLengthMismatch,
    /// Got `stack::Element::Satisfied` or `stack::Element::Dissatisfied` when the
    /// interpreter was expecting `stack::Element::Push`
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
            Error::ExpectedPush => f.write_str("expected push in script"),
            Error::UncompressedPubkey => f.write_str("Illegal use of uncompressed pubkey"),
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
