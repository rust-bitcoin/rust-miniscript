// Miniscript and Output Descriptors
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

//! Miniscript
//!
//! Blurb blurb blurb
//! cf https://gist.github.com/sipa/b7eec358de29d8e54c74e811820ed662
//! cf https://gist.github.com/sipa/e3d23d498c430bb601c5bca83523fa82
//!

#![cfg_attr(all(test, feature = "unstable"), feature(test))]
#[cfg(all(test, feature = "unstable"))] extern crate test;

extern crate arrayvec;
extern crate bitcoin;
extern crate bitcoin_hashes;
extern crate secp256k1;
#[cfg(feature="serde")] extern crate serde;

pub mod miniscript;
pub mod descriptor;
pub mod expression;
pub mod policy;
pub mod psbt;

use std::{error, fmt, str};

use bitcoin::blockdata::{opcodes, script};
use bitcoin_hashes::sha256;

pub use descriptor::Descriptor;
pub use miniscript::Miniscript;
pub use policy::AbstractPolicy;
pub use policy::Policy;

/// Fully-typed `None` value to give to satisfaction functions when there is no hash preimages
pub static NO_HASHES: Option<&'static fn(sha256::Hash) -> Option<[u8; 32]>> = None;

/// Dummy key which de/serializes to the empty string; useful sometimes for testing
#[derive(Copy, Clone, Debug)]
pub struct DummyKey;

impl str::FromStr for DummyKey {
    type Err = &'static str;
    fn from_str(x: &str) -> Result<DummyKey, &'static str> {
        if x.is_empty() {
            Ok(DummyKey)
        } else {
            Err("non empty dummy key")
        }
    }
}

impl fmt::Display for DummyKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("")
    }
}

/// Script Descriptor error
#[derive(Debug)]
pub enum Error {
    /// Opcode appeared which is not part of the script subset
    InvalidOpcode(opcodes::All),
    /// Push was illegal in some context
    InvalidPush(Vec<u8>),
    /// PSBT-related error
    Psbt(psbt::Error),
    /// rust-bitcoin script error
    Script(script::Error),
    /// Encountered unprintable character in descriptor
    Unprintable(u8),
    /// expected character while parsing descriptor; didn't find one
    ExpectedChar(char),
    /// While parsing backward, hit beginning of script
    UnexpectedStart,
    /// Got something we were not expecting
    Unexpected(String),
    /// Failed to parse a push as a public key
    BadPubkey(bitcoin::consensus::encode::Error),
    /// Could not satisfy a script (fragment) because of a missing hash preimage
    MissingHash(sha256::Hash),
    /// Could not satisfy a script (fragment) because of a missing signature
    MissingSig(String),
    /// Could not satisfy, locktime not met
    LocktimeNotMet(u32),
    /// General failure to satisfy
    CouldNotSatisfy
}

fn errstr(s: &str) -> Error {
    Error::Unexpected(s.to_owned())
}

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::BadPubkey(ref e) => Some(e),
            Error::Psbt(ref e) => Some(e),
            _ => None,
        }
    }

    fn description(&self) -> &str {
        ""
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidOpcode(ref op) => write!(f, "invalid opcode {}", op),
            Error::InvalidPush(ref push) => write!(f, "invalid push {:?}", push), // TODO hexify this
            Error::Psbt(ref e) => fmt::Display::fmt(e, f),
            Error::Script(ref e) => fmt::Display::fmt(e, f),
            Error::Unprintable(x) => write!(f, "unprintable character 0x{:02x}", x),
            Error::ExpectedChar(c) => write!(f, "expected {}", c),
            Error::UnexpectedStart => f.write_str("unexpected start of script"),
            Error::Unexpected(ref s) => write!(f, "unexpected «{}»", s),
            Error::MissingHash(ref h) => write!(f, "missing preimage of hash {}", h),
            Error::MissingSig(ref pk) => write!(f, "missing signature for key {:?}", pk),
            Error::LocktimeNotMet(n) => write!(f, "required locktime of {} blocks, not met", n),
            Error::CouldNotSatisfy => f.write_str("could not satisfy"),
            Error::BadPubkey(ref e) => fmt::Display::fmt(e, f),
        }
    }
}

#[doc(hidden)]
impl From<psbt::Error> for Error {
    fn from(e: psbt::Error) -> Error {
        Error::Psbt(e)
    }
}

