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
extern crate secp256k1;

pub mod descript;
pub mod descriptor;
pub mod expression;
pub mod policy;

use std::{error, fmt, str};

use bitcoin::blockdata::{opcodes, script};
use bitcoin::util::hash::{Hash160, Sha256dHash};

pub use descriptor::Descriptor;
pub use descript::Descript;
pub use policy::Policy;

/// Fully-typed `None` value to give to satisfaction functions when there is no hash preimages
pub static NO_HASHES: Option<&'static fn(Sha256dHash) -> Option<[u8; 32]>> = None;

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Opcode appeared which is not part of the script subset
    InvalidOpcode(opcodes::All),
    /// Push was illegal in some context
    InvalidPush(Vec<u8>),
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
    BadPubkey(secp256k1::Error),
    /// Could not satisfy a script (fragment) because of a missing hash preimage
    MissingHash(Sha256dHash),
    /// Could not satisfy a script (fragment) because of a missing signature
    MissingSig(String),
    /// Could not satisfy a script (fragment) because of a missing pubkey corresponding to a pkh hash
    MissingPubkey(Hash160),
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
            _ => None,
        }
    }

    fn description(&self) -> &str {
        match *self {
            Error::InvalidOpcode(..) => "invalid opcode",
            Error::InvalidPush(..) => "invalid push",
            Error::Script(ref e) => error::Error::description(e),
            Error::Unprintable(..) => "unprintable character in descriptor",
            Error::ExpectedChar(..) => "invalid character in descriptor",
            Error::UnexpectedStart => "unexpected start of script",
            Error::Unexpected(..) => "unexpected token",
            Error::MissingHash(..) => "missing hash preimage",
            Error::MissingSig(..) => "missing signature (checksig)",
            Error::MissingPubkey(..) => "missing pubkey (p2pkh)",
            Error::LocktimeNotMet(..) => "locktime not met",
            Error::CouldNotSatisfy => "could not satisfy",
            Error::BadPubkey(ref e) => error::Error::description(e),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidOpcode(ref op) => write!(f, "invalid opcode {}", op),
            Error::InvalidPush(ref push) => write!(f, "invalid push {:?}", push), // TODO hexify this
            Error::Script(ref e) => fmt::Display::fmt(e, f),
            Error::Unprintable(x) => write!(f, "unprintable character 0x{:02x}", x),
            Error::ExpectedChar(c) => write!(f, "expected {}", c),
            Error::UnexpectedStart => f.write_str("unexpected start of script"),
            Error::Unexpected(ref s) => write!(f, "unexpected «{}»", s),
            Error::MissingHash(ref h) => write!(f, "missing preimage of hash {}", h),
            Error::MissingSig(ref pk) => write!(f, "missing signature for key {:?}", pk),
            Error::MissingPubkey(ref hash) => write!(f, "missing public key for hash {:?}", hash),
            Error::LocktimeNotMet(n) => write!(f, "required locktime of {} blocks, not met", n),
            Error::CouldNotSatisfy => f.write_str("could not satisfy"),
            Error::BadPubkey(ref e) => fmt::Display::fmt(e, f),
        }
    }

}
