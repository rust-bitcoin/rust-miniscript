// BIP322 Generic Signature Algorithm
// Written in 2019 by
//     Rajarshi Maitra <rajarshi149@protonmail.com>]
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

//! # BIP322 Generic Signed Message Structure
//!
//! This module implements the BIP322 Generic Message Signer and Validator
//!
//! `https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki`
//!

use crate::{Descriptor, DescriptorTrait, MiniscriptKey, ToPublicKey};
use bitcoin::blockdata::{opcodes, script::Builder};
use bitcoin::hashes::{
    borrow_slice_impl, hex_fmt_impl, index_impl, serde_impl, sha256t_hash_newtype, Hash,
};
use bitcoin::secp256k1::{Secp256k1, Signature};
use bitcoin::{OutPoint, PublicKey, SigHashType, Transaction, TxIn, TxOut};

use crate::interpreter::{Error as InterpreterError, Interpreter};
use std::convert::From;

// BIP322 message tag = sha256("BIP0322-signed-message")
static MIDSTATE: [u8; 32] = [
    116, 101, 132, 161, 135, 47, 161, 0, 65, 85, 78, 255, 160, 56, 214, 18, 73, 66, 221, 121, 180,
    229, 138, 76, 218, 24, 78, 19, 219, 230, 44, 73,
];

// BIP322 Tagged Hash
sha256t_hash_newtype!(
    MessageHash,
    MessageTag,
    MIDSTATE,
    64,
    doc = "test hash",
    true
);

/// BIP322 Error types
#[derive(Debug)]
pub enum BIP322Error {
    /// BIP322 Internal Error
    InternalError(String),

    /// Signature Validation Error
    ValidationError(InterpreterError),
}

#[doc(hidden)]
impl From<InterpreterError> for BIP322Error {
    fn from(e: InterpreterError) -> BIP322Error {
        BIP322Error::ValidationError(e)
    }
}

/// Bip322 Signatures
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Bip322Signature {
    /// Legacy style. Only applicable for P2PKH message_challenge
    Legacy(Signature, PublicKey),

    /// Simple witness structure
    Simple(Vec<Vec<u8>>),

    /// Full `to_sign` transaction structure
    Full(Transaction),
}

/// BIP322 validator structure
/// A standard for interoperable signed messages based on the Bitcoin Script format,
/// either for proving fund availability, or committing to a message as the intended
/// recipient of funds sent to the invoice address.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Bip322<T: MiniscriptKey + ToPublicKey> {
    /// Message to be signed
    message: Vec<u8>,

    /// Signature to verify the message
    /// Optional value is used here because a validator structure can be
    /// created without a BIP322Signature. Such structure can only produce
    /// to_spend (or empty to_sign) transaction, but cannot validate them.
    signature: Option<Bip322Signature>,

    /// script_pubkey to define the challenge script inside to_spend transaction
    /// here we take in descriptors to derive the resulting script_pubkey
    message_challenge: Descriptor<T>,
}

impl<T: MiniscriptKey + ToPublicKey> Bip322<T> {
    /// Create a new BIP322 validator
    pub fn new(msg: &[u8], sig: Option<Bip322Signature>, addr: Descriptor<T>) -> Self {
        Bip322 {
            message: msg.to_vec(),
            signature: sig,
            message_challenge: addr,
        }
    }

    /// Insert Signature inside BIP322 structure
    pub fn insert_sig(&mut self, sig: Bip322Signature) {
        self.signature = Some(sig)
    }

    /// create the to_spend transaction
    pub fn to_spend(&self) -> Transaction {
        // create default input and output
        let mut vin = TxIn::default();
        let mut vout = TxOut::default();

        // calculate the message tagged hash
        let msg_hash = MessageHash::hash(&self.message[..]).into_inner();

        // mutate the input with appropriate script_sig and sequence
        vin.script_sig = Builder::new()
            .push_int(0)
            .push_slice(&msg_hash[..])
            .into_script();
        vin.sequence = 0;

        // mutate the value and script_pubkey as appropriate
        vout.value = 0;
        vout.script_pubkey = self.message_challenge.script_pubkey();

        // create and return final transaction
        Transaction {
            version: 0,
            lock_time: 0,
            input: vec![vin],
            output: vec![vout],
        }
    }

    /// Create to_sign transaction
    /// This will create a transaction structure with empty signature and witness field
    /// its up to the user of the library to fill the Tx with appropriate signature and witness  
    pub fn to_sign(&self) -> Transaction {
        // create the appropriate input
        let outpoint = OutPoint::new(self.to_spend().txid(), 0);
        let mut input = TxIn::default();
        input.previous_output = outpoint;
        input.sequence = 0;

        // create the output
        let output = TxOut {
            value: 0,
            script_pubkey: Builder::new()
                .push_opcode(opcodes::all::OP_RETURN)
                .into_script(),
        };

        // return resulting transaction
        Transaction {
            version: 0,
            lock_time: 0,
            input: vec![input],
            output: vec![output],
        }
    }

    /// Validate a BIP322 Signature against the message and challenge script
    /// This will require a BIP322Signature inside the structure
    pub fn validate(&self) -> Result<bool, BIP322Error> {
        match &self.signature {
            None => Err(BIP322Error::InternalError(
                "Signature required for validation".to_string(),
            )),
            Some(sig) => {
                match sig {
                    // A Full signature can be validated directly against the `to_sign` transaction
                    Bip322Signature::Full(to_sign) => self.tx_validation(to_sign),

                    // If Simple Signature is provided, the resulting `to_sign` Tx will be computed
                    Bip322Signature::Simple(witness) => {
                        // create empty to_sign transaction
                        let mut to_sign = self.to_sign();

                        to_sign.input[0].witness = witness.to_owned();

                        self.tx_validation(&to_sign)
                    }

                    // Legacy Signature can only be used to validate against P2PKH message_challenge
                    Bip322Signature::Legacy(sig, pubkey) => {
                        if !self.message_challenge.script_pubkey().is_p2pkh() {
                            return Err(BIP322Error::InternalError("Legacy style signature is only applicable for P2PKH message_challenge".to_string()));
                        } else {
                            let mut sig_ser = sig.serialize_der()[..].to_vec();

                            // By default SigHashType is ALL
                            sig_ser.push(SigHashType::All as u8);

                            let script_sig = Builder::new()
                                .push_slice(&sig_ser[..])
                                .push_key(&pubkey)
                                .into_script();

                            let mut to_sign = self.to_sign();

                            to_sign.input[0].script_sig = script_sig;

                            self.tx_validation(&to_sign)
                        }
                    }
                }
            }
        }
    }

    // Internal helper function to perform transaction validation
    fn tx_validation(&self, to_sign: &Transaction) -> Result<bool, BIP322Error> {
        let secp = Secp256k1::new();

        // create an Interpreter to validate to_spend transaction
        let mut interpreter = Interpreter::from_txdata(
            &self.message_challenge.script_pubkey(),
            &to_sign.input[0].script_sig,
            &to_sign.input[0].witness,
            0,
            0,
        )?;

        // create the signature verification function
        let vfyfn = interpreter.sighash_verify(&secp, &to_sign, 0, 0);

        let mut result = false;

        for elem in interpreter.iter(vfyfn) {
            match elem {
                Ok(_) => result = true,
                Err(e) => return Err(BIP322Error::ValidationError(e)),
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bitcoin::secp256k1::{Message, Secp256k1};
    use bitcoin::util::bip143;
    use bitcoin::PrivateKey;
    use bitcoin::SigHashType;

    #[test]
    fn test_bip322_validation() {
        // Create key pairs and secp context
        let sk =
            PrivateKey::from_wif("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy").unwrap();

        let ctx = Secp256k1::new();
        let pk = sk.public_key(&ctx);

        // wpkh descriptor from pubkey
        let desc = Descriptor::new_wpkh(pk).unwrap();

        // Corresponding p2pkh script. used for sighash calculation
        let p2pkh_script = bitcoin::Script::new_p2pkh(&pk.pubkey_hash());

        // Create BIP322 structures with empty signature
        let mut bip322_1 = Bip322 {
            message: b"Hello World".to_vec(),
            message_challenge: desc.clone(),
            signature: None,
        };
        let mut bip322_2 = bip322_1.clone();
        let mut bip322_3 = bip322_1.clone();

        // --------------------------------------------------------------
        // Check BIP322Signature::FUll

        // Generate to_sign transaction
        let mut to_sign = bip322_1.to_sign();

        // Generate witness for above wpkh pubkey
        let mut sighash_cache = bip143::SigHashCache::new(&to_sign);
        let message = sighash_cache.signature_hash(0, &p2pkh_script, 0, SigHashType::All.into());
        let message = Message::from_slice(&message[..]).unwrap();

        let signature = ctx.sign(&message, &sk.key);
        let der = signature.serialize_der();
        let mut sig_with_hash = der[..].to_vec();
        sig_with_hash.push(SigHashType::All as u8);

        let witness: Vec<Vec<u8>> = vec![sig_with_hash, pk.to_bytes()];
        to_sign.input[0].witness = witness.clone();

        // Insert signature inside BIP322 structure
        let bip322_signature = Bip322Signature::Full(to_sign);
        bip322_1.insert_sig(bip322_signature);

        // Check validation
        assert_eq!(bip322_1.validate().unwrap(), true);

        // ------------------------------------------------------------
        // Check Bip322Signature::Simple

        // Same structure can be validated with Simple type signature
        bip322_2.insert_sig(Bip322Signature::Simple(witness));

        assert_eq!(bip322_2.validate().unwrap(), true);

        // ------------------------------------------------------------
        // Check Bip322Signature::Legacy

        let desc = Descriptor::new_pkh(pk);

        // Replace previous message_challenge with p2pkh
        bip322_3.message_challenge = desc.clone();

        // Create empty to_sign
        let to_sign = bip322_3.to_sign();

        // Compute SigHash and Signature
        let message = to_sign.signature_hash(0, &desc.script_pubkey(), SigHashType::All as u32);
        let message = Message::from_slice(&message[..]).unwrap();
        let signature = ctx.sign(&message, &sk.key);

        // Create Bip322Signature::Legacy
        let bip322_sig = Bip322Signature::Legacy(signature, pk);
        bip322_3.insert_sig(bip322_sig);

        // Check validation
        assert_eq!(bip322_3.validate().unwrap(), true);
    }
}
