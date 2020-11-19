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

use bitcoin::{self, secp256k1};

use super::Error;
use BitcoinSig;

/// Helper function to verify serialized signature
pub fn verify_sersig<'stack, F>(
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

