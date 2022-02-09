use bitcoin;
use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script;
use bitcoin::blockdata::script::Instruction;
use bitcoin::Script;
use miniscript::context;

use {ScriptContext, ToPublicKey};
pub(crate) fn varint_len(n: usize) -> usize {
    bitcoin::VarInt(n as u64).len()
}

// Helper function to calculate witness size
pub(crate) fn witness_size(wit: &[Vec<u8>]) -> usize {
    wit.iter().map(Vec::len).sum::<usize>() + varint_len(wit.len())
}

pub(crate) fn witness_to_scriptsig(witness: &[Vec<u8>]) -> Script {
    let mut b = script::Builder::new();
    for wit in witness {
        if let Ok(n) = script::read_scriptint(wit) {
            b = b.push_int(n);
        } else {
            b = b.push_slice(wit);
        }
    }
    b.into_script()
}

// trait for pushing key that depend on context
pub(crate) trait MsKeyBuilder {
    /// Serialize the key as bytes based on script context. Used when encoding miniscript into bitcoin script
    fn push_ms_key<Pk, Ctx>(self, key: &Pk) -> Self
    where
        Pk: ToPublicKey,
        Ctx: ScriptContext;
}

impl MsKeyBuilder for script::Builder {
    fn push_ms_key<Pk, Ctx>(self, key: &Pk) -> Self
    where
        Pk: ToPublicKey,
        Ctx: ScriptContext,
    {
        match Ctx::sig_type() {
            context::SigType::Ecdsa => self.push_key(&key.to_public_key()),
            context::SigType::Schnorr => self.push_slice(&key.to_x_only_pubkey().serialize()),
        }
    }
}

// This belongs in rust-bitcoin, make this upstream later
pub(crate) fn script_is_v1_tr(s: &Script) -> bool {
    let mut iter = s.instructions_minimal();
    if s.len() != 32
        || iter.next() != Some(Ok(Instruction::Op(opcodes::all::OP_PUSHNUM_1)))
        || iter.next() != Some(Ok(Instruction::Op(opcodes::all::OP_PUSHBYTES_32)))
    {
        return false;
    }
    return true;
}
