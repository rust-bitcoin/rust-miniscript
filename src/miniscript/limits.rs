//! Miscellaneous constraints imposed by Bitcoin.
//! These constraints can be either Consensus or Policy (standardness) rules, for either Segwitv0
//! or Legacy scripts.

/// Maximum operations per script
// https://github.com/bitcoin/bitcoin/blob/875e1ccc9fe01e026e564dfd39a64d9a4b332a89/src/script/script.h#L26
pub const MAX_OPS_PER_SCRIPT: usize = 201;
/// Maximum p2wsh initial stack items
// https://github.com/bitcoin/bitcoin/blob/875e1ccc9fe01e026e564dfd39a64d9a4b332a89/src/policy/policy.h#L40
pub const MAX_STANDARD_P2WSH_STACK_ITEMS: usize = 100;
/// Maximum script size allowed by consensus rules
// https://github.com/bitcoin/bitcoin/blob/42b66a6b814bca130a9ccf0a3f747cf33d628232/src/script/script.h#L32
pub const MAX_SCRIPT_SIZE: usize = 10_000;
/// Maximum script size allowed by standardness rules
// https://github.com/bitcoin/bitcoin/blob/283a73d7eaea2907a6f7f800f529a0d6db53d7a6/src/policy/policy.h#L44
pub const MAX_STANDARD_P2WSH_SCRIPT_SIZE: usize = 3600;
/// The Threshold for deciding whether `nLockTime` is interpreted as
/// time or height.
// https://github.com/bitcoin/bitcoin/blob/9ccaee1d5e2e4b79b0a7c29aadb41b97e4741332/src/script/script.h#L39
pub const HEIGHT_TIME_THRESHOLD: u32 = 500_000_000;

/// Bit flag for deciding whether sequence number is
/// interpreted as height or time
/* If nSequence encodes a relative lock-time and this flag
 * is set, the relative lock-time has units of 512 seconds,
 * otherwise it specifies blocks with a granularity of 1. */
// https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki
pub const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;

/// Disable flag for sequence locktime
/* Below flags apply in the context of BIP 68*/
/* If this flag set, nSequence is NOT interpreted as a
 * relative lock-time. For future soft-fork compatibility*/
// https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki
pub const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;

/// Maximum script element size allowed by consensus rules
// https://github.com/bitcoin/bitcoin/blob/42b66a6b814bca130a9ccf0a3f747cf33d628232/src/script/script.h#L23
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
/// Maximum script sig size allowed by standardness rules
// https://github.com/bitcoin/bitcoin/blob/42b66a6b814bca130a9ccf0a3f747cf33d628232/src/policy/policy.cpp#L102
pub const MAX_SCRIPTSIG_SIZE: usize = 1650;
/// Maximum items during stack execution
// This limits also applies for initial stack satisfaction
// https://github.com/bitcoin/bitcoin/blob/3af495d6972379b07530a5fcc2665aa626d01621/src/script/script.h#L35
pub const MAX_STACK_SIZE: usize = 1000;
/** The maximum allowed weight for a block, see BIP 141 (network rule) */
pub const MAX_BLOCK_WEIGHT: usize = 4000000;

/// Maximum pubkeys as arguments to CHECKMULTISIG
// https://github.com/bitcoin/bitcoin/blob/6acda4b00b3fc1bfac02f5de590e1a5386cbc779/src/script/script.h#L30
pub const MAX_PUBKEYS_PER_MULTISIG: usize = 20;
/// Maximum number of scripts allowed by standardness rules in TapTree format
// https://github.com/bitcoin/bitcoin/blob/81f4a3e84d6f30e7b12a9605dabc3359f614da93/src/script/interpreter.h#L229
pub const TAPROOT_MAX_NODE_COUNT: usize = 128;
