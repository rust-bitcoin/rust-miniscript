//! Various functions for manipulating Bitcoin timelocks.

use crate::miniscript::limits::LOCKTIME_THRESHOLD;

/// Returns true if `a` and `b` are the same unit i.e., both are block heights or both are UNIX
/// timestamps. `a` and `b` are nLockTime values.
pub fn absolute_timelocks_are_same_unit(a: u32, b: u32) -> bool {
    n_lock_time_is_block_height(a) == n_lock_time_is_block_height(b)
}

// https://github.com/bitcoin/bitcoin/blob/9ccaee1d5e2e4b79b0a7c29aadb41b97e4741332/src/script/script.h#L39

/// Returns true if nLockTime `n` is to be interpreted as a block height.
pub fn n_lock_time_is_block_height(n: u32) -> bool {
    n < LOCKTIME_THRESHOLD
}

/// Returns true if nLockTime `n` is to be interpreted as a UNIX timestamp.
pub fn n_lock_time_is_timestamp(n: u32) -> bool {
    n >= LOCKTIME_THRESHOLD
}
