//! Macros
//!
//! Macros meant to be used inside the Rust Miniscript library


/// Allows tests to create a miniscript directly from string as
/// `ms_str!("c:or_i(pk({}),pk({}))", pk1, pk2)`
macro_rules! ms_str {
    ($($arg:tt)*) => (Miniscript::<PublicKey, hash160::Hash>::from_str(&format!($($arg)*)).unwrap())
}

/// Allows tests to create a descriptor directly from string as
/// `des_str!("wsh(c:or_i(pk({}),pk({})))", pk1, pk2)`
macro_rules! des_str {
    ($($arg:tt)*) => (Descriptor::<PublicKey, hash160::Hash>::from_str(&format!($($arg)*)).unwrap())
}