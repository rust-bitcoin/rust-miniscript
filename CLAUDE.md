# Migration Guide: Upgrading to bitcoin v0.33.0-beta.0

This guide helps downstream projects migrate from bitcoin v0.32.x to v0.33.0-beta.0.

## Overview

Bitcoin v0.33.0-beta.0 represents a significant update with multiple breaking changes. The primary goals of this release are:

1. Facilitate testing of `primitives 1.0.0-rc.x` and upcoming 1.0 releases
2. Prepare for 1.0 releases of core dependencies:
   - `bitcoin-io` (1.0)
   - `primitives` (1.0)
   - `units` (1.0)

## Dependency Version Updates

Update your `Cargo.toml` dependencies:

```toml
[dependencies]
bitcoin = "0.33.0-beta.0"
```

## Breaking Changes & Migration Steps

### 1. Secp256k1 Context Changes

**What Changed:** The secp256k1 crate removed context types from public API. Functions like `generate_keypair` are now available at the crate level.

**Migration:**

```rust
// Before (v0.32.x)
use secp256k1::Secp256k1;
let secp = Secp256k1::new();
let (secret_key, public_key) = secp.generate_keypair(&mut rng);

// After (v0.33.0)
use secp256k1;
let (secret_key, public_key) = secp256k1::generate_keypair(&mut rng);

// For Schnorr signatures
// Before
let sig = secp.sign_schnorr_with_aux_rand(&msg, &keypair, &aux_rand);

// After
use secp256k1::schnorr;
let sig = schnorr::sign_no_aux_rand(&msg, &keypair);  // Or use aux_rand variant if needed
```

### 2. Transaction Default Implementations Removed

**What Changed:** `TxOut::default()`, `OutPoint::default()`, and `TxIn::default()` removed to prevent misuse.

**Migration:**

```rust
// Before
let prevout = OutPoint::default();
let input = TxIn::default();

// After - Use semantic constants
use bitcoin::OutPoint;
let prevout = OutPoint::COINBASE_PREVOUT;  // For coinbase inputs
let input = TxIn::EMPTY_COINBASE;           // For coinbase transactions

// For regular outputs, explicitly construct:
let txout = TxOut {
    value: Amount::ZERO,
    script_pubkey: ScriptBuf::new(),
};
```

### 3. Amount Module Reorganization

**What Changed:** The `amount` module was reorganized and moved to the `units` crate.

**Migration:**

```rust
// Imports may need updating
use bitcoin::Amount;
use bitcoin::SignedAmount;

// Amount::MAX_MONEY constant handling
// Check your usage - this constant may have changed/moved
```

### 4. Script Type Tagging (MAJOR BREAKING CHANGE)

**What Changed:** The generic `Script` and `ScriptBuf` types no longer exist. Scripts are now tagged by their purpose, requiring you to specify the exact script type. This provides better type safety and prevents misuse of scripts in the wrong context.

**Available Script Types:**

Borrowed (reference) types:
- `ScriptPubKey` - Script public key (locking script in outputs)
- `ScriptSig` - Script signature (unlocking script in inputs)
- `RedeemScript` - P2SH redeem script
- `WitnessScript` - Segwit v0 witness script
- `TapScript` - Taproot (Segwit v1) script

Owned types (similar to the old `ScriptBuf`):
- `ScriptPubKeyBuf`
- `ScriptSigBuf`
- `RedeemScriptBuf`
- `WitnessScriptBuf`
- `TapScriptBuf`

**Migration:**

The correct script type is usually obvious from context - check variable names, function parameter names, struct field names, or code comments to determine which type to use.

```rust
// Before (v0.32.x)
use bitcoin::Script;
use bitcoin::ScriptBuf;

fn process_output_script(script: &Script) {
    // ...
}

let mut script = ScriptBuf::new();

// After (v0.33.0) - Use specific types based on context
use bitcoin::script::{ScriptPubKey, ScriptPubKeyBuf};
use bitcoin::script::{ScriptSig, ScriptSigBuf};

fn process_output_script(script: &ScriptPubKey) {  // Variable name hints at ScriptPubKey
    // ...
}

let mut script_pubkey = ScriptPubKeyBuf::new();
let mut script_sig = ScriptSigBuf::new();
```

**Common Migration Patterns:**

```rust
// Transaction construction
// Before
let txout = TxOut {
    amount: Amount::ZERO,
    script_pubkey: ScriptBuf::new(),  // Generic ScriptBuf
};

// After
let txout = TxOut {
    amount: Amount::ZERO,
    script_pubkey: ScriptPubKeyBuf::new(),  // Tagged as ScriptPubKeyBuf
};

// Transaction input scripts
// Before
let txin = TxIn {
    previous_output: outpoint,
    script_sig: ScriptBuf::new(),  // Generic ScriptBuf
    sequence: Sequence::MAX,
    witness: Witness::new(),
};

// After
let txin = TxIn {
    previous_output: outpoint,
    script_sig: ScriptSigBuf::new(),  // Tagged as ScriptSigBuf
    sequence: Sequence::MAX,
    witness: Witness::new(),
};

// P2SH redeem scripts
// Before
use bitcoin::Script;
let redeem_script: &Script = ...;

// After
use bitcoin::script::RedeemScript;
let redeem_script: &RedeemScript = ...;

// Witness scripts (SegWit v0)
// Before
let witness_script = ScriptBuf::from(...);

// After
use bitcoin::script::WitnessScriptBuf;
let witness_script = WitnessScriptBuf::from(...);

// Taproot scripts
// Before
let tap_script = ScriptBuf::from(...);

// After
use bitcoin::script::TapScriptBuf;
let tap_script = TapScriptBuf::from(...);
```

**How to Choose the Right Type:**

1. **Look at variable/parameter names** - `script_pubkey` → `ScriptPubKey(Buf)`, `script_sig` → `ScriptSig(Buf)`
2. **Check the context** - Output scripts are `ScriptPubKey`, input scripts are `ScriptSig`
3. **Struct field types** - `TxOut::script_pubkey` is `ScriptPubKeyBuf`, `TxIn::script_sig` is `ScriptSigBuf`
4. **Read comments** - Code comments often indicate the script type
5. **Choose borrowed vs owned** - Use borrowed types (`ScriptPubKey`) for references, owned types (`ScriptPubKeyBuf`) for owned data (similar to `&str` vs `String`)

**Import Changes:**

```rust
// Before
use bitcoin::Script;
use bitcoin::ScriptBuf;

// After - Import the specific types you need
use bitcoin::script::{ScriptPubKey, ScriptPubKeyBuf};
use bitcoin::script::{ScriptSig, ScriptSigBuf};
use bitcoin::script::{RedeemScript, RedeemScriptBuf};
use bitcoin::script::{WitnessScript, WitnessScriptBuf};
use bitcoin::script::{TapScript, TapScriptBuf};

// Or import from the root if you prefer
use bitcoin::{ScriptPubKey, ScriptPubKeyBuf};
```

### 5. Script Method Changes

**What Changed:** `read_scriptint` moved from a free function to a method on `PushBytes`.

**Migration:**

```rust
// Before
use bitcoin::blockdata::script::read_scriptint;
let num = read_scriptint(bytes);

// After
use bitcoin::script::PushBytes;
let push_bytes = PushBytes::from(bytes);
let num = push_bytes.read_scriptint();
```

### 6. ECDSA Error Type Changes

**What Changed:** `ecdsa::Error` split into more specific error types.

**Migration:**

```rust
// Before
use bitcoin::ecdsa::Error;

// After - Use specific error types
use bitcoin::ecdsa::DecodeError;      // For Signature::from_slice
use bitcoin::ecdsa::ParseSignatureError;  // For Signature::from_str

// Update error handling accordingly
match signature_result {
    Err(DecodeError::...) => // Handle decode error
    Ok(sig) => // Handle success
}
```

### 7. Hash Method Renames

**What Changed:** `to_raw_hash()` renamed to `to_byte_array()` across hash types.

**Migration:**

```rust
// Before
let bytes = txid.to_raw_hash();

// After
let bytes = txid.to_byte_array();
```

### 8. Base58 Error Handling

**What Changed:** Base58 errors are now "closed" (no more `#[non_exhaustive]`).

**Migration:**

No code changes required, but error matching is now exhaustive:

```rust
// You can now match exhaustively
match result {
    Ok(decoded) => // ...
    Err(base58::Error::InvalidCharacter(c)) => // ...
    Err(base58::Error::InvalidLength) => // ...
    // No need for catch-all anymore
}
```

### 9. Hex Error Imports

**What Changed:** `UnprefixedHexError` moved location.

**Migration:**

```rust
// Before
use bitcoin::error::UnprefixedHexError;

// After
use bitcoin::parse::UnprefixedHexError;
```

### 10. Checked Division Methods Split

**What Changed:** `checked_div_by_weight` split into ceiling and floor versions.

**Migration:**

```rust
// Before
let result = amount.checked_div_by_weight(weight);

// After - Choose the appropriate rounding behavior
let result_floor = amount.checked_div_by_weight_floor(weight);
// or
let result_ceil = amount.checked_div_by_weight_ceil(weight);
```

### 11. Sequence Constants Renamed

**What Changed:** Sequence constant naming clarified, `FINAL` constant added.

**Migration:**

```rust
// Check usage of sequence constants
use bitcoin::Sequence;

// New constant available:
let final_sequence = Sequence::FINAL;
```

### 12. Transaction Version Three Support

**What Changed:** Added `Version::THREE` variant to `transaction::Version`.

**Migration:**

```rust
use bitcoin::transaction::Version;

// Now supports version 3 transactions
let version = Version::THREE;
```

### 13. Locktime API Changes

**What Changed:** `ENABLE_RBF_NO_LOCKTIME` replaced with `ENABLE_LOCKTIME_AND_RBF`.

**Migration:**

```rust
// Before
use bitcoin::transaction::ENABLE_RBF_NO_LOCKTIME;

// After
use bitcoin::transaction::ENABLE_LOCKTIME_AND_RBF;
// Review usage - semantic meaning may have changed
```

### 14. PSBT Encoding Changes

**What Changed:** PSBT keytype now encoded as compact size unsigned integer.

**Migration:**

If you're manually encoding/decoding PSBTs, update your code. For most users using the provided API, this is handled automatically.

### 15. Testnet4 Support

**What Changed:** Support for Testnet4 network added.

**Migration:**

```rust
use bitcoin::Network;

// New network variant available
let network = Network::Testnet4;
```

### 16. Signature Passing Convention

**What Changed:** Signatures and associated types now passed by value instead of reference.

**Migration:**

```rust
// Before
fn verify_signature(sig: &Signature, ...) { }
verify_signature(&signature, ...);

// After
fn verify_signature(sig: Signature, ...) { }
verify_signature(signature, ...);
```

### 17. Key Passing Convention

**What Changed:** Keys now passed by value instead of reference.

**Migration:**

```rust
// Before
fn sign_with_key(key: &PrivateKey) { }

// After
fn sign_with_key(key: PrivateKey) { }
```

### 18. BIP32 Field Rename

**What Changed:** Key field in `Key` renamed to `key_data`.

**Migration:**

```rust
// Before
let key_bytes = extended_key.key;

// After
let key_bytes = extended_key.key_data;
```

### 19. Midstate Method Rename

**What Changed:** `Midstate::into_parts` renamed to `Midstate::to_parts` (since it derives `Copy`).

**Migration:**

```rust
// Before
let parts = midstate.into_parts();

// After
let parts = midstate.to_parts();
```

### 20. Module Path Changes

**What Changed:** Usage of `blockdata` removed from paths.

**Migration:**

```rust
// Before
use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::Transaction;

// After - Also note that generic Script no longer exists (see section 4)
use bitcoin::script::{ScriptPubKey, ScriptPubKeyBuf};  // Use specific script types
use bitcoin::transaction::Transaction;
```

### 21. Denomination Changes

**What Changed:** `Denomination::MilliSatoshi` removed.

**Migration:**

```rust
// MilliSatoshi is not supported in bitcoin amounts
// Use the lightning crates for millisatoshi support
```

### 22. Script Size Limit Changes

**What Changed:** `MAX_SCRIPT_ELEMENT_SIZE` removed.

**Migration:**

```rust
// Before
use bitcoin::blockdata::constants::MAX_SCRIPT_ELEMENT_SIZE;

// After - Use more specific constants
use bitcoin::blockdata::constants::MAX_REDEEM_SCRIPT_SIZE;
// or
use bitcoin::blockdata::constants::MAX_STACK_ELEMENT_SIZE;
```

### 23. TxIdentifier Trait

**What Changed:** New `TxIdentifier` trait added for transaction identification.

**Migration:**

This is an addition, not a breaking change. You can now use:

```rust
use bitcoin::transaction::TxIdentifier;

// Trait provides unified interface for Txid and Wtxid
```

### 24. BlockHeader Re-export

**What Changed:** `block::Header` now re-exported as `BlockHeader` at crate root.

**Migration:**

```rust
// Before
use bitcoin::block::Header;

// After - Can use shorter import
use bitcoin::BlockHeader;
// Old path still works for compatibility
```

## PSBT Serde Breaking Change (Unreleased)

**Note:** This change is in the unreleased section and may be included in beta.0.

**What Changed:** PSBT serde implementation now contextually uses PSBT binary or base64 encoded formats per BIP-0174.

**Migration:**

Review your PSBT serialization code if using serde. The format will now depend on context:
- Binary format for binary serializers
- Base64 format for text serializers (JSON, etc.)

```rust
// Ensure your serialization/deserialization matches expected format
let psbt: Psbt = serde_json::from_str(&json_str)?;  // Expects base64
let psbt: Psbt = bincode::deserialize(&bytes)?;     // Expects binary
```

## Testing Your Migration

1. **Update dependencies** in Cargo.toml
2. **Run `cargo check`** to identify compilation errors
3. **Address each error** using this guide
4. **Run your test suite** to catch runtime issues
5. **Review deprecation warnings** for future removals
6. **Test with alpha/beta versions** before final release

## Gradual Migration Strategy

If you cannot migrate everything at once:

1. **Update in a feature branch** to isolate changes
2. **Migrate module by module** using conditional compilation if needed
3. **Use type aliases temporarily** to reduce changeset size:
   ```rust
   // Temporary during migration
   type OldAmount = bitcoin::Amount;
   ```
4. **Monitor for additional beta releases** as the API may still evolve

## Getting Help

- **GitHub Issues:** https://github.com/rust-bitcoin/rust-bitcoin/issues
- **API Documentation:** https://docs.rs/bitcoin/0.33.0-alpha.0/bitcoin/ (will update to beta.0)
- **Changelog:** See `bitcoin/CHANGELOG.md` for complete details
- **Dependency Changelogs:**
  - `bitcoin_hashes`: https://github.com/rust-bitcoin/rust-bitcoin/blob/master/hashes/CHANGELOG.md
  - `hex-conservative`: https://github.com/rust-bitcoin/hex-conservative/blob/master/CHANGELOG.md
  - `bitcoin-io`: https://github.com/rust-bitcoin/rust-bitcoin/blob/master/io/CHANGELOG.md
  - `bitcoin-primitives`: https://github.com/rust-bitcoin/rust-bitcoin/blob/master/primitives/CHANGELOG.md
  - `bitcoin-units`: https://github.com/rust-bitcoin/rust-bitcoin/blob/master/units/CHANGELOG.md

## Important Notes

1. **Not a 1.0 Release:** While major dependencies are approaching 1.0, the bitcoin crate itself is still pre-1.0, meaning further breaking changes are possible.

2. **Alpha/Beta Stability:** This is a beta release for testing purposes. Pin your version explicitly if you need stability.

3. **MSRV:** Minimum Supported Rust Version may have changed. Check `Cargo.toml` for current MSRV (currently 1.74.0).

4. **Feature Flags:** Review your feature flag usage as some may have changed or been added.

## Future Plans

The rust-bitcoin project is working toward 1.0 releases of core dependencies. After 0.33.0 is finalized:
- Expect continued API refinement
- More comprehensive documentation
- Stabilization of core interfaces
- Eventually, a 1.0 release of the bitcoin crate itself

Stay updated by watching the repository and reviewing changelogs regularly.
