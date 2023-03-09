#!/bin/sh -ex

set -e

FEATURES="compiler serde rand"

cargo update -p serde --precise 1.0.142
cargo update -p serde_derive --precise 1.0.142

cargo --version
rustc --version

# Work out if we are using a nightly toolchain.
MSRV=false
if cargo --version | grep "1\.41\.0"; then
    MSRV=true
fi

if cargo --version | grep "1\.47\.0"; then
    cargo update -p once_cell --precise 1.13.1
fi

# form_urlencoded 1.1.0 breaks MSRV.
if [ "$MSRV" = true ]; then
    cargo update -p url --precise 2.2.2
    cargo update -p form_urlencoded --precise 1.0.1
    cargo update -p once_cell --precise 1.13.1
    cargo update -p syn --precise 1.0.107
fi

# Format if told to
if [ "$DO_FMT" = true ]
then
    rustup component add rustfmt
    cargo fmt --all -- --check
fi

# Fuzz if told to
if [ "$DO_FUZZ" = true ]
then
    cd fuzz
    cargo test --verbose
    ./travis-fuzz.sh

    # Exit out of the fuzzer, do not run other tests.
    exit 0
fi

# Defaults / sanity checks
cargo test

if [ "$DO_FEATURE_MATRIX" = true ]
then
    # All features
    cargo test --features="$FEATURES"

    # Single features
    for feature in ${FEATURES}
    do
        cargo test --features="$feature"
    done

    # Run all the examples
    cargo build --examples
    cargo run --example htlc --features=compiler
    cargo run --example parse
    cargo run --example sign_multisig
    cargo run --example verify_tx > /dev/null
    cargo run --example psbt
    cargo run --example xpub_descriptors
    cargo run --example taproot --features=compiler
    cargo run --example psbt_sign_finalize
fi

if [ "$DO_NO_STD" = true ]
then
  # Build no_std, to make sure that cfg(test) doesn't hide any issues
  cargo build --verbose --no-default-features --features="no-std"

  # Test no_std
  cargo test --verbose --no-default-features --features="no-std"

  # Build all features
  cargo build --verbose --no-default-features --features="no-std $FEATURES"

  # Build specific features
  for feature in ${FEATURES}
  do
      cargo build --verbose --no-default-features --features="no-std $feature"
  done
fi

# Bench if told to (this only works with the nightly toolchain)
if [ "$DO_BENCH" = true ]
then
    cargo bench --features="unstable compiler"
fi

# Build the docs if told to (this only works with the nightly toolchain)
if [ "$DO_DOCS" = true ]; then
    RUSTDOCFLAGS="--cfg docsrs" cargo doc --all --features="$FEATURES"
fi

exit 0
