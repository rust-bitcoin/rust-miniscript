#!/bin/sh

set -ex

FEATURES="compiler serde rand base64"

cargo --version
rustc --version

# Cache the toolchain we are using.
NIGHTLY=false
if cargo --version | grep nightly; then
    NIGHTLY=true
fi

# Format if told to
if [ "$DO_FMT" = true ]
then
    rustup component add rustfmt
    cargo fmt -- --check
fi

# Pin dependencies required to build with Rust 1.48.0
cp Cargo-recent.lock Cargo.lock

# Test bitcoind integration tests if told to (this only works with the stable toolchain)
if [ "$DO_BITCOIND_TESTS" = true ]; then
    cd bitcoind-tests
    BITCOIND_EXE="$(git rev-parse --show-toplevel)/bitcoind-tests/bin/bitcoind" \
    cargo --locked test --verbose

    # Exit integration tests, do not run other tests.
    exit 0
fi

# Defaults / sanity checks
cargo --locked test

if [ "$DO_FEATURE_MATRIX" = true ]
then
    # All features
    cargo --locked test --features="$FEATURES"

    # Single features
    for feature in ${FEATURES}
    do
        cargo --locked test --features="$feature"
    done

    # Run all the examples
    cargo --locked build --examples
    cargo --locked run --example htlc --features=compiler
    cargo --locked run --example parse
    cargo --locked run --example sign_multisig
    cargo --locked run --example verify_tx > /dev/null
    cargo --locked run --example xpub_descriptors
    cargo --locked run --example taproot --features=compiler
    cargo --locked run --example psbt_sign_finalize --features=base64
fi

if [ "$DO_NO_STD" = true ]
then
  # Build no_std, to make sure that cfg(test) doesn't hide any issues
  cargo --locked build --verbose --no-default-features --features="no-std"

  # Test no_std
  cargo --locked test --verbose --no-default-features --features="no-std"

  # Build all features
  cargo --locked build --verbose --no-default-features --features="no-std $FEATURES"

  # Build specific features
  for feature in ${FEATURES}
  do
      cargo --locked build --verbose --no-default-features --features="no-std $feature"
  done
fi

# Bench if told to, only works with non-stable toolchain (nightly, beta).
if [ "$DO_BENCH" = true ]
then
    if [ "$NIGHTLY" = false ]; then
        if [ -n "$RUSTUP_TOOLCHAIN" ]; then
            echo "RUSTUP_TOOLCHAIN is set to a non-nightly toolchain but DO_BENCH requires a nightly toolchain"
        else
            echo "DO_BENCH requires a nightly toolchain"
        fi
        exit 1
    fi
    RUSTFLAGS='--cfg=bench' cargo --locked bench
fi

# Build the docs if told to (this only works with the nightly toolchain)
if [ "$DO_DOCS" = true ]; then
    RUSTDOCFLAGS="--cfg docsrs" cargo +nightly rustdoc --features="$FEATURES" -- -D rustdoc::broken-intra-doc-links
fi

exit 0
