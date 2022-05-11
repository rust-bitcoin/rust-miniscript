#!/bin/sh -ex

set -e

FEATURES="compiler use-serde rand"

# Use toolchain if explicitly specified
if [ -n "$TOOLCHAIN" ]
then
    alias cargo="cargo +$TOOLCHAIN"
fi

cargo --version
rustc --version

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

# Run Integration tests if told so
if [ -n "$BITCOINVERSION" ]; then
    set -e
    cd integration_test
    curl https://bitcoincore.org/bin/bitcoin-core-$BITCOINVERSION/bitcoin-$BITCOINVERSION-x86_64-linux-gnu.tar.gz | tar xvzf - bitcoin-$BITCOINVERSION/bin/bitcoind    # will abort if the check fails.
    sha256sum --check bitcoin-core-$BITCOINVERSION.sha256sum
    export PATH=$PATH:$(pwd)/bitcoin-$BITCOINVERSION/bin
    ./run.sh
    # Cleanups
    rm -rf bitcoin-$BITCOINVERSION
    exit 0
fi
