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

# Lint if told to
if [ "$DO_FMT" = true ]
then
    (
        rustup component add rustfmt
        cargo fmt --all -- --check
    )
fi

# Defaults / sanity checks
cargo build --all
cargo test --all

if [ "$DO_FEATURE_MATRIX" = true ]
then
    # All features
    cargo build --all --no-default-features --features="$FEATURES"
    cargo test --all --no-default-features --features="$FEATURES"
    # Single features
    for feature in ${FEATURES}
    do
        cargo build --all --no-default-features --features="$feature"
        cargo test --all --no-default-features --features="$feature"
    done

    # Also build and run each example to catch regressions
    cargo build --examples

    cargo run --example htlc --features=compiler
    for example in "parse psbt sign_multisig verify_tx xpub_descriptors"
    do
        cargo run --example $example
    done
fi

# Bench if told to
if [ "$DO_BENCH" = true ]
then
    cargo bench --features="unstable compiler"
fi

# Fuzz if told to
if [ "$DO_FUZZ" = true ]
then
    (
        cd fuzz
        cargo test --verbose
        ./travis-fuzz.sh
        # Exit out of the fuzzer,
        # run stable tests in other CI vms
        exit 0
    )
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
