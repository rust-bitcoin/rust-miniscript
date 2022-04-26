#!/bin/sh -ex

FEATURES="compiler use-serde rand"

# Use toolchain if explicitly specified
if [ -n "$TOOLCHAIN" ]
then
    alias cargo="cargo +$TOOLCHAIN"
fi

# Lint if told to
if [ "$DO_FMT" = true ]
then
    (
        rustup component add rustfmt
        cargo fmt --all -- --check
    )
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

# Test without any features first
cargo test --verbose

# Test each feature
for feature in ${FEATURES}
do
    cargo test --verbose --features="$feature"
done

# Also build and run each example to catch regressions
cargo build --examples

EXAMPLES="parse psbt sign_multisig verify_tx xpub_descriptors"
for example in ${EXAMPLES}
do
    cargo run --example $example
done
cargo run --example htlc --features=compiler

# Bench if told to
if [ "$DO_BENCH" = true ]
then
    cargo bench --features="unstable compiler"
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
