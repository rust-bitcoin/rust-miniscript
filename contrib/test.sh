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

# Test without any features first
cargo test --verbose

# Test each feature
for feature in ${FEATURES}
do
    cargo test --verbose --features="$feature"
done

# Also build and run each example to catch regressions
cargo build --examples
# run all examples
run-parts ./target/debug/examples

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
