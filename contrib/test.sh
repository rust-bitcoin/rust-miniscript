#!/bin/sh -ex

FEATURES="compiler serde"

# Use toolchain if explicitly specified
if [ -n "$TOOLCHAIN" ]
then
    alias cargo="cargo +$TOOLCHAIN"
fi

# Lint if told to
if [ "$DO_LINT" = true ]
then
    (
        rustup component add rustfmt
        cargo fmt --all -- --check
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
./target/debug/examples/htlc
./target/debug/examples/parse
./target/debug/examples/sign_multisig
./target/debug/examples/verify_tx

# Fuzz if told to
if [ "$DO_FUZZ" = true ]
then
    (
        cd fuzz
        cargo test --verbose
        ./travis-fuzz.sh
    )
fi

# Miri Checks if told to
# Only supported in nightly
if [ "$DO_MIRI" = true ]
then
    (
        MIRI_NIGHTLY=nightly-$(curl -s https://rust-lang.github.io/rustup-components-history/x86_64-unknown-linux-gnu/miri)
        echo "Installing latest nightly with Miri: $MIRI_NIGHTLY"
        rustup set profile minimal
        rustup default "$MIRI_NIGHTLY"
        rustup component add miri
        cargo miri test -- -- miri_

        # Change back to latest nightly possibly without Miri
        rustup default nightly
    )
fi

# Bench if told to
if [ "$DO_BENCH" = true ]
then
    cargo bench --features="unstable compiler"
fi
