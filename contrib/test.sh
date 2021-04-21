#!/bin/sh -ex

FEATURES="compiler use-serde rand"

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
# run all examples
run-parts ./target/debug/examples

# Bench if told to
if [ "$DO_BENCH" = true ]
then
    cargo bench --features="unstable compiler"
fi
