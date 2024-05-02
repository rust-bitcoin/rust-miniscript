#!/usr/bin/env bash
#
# Run the integration tests using the binary in `bitcoind-tests/bin`.

set -euo pipefail

REPO_DIR=$(git rev-parse --show-toplevel)

# Make all cargo invocations verbose.
export CARGO_TERM_VERBOSE=true

BITCOIND_EXE="$REPO_DIR/bitcoind-tests/bin/bitcoind" cargo test --verbose
