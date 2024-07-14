default:
  @just --list

# Cargo build everything.
build:
  cargo build --all-targets --all-features

# Cargo check everything.
check:
  cargo check --all-targets --all-features

# Lint everything.
lint:
  cargo +nightly clippy --all-targets --all-features -- --deny warnings

# Run the formatter.
fmt:
  cargo +nightly fmt

# Check the formatting.
fmt-check:
  cargo +nightly fmt --check

# Run the benchmark suite.
bench:
  RUSTFLAGS='--cfg=bench' cargo +nightly bench

# Build the docs (same as for docs.rs).
docsrs:
  RUSTDOCFLAGS="--cfg docsrs" cargo +nightly rustdoc --all-features -- -D rustdoc::broken-intra-doc-links

# Quick and dirty CI useful for pre-push checks.
sane: fmt-check lint
  cargo test --quiet --all-targets --no-default-features --features > /dev/null || exit 1
  cargo test --quiet --all-targets > /dev/null || exit 1
  cargo test --quiet --all-targets --all-features > /dev/null || exit 1

  # doctests don't get run from workspace root with `cargo test`.
  cargo test --quiet --doc || exit 1

# Update the recent and minimal lock files.
update-lock-files:
  contrib/update-lock-files.sh
