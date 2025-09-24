# Fuzzing

`miniscript` has a fuzzing harness setup for use with cargo-fuzz.

To run the fuzz-tests as in CI -- briefly fuzzing every target -- simply
run

    RUSTUP_TOOLCHAIN=nightly ./fuzz.sh

in this directory.

You need a nightly compiler to run the fuzz tests. You will also need
`cargo-fuzz` installed:

    cargo install --force cargo-fuzz

## Fuzzing with weak cryptography

You may wish to replace the hashing and signing code with broken crypto,
which will be faster and enable the fuzzer to do otherwise impossible
things such as forging signatures or finding preimages to hashes.

Doing so may result in spurious bug reports since the broken crypto does
not respect the encoding or algebraic invariants upheld by the real crypto. We
would like to improve this but it's a nontrivial problem -- though not
beyond the abilities of a motivated student with a few months of time.
Please let us know if you are interested in taking this on!

Meanwhile, to use the broken crypto, simply compile (and run the fuzzing
scripts) with

    RUSTFLAGS="--cfg=hashes_fuzz --cfg=secp256k1_fuzz"

which will replace the hashing library with broken hashes, and the
secp256k1 library with broken cryptography.

Needless to say, NEVER COMPILE REAL CODE WITH THESE FLAGS because if a
fuzzer can break your crypto, so can anybody.

## Long-term fuzzing

To see the full list of targets, the most straightforward way is to run

    source ./fuzz-util.sh
    listTargetNames

To run each of them for an hour, run

    ./cycle.sh

To run a single fuzztest indefinitely, run

    cargo +nightly fuzz run <target>

`cycle.sh` uses the `chrt` utility to try to reduce the priority of the
jobs. If you would like to run for longer, the most straightforward way
is to edit `cycle.sh` before starting. To run the fuzz-tests in parallel,
you will need to implement a custom harness.

## Adding fuzz tests

All fuzz tests can be found in the `fuzz_target/` directory. Adding a new
one is as simple as copying an existing one and editing the `do_test`
function to do what you want.

If you need to add dependencies, edit the file `generate-files.sh` to add
it to the generated `Cargo.toml`.

Once you've added a fuzztest, regenerate the `Cargo.toml` and CI job by
running

    ./generate-files.sh

Then to test your fuzztest, run

    ./fuzz.sh <target>

If it is working, you will see a rapid stream of data for many seconds
(you can hit Ctrl+C to stop it early). If not, you should quickly see
an error.

## Computing code coverage

Compute the code coverage of the corpus of a given target using the following command:

```bash
cargo fuzz coverage TARGET
```

Generate a human-readable HTML coverage report using a command as below. _The exact paths might differ depending on the target architecture._

The demangler `rustfilt` must be installed.

```bash
cargo cov -- show -Xdemangler=rustfilt target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/TARGET -instr-profile=fuzz/coverage/TARGET/coverage.profdata -show-line-counts-or-regions -show-instantiations --format html --output-dir=OUTPUT_DIR -ignore-filename-regex="\.cargo"
```

More information is available in the [rustc book](https://doc.rust-lang.org/stable/rustc/instrument-coverage.html#running-the-instrumented-binary-to-generate-raw-coverage-profiling-data).

## Reproducing and Minimizing Failures

(todo -- wait for some failures to happen before filling in this section)
