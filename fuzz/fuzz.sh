#!/usr/bin/env bash
set -o errexit # exit immediately if any command fails
set -o xtrace # print trace of executed commands

REPO_DIR=$(git rev-parse --show-toplevel)

# shellcheck source=./fuzz/fuzz-util.sh
source "$REPO_DIR/fuzz/fuzz-util.sh"

# Check that input files are correct Windows file names
checkWindowsFiles

if [ "$1" == "" ]; then
  targetFiles="$(listTargetFiles)"
else
  targetFiles=fuzz_targets/"$1".rs
fi

cargo --version
rustc --version

# Run fuzz target
for targetFile in $targetFiles; do
  targetName=$(targetFileToName "$targetFile")
  cargo-fuzz run "$targetName" -- -max_total_time=30
done
