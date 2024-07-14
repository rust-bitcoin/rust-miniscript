#!/usr/bin/env bash
#
# Do pinning as required for current MSRV.

set -euo pipefail

cargo update -p cc --precise 1.0.79
