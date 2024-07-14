# No shebang, this file should not be executed.
# shellcheck disable=SC2148
#
# disable verify unused vars, despite the fact that they are used when sourced
# shellcheck disable=SC2034

# Crates in this workspace to test (excl. fuzz an integration-tests).
CRATES=(".")                    # Non-workspaces don't have crates.
