#!/usr/bin/env bash
# Serialize the loopback-port-binding test suites (LLP 0049 §3 rule 9).
#
# `node_net_builtins` (tests/node_net_builtins.rs) and the host-http-server
# suites bind loopback TCP ports and produce FALSE failures when two runs
# overlap (LLP 0046 §4: "a false 4/4 failure that reads as a regression").
# Rule 9's remedy is a repo-local advisory lock taken by the harness, not
# agent discipline: this wrapper acquires a BLOCKING exclusive lock on
# target/.capsec-port-suite.lock and then execs the wrapped command, so the
# lock is held for exactly the command's lifetime and released by the kernel
# on any exit, including SIGKILL (that IS the stale-lock recovery).
#
# macOS ships bash 3.2 and no flock(1). The portable pattern is the one
# scripts/hermes-version.sh already uses: bash opens fd 9 on the lock file
# and Perl's core Fcntl flock(2) locks that inherited open-file description.
# The lock survives the final `exec` because fd 9 is a plain (non-CLOEXEC)
# shell redirection inherited by the command and all its descendants; it is
# released only when every inherited copy of the fd is closed. Metadata
# written into the file is diagnostic only — kernel flock is the authority.
# Same-uid processes that ignore the protocol are outside the trust boundary.
#
# Usage: scripts/with-port-suite-lock.sh <command> [args...]
# Env:   IBEX_PORT_SUITE_LOCK_FILE overrides the lock path (tests only).
#
# @ref LLP 0049#3-construction-rules — rule 9: port-binding suites never run
# in parallel, enforced by this lock in the harness layer, never by rewriting
# the stored recipe/evidence commands (LLP 0039: the stored command is itself
# evidence).
set -uo pipefail

if [ "$#" -lt 1 ]; then
    echo "usage: ${BASH_SOURCE[0]} <command> [args...]" >&2
    exit 2
fi

# Re-entrancy: a wrapped command that (transitively) invokes this wrapper
# again already holds the lock through inherited fd 9; opening a NEW file
# description and blocking on it would deadlock against our own parent.
if [ "${IBEX_PORT_SUITE_LOCK_HELD:-}" = 1 ]; then
    exec "$@"
fi

if ! command -v perl >/dev/null 2>&1; then
    echo "[port-suite-lock] Perl with core Fcntl is required (macOS has no flock(1))." >&2
    exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
lock_file="${IBEX_PORT_SUITE_LOCK_FILE:-$repo_root/target/.capsec-port-suite.lock}"
mkdir -p "$(dirname "$lock_file")" || exit 1

# Append mode: opening must never truncate a file another process has locked
# and written its diagnostic metadata into.
if ! exec 9>>"$lock_file"; then
    echo "[port-suite-lock] Could not open lock file: $lock_file" >&2
    exit 1
fi

# Try without blocking first, purely so waiting is announced with the owner's
# diagnostic metadata; then block for as long as the owner runs.
if ! perl -MFcntl=:flock \
    -e 'exit(flock(STDIN, LOCK_EX | LOCK_NB) ? 0 : 1)' <&9; then
    owner_pid="$(sed -n 's/^pid=//p' "$lock_file" 2>/dev/null | head -n 1 || true)"
    owner_command="$(sed -n 's/^command=//p' "$lock_file" 2>/dev/null | head -n 1 || true)"
    echo "[port-suite-lock] Waiting for port-binding suite run owned by pid ${owner_pid:-unknown} (${owner_command:-unknown})..." >&2
    if ! perl -MFcntl=:flock \
        -e 'flock(STDIN, LOCK_EX) or die "flock: $!\n"' <&9; then
        exec 9>&-
        exit 1
    fi
    echo "[port-suite-lock] Acquired after the prior owner released or exited." >&2
fi

# Truncating the already-locked inode cannot create a second acquisition path.
: >"$lock_file" || { exec 9>&-; exit 1; }
{
    printf 'pid=%s\n' "$$"
    printf 'command=%s\n' "$*"
} >&9 || { exec 9>&-; exit 1; }

IBEX_PORT_SUITE_LOCK_HELD=1
export IBEX_PORT_SUITE_LOCK_HELD
exec "$@"
