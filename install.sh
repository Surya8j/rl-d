#!/usr/bin/env bash
#
# rl-d installer — puts an `rl-d` command on your PATH.
# Prefers pipx (isolated); falls back to a local venv + symlink.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${HOME}/.local/bin"

say() { printf '  %s\n' "$*"; }

if command -v pipx >/dev/null 2>&1; then
    say "Installing rl-d via pipx…"
    pipx install --force "${SCRIPT_DIR}"
    pipx ensurepath >/dev/null 2>&1 || true
    say ""
    say "✔ Installed.  Run:  rl-d --help"
    say "  (open a new terminal if 'rl-d' isn't found yet)"
else
    say "pipx not found — installing into a local venv + symlink…"
    VENV="${HOME}/.local/share/rl-d/venv"
    mkdir -p "${BIN}"
    python3 -m venv "${VENV}"
    "${VENV}/bin/pip" install -q --upgrade pip
    "${VENV}/bin/pip" install -q "${SCRIPT_DIR}"
    ln -sf "${VENV}/bin/rl-d" "${BIN}/rl-d"
    say ""
    say "✔ Installed to ${BIN}/rl-d"
    case ":${PATH}:" in
        *":${BIN}:"*) ;;
        *) say "⚠ Add ${BIN} to your PATH, then reopen your shell:"
           say "    echo 'export PATH=\"${BIN}:\$PATH\"' >> ~/.zshrc" ;;
    esac
    say "  Run:  rl-d --help"
fi
