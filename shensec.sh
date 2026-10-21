#!/usr/bin/env sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if ! command -v uv >/dev/null 2>&1; then
  echo 'Install uv: https://docs.astral.sh/uv/getting-started/installation/' >&2
  exit 1
fi
exec uv run --locked --extra gui shensec gui "$@"
