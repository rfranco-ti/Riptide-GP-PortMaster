#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
GAME_DIR="${NXEXTRACT_GAME_DIR:-$SCRIPT_DIR}"
RECIPE="${NXEXTRACT_RECIPE:-$GAME_DIR/extractor.json}"
PYTHON_BIN="${NXEXTRACT_PYTHON:-python3}"
RUNTIME_HELPER="$SCRIPT_DIR/nxextract-runtime-env.sh"

if [ "${NXEXTRACT_RUNTIME_ENV_ACTIVE:-0}" != 1 ]; then
  [ -f "$RUNTIME_HELPER" ] || {
    printf 'NXExtract: runtime helper is missing: %s\n' \
      "$RUNTIME_HELPER" >&2
    exit 1
  }
  export NXEXTRACT_GAME_DIR="$GAME_DIR"
  # Package extraction must not depend on ZIP tools preserving executable
  # mode bits. Run both shell files explicitly through bash; the helper still
  # creates the isolated child environment before re-entering this launcher.
  exec bash "$RUNTIME_HELPER" bash "$SCRIPT_DIR/run-extractor.sh" "$@"
fi

reuse_args=()
case "${NXEXTRACT_REUSE_ONLY:-0}" in
  0|'') ;;
  1) reuse_args=(--reuse-only) ;;
  *)
    printf 'NXExtract: NXEXTRACT_REUSE_ONLY must be 0 or 1\n' >&2
    exit 64
    ;;
esac

seal_args=()
if [[ -n ${NXEXTRACT_EXPECT_CONTENT_SEAL:-} ]]; then
  if [[ ! ${NXEXTRACT_EXPECT_CONTENT_SEAL} =~ ^[0-9a-fA-F]{64}$ ]]; then
    printf 'NXExtract: NXEXTRACT_EXPECT_CONTENT_SEAL must be 64 hexadecimal characters\n' >&2
    exit 64
  fi
  seal_args=(--expected-content-seal "${NXEXTRACT_EXPECT_CONTENT_SEAL,,}")
fi

exec "$PYTHON_BIN" "$SCRIPT_DIR/nxextract.py" install \
  --recipe "$RECIPE" \
  --game-dir "$GAME_DIR" \
  --require-ui \
  "${reuse_args[@]}" \
  "${seal_args[@]}" \
  "$@"
