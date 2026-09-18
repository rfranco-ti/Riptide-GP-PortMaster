#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Run NXExtract with firmware libraries first and game-private libraries out of
# process scope. SDL's inherited backend choice is intentionally preserved.
set -euo pipefail

if [ "$#" -eq 0 ]; then
  printf 'usage: %s COMMAND [ARG ...]\n' "${0##*/}" >&2
  exit 64
fi

nx_runtime_path=
nx_game_root=
nx_game_path=

nx_canonical_dir() {
  local candidate=$1

  if [ -d "$candidate" ]; then
    (CDPATH= cd -- "$candidate" 2>/dev/null && pwd -P) || return 1
  else
    while [ "$candidate" != / ] && [ "${candidate%/}" != "$candidate" ]; do
      candidate=${candidate%/}
    done
    printf '%s\n' "$candidate"
  fi
}

nx_path_is_inside() {
  local root=$1 candidate=$2

  [ -n "$root" ] || return 1
  [ "$root" = / ] && return 0
  case "$candidate" in
    "$root"|"$root"/*) return 0 ;;
    *) return 1 ;;
  esac
}

nx_append_runtime_dir() {
  local candidate=$1 canonical

  [ -n "$candidate" ] || return 0
  case "$candidate" in
    /*) ;;
    *) return 0 ;;
  esac

  nx_path_is_inside "$nx_game_path" "$candidate" && return 0

  canonical=$(nx_canonical_dir "$candidate") || return 0
  nx_path_is_inside "$nx_game_root" "$canonical" && return 0
  case ":$nx_runtime_path:" in
    *":$canonical:"*) return 0 ;;
  esac
  if [ -n "$nx_runtime_path" ]; then
    nx_runtime_path="$nx_runtime_path:$canonical"
  else
    nx_runtime_path=$canonical
  fi
}

nx_append_runtime_list() {
  local remaining=$1 candidate

  while :; do
    case "$remaining" in
      *:*)
        candidate=${remaining%%:*}
        remaining=${remaining#*:}
        ;;
      *)
        candidate=$remaining
        remaining=
        ;;
    esac
    nx_append_runtime_dir "$candidate"
    [ -n "$remaining" ] || break
  done
}

if [ -n "${NXEXTRACT_GAME_DIR:-}" ]; then
  nx_game_path=$NXEXTRACT_GAME_DIR
  case "$nx_game_path" in
    /*) ;;
    *) nx_game_path=$PWD/$nx_game_path ;;
  esac
  while [ "$nx_game_path" != / ] && [ "${nx_game_path%/}" != "$nx_game_path" ]; do
    nx_game_path=${nx_game_path%/}
  done
  nx_game_root=$(nx_canonical_dir "$NXEXTRACT_GAME_DIR") || nx_game_root=
fi

nx_machine=${NXEXTRACT_MACHINE:-$(uname -m 2>/dev/null || printf unknown)}
case "$nx_machine" in
  aarch64|arm64)
    nx_append_runtime_list \
      '/usr/local/lib/aarch64-linux-gnu:/usr/local/lib:/usr/lib/aarch64-linux-gnu:/lib/aarch64-linux-gnu:/usr/lib:/lib'
    ;;
  armv7*|armv8l|armhf|arm)
    nx_append_runtime_list \
      '/usr/local/lib/arm-linux-gnueabihf:/usr/local/lib:/usr/lib/arm-linux-gnueabihf:/lib/arm-linux-gnueabihf:/usr/lib:/lib'
    ;;
  x86_64|amd64)
    nx_append_runtime_list \
      '/usr/local/lib/x86_64-linux-gnu:/usr/local/lib:/usr/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu:/usr/lib:/lib'
    ;;
  i?86|x86)
    nx_append_runtime_list \
      '/usr/local/lib/i386-linux-gnu:/usr/local/lib:/usr/lib/i386-linux-gnu:/lib/i386-linux-gnu:/usr/lib:/lib'
    ;;
  *)
    nx_append_runtime_list '/usr/local/lib:/usr/lib:/lib'
    ;;
esac

# A launcher may add known firmware/PortMaster library directories here. They
# are filtered through the same boundary, so a path inside the game directory
# can never re-enter the extractor environment by this override.
nx_append_runtime_list "${NXEXTRACT_FIRMWARE_LIBRARY_PATH:-}"
nx_append_runtime_list "${LD_LIBRARY_PATH:-}"

export LD_LIBRARY_PATH="$nx_runtime_path"
export NXEXTRACT_RUNTIME_ENV_ACTIVE=1

# The default preserves every inherited SDL selection. A launcher that has
# already proved the inherited backend invalid may explicitly request clean
# SDL autodetection for this child only; no replacement backend is selected.
if [ "${NXEXTRACT_SDL_AUTODETECT:-0}" = 1 ]; then
  unset SDL_VIDEODRIVER SDL_VIDEO_DRIVER SDL_AUDIODRIVER
fi

exec "$@"
