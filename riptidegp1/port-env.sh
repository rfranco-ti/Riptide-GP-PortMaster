#!/usr/bin/env bash
# Riptide GP1 — port-env.sh (NextOS runtime hook, fork BB1 + fixes BBR2)
# Hook por-port: descoberta de controles + perfil ultra-low único (512MB e 1GB).
# Tudo aqui é best-effort e isolado ao port: nunca aborta o launch (|| true),
# nunca toca no sistema de forma persistente.

# Bind runtime evidence to the launcher's selected immutable generation.
if [ -n "${NXBOOTSTRAP_HEALTH_GENERATION:-}" ]; then
  export NX_GENERATION="$NXBOOTSTRAP_HEALTH_GENERATION"
fi
export NX_PORT_ID=riptidegp1
export NX_PORT_VERSION=1.0.3

# --- Controller discovery (BBR2-style SDL2->SDL3 staging, renomeado RGP) ---
if [ -z "${SDL_GAMECONTROLLERCONFIG_FILE:-}" ] &&
   [ -n "${controlfolder:-}" ]; then
  for nx_rgp_db in \
    "$controlfolder/gamecontrollerdb.txt" \
    "$controlfolder/gamecontrollerdb-SDL2.txt"; do
    if [ -f "$nx_rgp_db" ] && [ -r "$nx_rgp_db" ] && [ ! -L "$nx_rgp_db" ]; then
      export SDL_GAMECONTROLLERCONFIG_FILE="$nx_rgp_db"
      break
    fi
  done
fi

if [ -z "${SDL_GAMECONTROLLERCONFIG_FILE:-}" ]; then
  for nx_rgp_db in \
    /opt/system/Tools/PortMaster/gamecontrollerdb.txt \
    /roms/ports/PortMaster/gamecontrollerdb.txt \
    /roms2/ports/PortMaster/gamecontrollerdb.txt \
    /storage/.config/SDL-GameControllerDB/gamecontrollerdb.txt \
    /usr/share/SDL2/gamecontrollerdb.txt; do
    [ -n "$nx_rgp_db" ] || continue
    if [ -f "$nx_rgp_db" ] && [ -r "$nx_rgp_db" ] && [ ! -L "$nx_rgp_db" ]; then
      export SDL_GAMECONTROLLERCONFIG_FILE="$nx_rgp_db"
      break
    fi
  done
fi

case "${RGP_INPUT_TRACE:-0}" in
  0|1) ;;
  *) unset RGP_INPUT_TRACE ;;
esac

unset RGP_PORTMASTER_CONTROLLERCONFIG
if [ -n "${SDL_GAMECONTROLLERCONFIG:-}" ]; then
  # SDL3 loads SDL_GAMECONTROLLERCONFIG at USER priority; stage outside SDL
  # so the adapter registers the measured per-instance SDL3 form before the
  # guest first classifies the device (fix herdado do BBR2).
  export RGP_PORTMASTER_CONTROLLERCONFIG="$SDL_GAMECONTROLLERCONFIG"
  unset SDL_GAMECONTROLLERCONFIG
  echo "[input] mapping source=PortMaster-inline staged=SDL3-instance"
elif [ -n "${SDL_GAMECONTROLLERCONFIG_FILE:-}" ]; then
  echo "[input] mapping source=firmware-database"
else
  echo "[input] mapping source=SDL-builtin"
fi

unset nx_rgp_db

# --- Riptide GP1 ultra-low: identidade + hints (lidos pelo loader quando suportado) ---
# Stick direito 100% nativo para manobras: nenhuma variável de cursor/mouse aqui.
export RGP_QUALITY=low
export RGP_RENDER_SCALE=0.66
export RGP_WATER=low
export RGP_FOAM=low
export RGP_SPRAY=low
export RGP_REFLECTIONS=0
export RGP_TRANSITIONS=fast
export RGP_TARGET_FPS=30
export RGP_AUDIO_RATE=22050

# SDL: NÃO fixar SDL_VIDEODRIVER — a SDL3 bundlada prova KMSDRM / Wayland /
# mali-fbdev em runtime e escolhe o funcional (a variável aceita UM driver só;
# uma lista separada por vírgula invalida a seleção e dá tela preta).
# Respeita herança do CFW; só garante fallback seguro quando ausente.
if [ -n "${SDL_VIDEODRIVER:-}" ]; then
  echo "[video] SDL_VIDEODRIVER herdado=${SDL_VIDEODRIVER}"
else
  echo "[video] SDL_VIDEODRIVER=auto (KMSDRM/Wayland/mali-fbdev por prova)"
fi
export SDL_HINT_VIDEO_MINIMIZE_ON_FOCUS_LOSS=0
export SDL_HINT_JOYSTICK_ALLOW_BACKGROUND_EVENTS=1

# Áudio: buffer maior evita XRUN em 512MB; FMOD bridge negocia S16.
export SDL_HINT_AUDIO_DEVICE_SAMPLE_FRAMES=2048

# --- Ultra-low de sistema (sessão apenas, sem persistência, nunca fatal) ---
{
  RGP_MEMKB=$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null)
  case "${RGP_MEMKB:-}" in ''|*[!0-9]*) RGP_MEMKB=0 ;; esac
  if [ "$RGP_MEMKB" -gt 0 ] && [ "$RGP_MEMKB" -lt 700000 ]; then
    echo "[perf] RAM detectada ~512MB (MemTotal=${RGP_MEMKB}kB): perfil ultra-low"
  elif [ "$RGP_MEMKB" -gt 0 ]; then
    echo "[perf] RAM detectada ~1GB (MemTotal=${RGP_MEMKB}kB): perfil ultra-low único"
  else
    echo "[perf] RAM desconhecida: perfil ultra-low único"
  fi

  # Governors CPU -> performance (sessão; frontend/CFW gerencia após sair).
  for rgp_cpu in /sys/devices/system/cpu/cpu[0-3]/cpufreq/scaling_governor; do
    [ -w "$rgp_cpu" ] || continue
    if command -v "$ESUDO" >/dev/null 2>&1; then
      $ESUDO sh -c "echo performance > '$rgp_cpu'" 2>/dev/null || true
    else
      echo performance > "$rgp_cpu" 2>/dev/null || true
    fi
  done

  # GPU Mali: tentar performance onde exposto (panfrost/mali), sem falhar.
  for rgp_gpu in /sys/class/devfreq/*gpu*/governor /sys/devices/platform/*gpu*/devfreq/*/governor; do
    [ -w "$rgp_gpu" ] || continue
    if command -v "$ESUDO" >/dev/null 2>&1; then
      $ESUDO sh -c "echo performance > '$rgp_gpu'" 2>/dev/null || true
    else
      echo performance > "$rgp_gpu" 2>/dev/null || true
    fi
  done

  # zram: se já existe e está pequeno, tenta aliviar swap pressure da sessão.
  # Não recria dispositivos nem persiste nada; só ajusta swappiness temporário.
  if [ -w /proc/sys/vm/swappiness ]; then
    if command -v "$ESUDO" >/dev/null 2>&1; then
      $ESUDO sh -c "echo 150 > /proc/sys/vm/swappiness" 2>/dev/null || true
    else
      echo 150 > /proc/sys/vm/swappiness 2>/dev/null || true
    fi
    echo "[perf] swappiness=150 (sessão, zram-first)"
  fi

  # Cache pressure baixa mantém texturas/APF em RAM em vez de reclaim agressivo.
  if [ -w /proc/sys/vm/vfs_cache_pressure ]; then
    if command -v "$ESUDO" >/dev/null 2>&1; then
      $ESUDO sh -c "echo 50 > /proc/sys/vm/vfs_cache_pressure" 2>/dev/null || true
    else
      echo 50 > /proc/sys/vm/vfs_cache_pressure 2>/dev/null || true
    fi
  fi

  # Sincroniza e libera pagecache ANTES do jogo (não durante): mais RAM livre p/ Base.apf.
  sync 2>/dev/null || true
  if [ -w /proc/sys/vm/drop_caches ]; then
    if command -v "$ESUDO" >/dev/null 2>&1; then
      $ESUDO sh -c "echo 1 > /proc/sys/vm/drop_caches" 2>/dev/null || true
    else
      echo 1 > /proc/sys/vm/drop_caches 2>/dev/null || true
    fi
  fi

  unset RGP_MEMKB rgp_cpu rgp_gpu
} || true

# --- Diagnóstico de boot (sempre ativo, barato, cai no log.txt) ---
# Serve para localizar tela preta: cada estágio deixa recibo no log.
{
  echo "[rgp-stage] port-env ok cfw=${CFW_NAME:-none} kernel=$(uname -r 2>/dev/null) arch=$(uname -m 2>/dev/null)"
  echo "[rgp-stage] dri=$(ls /dev/dri 2>/dev/null | tr '\n' ' ') fb0=$([ -e /dev/fb0 ] && echo yes || echo no) uinput=$([ -e /dev/uinput ] && echo yes || echo no)"
  for rgp_lib in libGLESv2.so libGLESv2.so.2 libEGL.so libEGL.so.1 libmali.so libGLES_mali.so libdrm.so.2 libz.so.1; do
    rgp_found=$(ldconfig -p 2>/dev/null | grep -m1 -F "$rgp_lib" || true)
    [ -n "$rgp_found" ] || rgp_found=$(find /usr/lib /lib /usr/local/lib /opt -maxdepth 4 -name "$rgp_lib" 2>/dev/null | head -n 1 || true)
    echo "[rgp-stage] lib $rgp_lib => ${rgp_found:-MISSING}"
  done
  echo "[rgp-stage] gamedata libmain=$([ -s "$GAMEDIR/gamedata/lib/arm64-v8a/libmain.so" ] && echo ok || echo MISSING) base=$([ -s "$GAMEDIR/gamedata/assets/Base.apf" ] && echo ok || echo MISSING)"
  unset rgp_lib rgp_found
} || true

unset nx_bb_db 2>/dev/null || true
