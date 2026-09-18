# Riptide GP — PortMaster port for R36S

<p align="center"><a href="https://vectorunit.itch.io/riptide-gp"><img src="cover.png" alt="Riptide GP" width="640"/></a></p>

## English

**Riptide GP** (Vector Unit, first of the series) running natively on aarch64 Linux handhelds via a Linux
so-loader: original ARM64 engine on SDL3 + FMOD, runtime GLES2 resolution.

Tested on R36S with DarkOS EN and DarkOS RE. Other systems and devices require testing.

### Install

1. Unzip into your `ports` folder (`Riptide GP1.sh` + `riptidegp1/`).
2. Get the free APK at <https://vectorunit.itch.io/riptide-gp> and put it in
   `ports/riptidegp1/gamedata/` (any filename works).
3. Open once: it extracts and starts. Done.

Needs: aarch64 CFW (glibc 2.27+), GLES2, ~350MB free on first run, 640x480.

### Controls (100% native gamepad)

Left stick / D-pad: steer · Right stick: stunts ·
`A`: nitro/confirm · `B`: back · `R1`/`R2`: accelerate · `L1`/`L2`: brake ·
`START`: pause · `SELECT+START`: exit.

Reference APK: `RiptideGP_2025.12.11.apk`, package `com.vectorunit.blue.archive`,
52411304 bytes, `arm64-v8a`.

## Português

**Riptide GP** (Vector Unit, primeiro da série) rodando nativo em portáteis aarch64 com CFW via
so-loader Linux: engine ARM64 original em SDL3 + FMOD, resolução GLES2 em runtime.

Testado em R36S com DarkOS EN e DarkOS RE. Outros sistemas e dispositivos requerem teste.

### Instalação

1. Descompacte em `ports/` (`Riptide GP1.sh` + `riptidegp1/`).
2. Baixe o APK grátis em <https://vectorunit.itch.io/riptide-gp> e coloque em
   `ports/riptidegp1/gamedata/` (qualquer nome de arquivo funciona).
3. Abra uma vez: extrai e inicia. Pronto.

Requer: CFW aarch64 (glibc 2.27+), GLES2, ~350MB livres na 1ª vez, 640x480.

### Controles (100% gamepad nativo)

Analógico esquerdo / D-pad: pilotar · Analógico direito: manobras ·
`A`: nitro/confirmar · `B`: voltar · `R1`/`R2`: acelerar · `L1`/`L2`: frear ·
`START`: pausa · `SELECT+START`: sair.

APK de referência: `RiptideGP_2025.12.11.apk`, pacote `com.vectorunit.blue.archive`,
52411304 bytes, `arm64-v8a`.
