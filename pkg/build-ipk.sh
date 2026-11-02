#!/bin/sh
# Builds wg-obfuscator-keenetic_<ver>_<arch>.ipk for Entware on Keenetic.
#   ./pkg/build-ipk.sh [mipsel-3.4|mips-3.4|aarch64-3.10]   (default: all)
# Needs: go >= 1.24, curl, tar, gzip.
set -eu

OBF_VER=1.6
PKG_REL=4
PANEL_VER=1.2.0
PKG=wg-obfuscator-keenetic
VERSION="${OBF_VER}-${PKG_REL}"

HERE=$(cd "$(dirname "$0")" && pwd)
PANEL_SRC="$HERE/../panel"
OUT="$HERE/out"
mkdir -p "$OUT"

# Entware arch -> wg-obfuscator release asset, Go target. Keenetic SoCs have no
# FPU, so MIPS builds are soft-float.
arch_info() {
	case "$1" in
	mipsel-3.4)   echo "mipsel-mips32-sf mipsle softfloat" ;;
	mips-3.4)     echo "mips-mips32-sf mips softfloat" ;;
	aarch64-3.10) echo "arm64 arm64 -" ;;
	*) echo "unknown arch: $1" >&2; exit 1 ;;
	esac
}

build_one() {
	ARCH=$1
	set -- $(arch_info "$ARCH")
	OBF_ASSET=$1 GOARCH_=$2 GOMIPS_=$3
	WORK="$HERE/work/$ARCH"
	rm -rf "$WORK" && mkdir -p "$WORK/data" "$WORK/ctrl" "$WORK/dl"

	# 1. Obfuscator: official static build from the wg-obfuscator releases.
	curl -fsSL -o "$WORK/dl/obf.tar.gz" \
		"https://github.com/ClusterM/wg-obfuscator/releases/download/v${OBF_VER}/wg-obfuscator-v${OBF_VER}-linux-${OBF_ASSET}.tar.gz"
	tar -xzf "$WORK/dl/obf.tar.gz" -C "$WORK/dl"

	# 2. Panel: static Go binary.
	if [ "$GOMIPS_" = "-" ]; then GOMIPS_=""; fi
	( cd "$PANEL_SRC" && CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH_" GOMIPS="$GOMIPS_" \
		go build -trimpath -ldflags "-s -w -X main.panelVersion=${PANEL_VER}" -o "$WORK/dl/wg-obfuscator-panel" . )

	# 3. Data tree.
	D="$WORK/data"
	install -d "$D/opt/bin" "$D/opt/etc/init.d" "$D/opt/share/wg-obfuscator"
	install -m 0755 "$WORK/dl/wg-obfuscator/wg-obfuscator" "$D/opt/bin/wg-obfuscator"
	install -m 0755 "$WORK/dl/wg-obfuscator-panel"        "$D/opt/bin/wg-obfuscator-panel"
	install -m 0755 "$HERE/files/S99wg-obfuscator"         "$D/opt/etc/init.d/S99wg-obfuscator"
	install -m 0755 "$HERE/files/S98wg-obfuscator-panel"   "$D/opt/etc/init.d/S98wg-obfuscator-panel"
	install -m 0644 "$HERE/files/wg-obfuscator.conf.example" "$D/opt/share/wg-obfuscator/wg-obfuscator.conf.example"
	install -m 0644 "$WORK/dl/wg-obfuscator/LICENSE"        "$D/opt/share/wg-obfuscator/LICENSE"
	install -m 0644 "$WORK/dl/wg-obfuscator/README.md"      "$D/opt/share/wg-obfuscator/README.md"
	SIZE=$(du -sb "$D" | cut -f1)

	# 4. Control files.
	cat > "$WORK/ctrl/control" <<CTRL
Package: $PKG
Version: $VERSION
Section: net
Architecture: $ARCH
Installed-Size: $SIZE
Maintainer: Artt652
License: GPL-3.0
URL: https://github.com/artt652/wg-obfuscator-keenetic
Description: WireGuard Obfuscator v${OBF_VER} by ClusterM with a web panel
 for Keenetic routers (Entware). Panel ${PANEL_VER}: settings form, import of
 the server config, start/stop/restart, log viewer, WireGuard status and MTU.
CTRL
	install -m 0755 "$HERE/control/preinst"  "$WORK/ctrl/preinst"
	install -m 0755 "$HERE/control/postinst" "$WORK/ctrl/postinst"
	install -m 0755 "$HERE/control/prerm"    "$WORK/ctrl/prerm"
	echo "2.0" > "$WORK/debian-binary"

	# 5. Pack the way Entware does: tar.gz of debian-binary, data, control.
	TAR_OPTS="--owner=0 --group=0 --numeric-owner --sort=name --mtime=@${SOURCE_DATE_EPOCH:-$(date +%s)}"
	( cd "$WORK/ctrl" && tar $TAR_OPTS -czf "$WORK/control.tar.gz" ./ )
	( cd "$WORK/data" && tar $TAR_OPTS -czf "$WORK/data.tar.gz" ./ )
	IPK="$OUT/${PKG}_${VERSION}_${ARCH}.ipk"
	( cd "$WORK" && tar $TAR_OPTS -czf "$IPK" ./debian-binary ./data.tar.gz ./control.tar.gz )
	echo "Built: $IPK ($(du -h "$IPK" | cut -f1))"
}

ARCHES=${1:-"mipsel-3.4 mips-3.4 aarch64-3.10"}
for a in $ARCHES; do build_one "$a"; done
