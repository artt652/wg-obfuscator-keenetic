#!/bin/sh
# Builds an opkg feed from pkg/out: dist/<arch>/{*.ipk,Packages,Packages.gz}.
# Entware on the router then uses: src/gz wg-obfuscator <base-url>/<arch>
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
DIST="$HERE/../dist"
rm -rf "$DIST" && mkdir -p "$DIST"
for ipk in "$HERE"/out/*.ipk; do
	arch=$(basename "$ipk" .ipk | sed 's/.*_//')
	mkdir -p "$DIST/$arch"
	cp "$ipk" "$DIST/$arch/"
done
for dir in "$DIST"/*/; do
	: > "$dir/Packages"
	for ipk in "$dir"*.ipk; do
		tmp=$(mktemp -d)
		( cd "$tmp" && tar -xzf "$ipk" ./control.tar.gz && tar -xzf control.tar.gz ./control )
		sed '/^$/d' "$tmp/control" >> "$dir/Packages"
		{
			echo "Filename: $(basename "$ipk")"
			echo "Size: $(wc -c < "$ipk" | tr -d ' ')"
			echo "SHA256sum: $(sha256sum "$ipk" | cut -d' ' -f1)"
			echo
		} >> "$dir/Packages"
		rm -rf "$tmp"
	done
	gzip -9nc "$dir/Packages" > "$dir/Packages.gz"
done
echo "Feed in $DIST:"; ls -R "$DIST"
