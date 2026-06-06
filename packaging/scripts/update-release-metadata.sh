#!/usr/bin/env bash
#
# Update packaging manifests (Homebrew, AUR, RPM) to a released version.
#
# Usage: update-release-metadata.sh <version> <assets-dir>
#
#   <version>     Release version without the leading 'v' (e.g. 0.2.0).
#   <assets-dir>  Directory containing the release '<artifact>.sha256' files
#                 produced by the CI release job.
#
# Reads the per-binary checksums Homebrew needs from <assets-dir> and computes
# the source-tarball checksum AUR/RPM need from the GitHub archive. Idempotent:
# safe to re-run; it rewrites the relevant fields in place regardless of their
# current value.
set -euo pipefail

VERSION="${1:?usage: update-release-metadata.sh <version> <assets-dir>}"
ASSETS_DIR="${2:?usage: update-release-metadata.sh <version> <assets-dir>}"
REPO="${BATIN_REPO:-ahmeddwalid/batin}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

sha_for() {
	local asset="$1"
	local file="${ASSETS_DIR}/${asset}.sha256"
	if [[ ! -f "$file" ]]; then
		echo "error: missing checksum file: $file" >&2
		exit 1
	fi
	awk '{print $1}' "$file"
}

linux_x86=$(sha_for batin-linux-x86_64)
linux_arm=$(sha_for batin-linux-aarch64)
mac_x86=$(sha_for batin-macos-x86_64)
mac_arm=$(sha_for batin-macos-aarch64)

src_url="https://github.com/${REPO}/archive/v${VERSION}.tar.gz"
if [[ -n "${BATIN_SRC_SHA:-}" ]]; then
	src_sha="$BATIN_SRC_SHA"
else
	echo "Fetching source tarball checksum from ${src_url}" >&2
	src_sha=$(curl -fsSL "$src_url" | sha256sum | awk '{print $1}')
fi

# --- Homebrew formula: version + per-platform sha256 (line after each url) ---
formula="${REPO_ROOT}/Formula/batin.rb"
sed -i -E "s/^(  version )\"[^\"]*\"/\1\"${VERSION}\"/" "$formula"
sed -i -E "/batin-linux-x86_64\"/{n;s/sha256 \"[^\"]*\"/sha256 \"${linux_x86}\"/}" "$formula"
sed -i -E "/batin-linux-aarch64\"/{n;s/sha256 \"[^\"]*\"/sha256 \"${linux_arm}\"/}" "$formula"
sed -i -E "/batin-macos-x86_64\"/{n;s/sha256 \"[^\"]*\"/sha256 \"${mac_x86}\"/}" "$formula"
sed -i -E "/batin-macos-aarch64\"/{n;s/sha256 \"[^\"]*\"/sha256 \"${mac_arm}\"/}" "$formula"

# --- AUR PKGBUILD: pkgver + source tarball sha256 ---
pkgbuild="${REPO_ROOT}/packaging/aur/PKGBUILD"
sed -i -E "s/^pkgver=.*/pkgver=${VERSION}/" "$pkgbuild"
sed -i -E "s/^sha256sums=\('[^']*'\)/sha256sums=('${src_sha}')/" "$pkgbuild"

# --- AUR .SRCINFO: pkgver, source line, sha256 ---
srcinfo="${REPO_ROOT}/packaging/aur/.SRCINFO"
sed -i -E "s/^(\tpkgver = ).*/\1${VERSION}/" "$srcinfo"
sed -i -E "s|(\tsource = [^=]*-)[0-9][^.]*[^:]*(\.tar\.gz::.*archive/v)[^.]*[^/]*(\.tar\.gz)|\1${VERSION}\2${VERSION}\3|" "$srcinfo"
sed -i -E "s/^(\tsha256sums = ).*/\1${src_sha}/" "$srcinfo"

# --- RPM spec: Version + changelog entry ---
spec="${REPO_ROOT}/packaging/rpm/batin.spec"
sed -i -E "s/^(Version:[[:space:]]+).*/\1${VERSION}/" "$spec"
if ! grep -q "\- ${VERSION}-1$" "$spec"; then
	changelog_date="$(date '+%a %b %d %Y')"
	entry="* ${changelog_date} Ahmed Walid <devahmedwalid@proton.me> - ${VERSION}-1\n- Release ${VERSION}\n"
	awk -v entry="$entry" '
		/^%changelog/ { print; printf entry; next }
		{ print }
	' "$spec" >"${spec}.tmp" && mv "${spec}.tmp" "$spec"
fi

echo "Updated packaging manifests to v${VERSION}" >&2
