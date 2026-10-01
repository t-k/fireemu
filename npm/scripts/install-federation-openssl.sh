#!/bin/sh
# The frozen federation fixtures require req validity flags introduced in OpenSSL3.4.
set -eu
prefix=${1:?usage: install-federation-openssl.sh <absolute installation directory>}
case "$prefix" in /*) ;; *) echo 'OpenSSL installation directory must be absolute' >&2; exit 2 ;; esac
if [ -e "$prefix" ]; then echo 'OpenSSL installation directory already exists' >&2; exit 2; fi
version=3.6.4
sha256=9bffaa1ad1e07b354c21bd3324ec02fa15579f45a7d0494b3e74bc449b7333ef
source_url="https://github.com/openssl/openssl/releases/download/openssl-${version}/openssl-${version}.tar.gz"
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/fireemu-release-openssl-XXXXXX")
trap 'rm -rf "$build_dir"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
archive="$build_dir/openssl-${version}.tar.gz"
# An offline dry run can supply the same archive; its checksum is still mandatory.
if [ -n "${FIREEMU_OPENSSL_SOURCE_TARBALL:-}" ]; then
  cp "$FIREEMU_OPENSSL_SOURCE_TARBALL" "$archive"
else
  curl --fail --location --proto '=https' --tlsv1.2 "$source_url" --output "$archive"
fi
printf '%s  %s\n' "$sha256" "$archive" | sha256sum --check --strict
printf 'OpenSSL source=%s version=%s sha256=%s\n' "$source_url" "$version" "$sha256"
tar -xzf "$archive" -C "$build_dir"
cd "$build_dir/openssl-${version}"
./Configure --prefix="$prefix" --openssldir="$prefix/ssl" no-shared no-tests no-docs
make -j"${FIREEMU_OPENSSL_BUILD_JOBS:-2}" build_sw
make install_sw install_ssldirs
"$prefix/bin/openssl" version
"$prefix/bin/openssl" req -help 2>&1 | grep -- '-not_before' >/dev/null
"$prefix/bin/openssl" req -help 2>&1 | grep -- '-not_after' >/dev/null
