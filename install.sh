#!/bin/sh
# Installs the latest flow-remote release for this Mac.
#
#   curl -fsSL https://raw.githubusercontent.com/pa/flow-remote/main/install.sh | sh
#
# It downloads anonymously with curl, so it never uses your GitHub login.
# Settings:
#   FLOW_REMOTE_INSTALL_DIR  where to put it (default ~/.local/bin)
#   FLOW_REMOTE_VERSION      a release tag instead of the latest, e.g. v0.2.0
#
# The download is checked against the release's checksums.txt. After this,
# `flow-remote upgrade` keeps it current.
set -eu

REPO=pa/flow-remote
DIR=${FLOW_REMOTE_INSTALL_DIR:-$HOME/.local/bin}
WANT=${FLOW_REMOTE_VERSION:-}

say() { printf '%s\n' "$*"; }
die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case $(uname -m) in
  arm64 | aarch64) arch=arm64 ;;
  x86_64 | amd64) arch=amd64 ;;
  *) die "unsupported CPU: $(uname -m)" ;;
esac
[ "$os" = darwin ] || die "flow-remote runs on macOS for now (this is $os)"

tmp=$(mktemp -d) || die "can't make a temporary folder"
# ${tmp:?} refuses to run with an empty path, so the cleanup can only ever
# remove the folder mktemp made.
trap 'rm -rf -- "${tmp:?}"' EXIT

if [ -z "$WANT" ]; then
  tag=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)
  [ -n "$tag" ] || die "no release found (or GitHub is rate-limiting this address)"
else
  tag=$WANT
fi
name="flow-remote_${tag}_${os}_${arch}.tar.gz"
base="https://github.com/$REPO/releases/download/$tag"
say "downloading $name..."
curl -fsSL -o "$tmp/$name" "$base/$name" || die "download failed"
curl -fsSL -o "$tmp/checksums.txt" "$base/checksums.txt" || die "download failed"

(cd "$tmp" && grep " $name\$" checksums.txt | shasum -a 256 -c -) >/dev/null || die "$name doesn't match its checksum; not installing it"
tar -xzf "$tmp/$name" -C "$tmp"
mkdir -p "$DIR"
install -m 755 "$tmp/${name%.tar.gz}/flow-remote" "$DIR/flow-remote"
say "installed flow-remote $tag to $DIR/flow-remote"

case ":$PATH:" in
  *":$DIR:"*) ;;
  *) say "add $DIR to your PATH, e.g.: echo 'export PATH=\"$DIR:\$PATH\"' >> ~/.zshrc" ;;
esac
say "next: flow-remote setup --name \"My laptop\"   (see https://github.com/$REPO#readme)"
