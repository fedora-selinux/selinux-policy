#!/bin/bash

# Make an SRPM for COPR

set -eux

outdir="$1"; shift

rootdir="$(realpath -m "$0/../..")"

rpm -q rpm-build git-core || dnf install -y rpm-build git-core

tmpdir="$(mktemp -d)"

trap 'rm -rf "$tmpdir"' EXIT

rpmbuild_dir="$tmpdir"
distgit_dir="$tmpdir/SOURCES"

mkdir -p "$distgit_dir"

"$rootdir/scripts/make-sources.sh" "$distgit_dir"

rpmbuild --define "_topdir $rpmbuild_dir" -bs "$distgit_dir/selinux-policy.spec"
cp "$rpmbuild_dir/SRPMS/"*.src.rpm "$outdir"
