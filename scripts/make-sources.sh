#!/bin/bash

# Prepare sources for an SRPM build

set -eux

outdir="$1"; shift

rootdir="$(realpath -m "$0/../..")"

DISTGIT_URL=https://src.fedoraproject.org/rpms/selinux-policy
DISTGIT_REF=rawhide

CONTAINER_URL=https://github.com/containers/container-selinux
EXPANDER_URL=https://github.com/fedora-selinux/macro-expander

base_head_id="$(git -C "$rootdir" rev-parse HEAD)"
base_short_head_id="${base_head_id:0:7}"
base_date="$(TZ=UTC git show -s --format=%cd --date=format-local:%F_%T HEAD | tr -d :-)"

tmpdir="$(mktemp -d)"

trap 'rm -rf "$tmpdir"' EXIT

container_dir="$tmpdir/container-selinux"
expander_dir="$tmpdir/macro-expander"

git clone --single-branch --depth 1 "$CONTAINER_URL" "$container_dir"
git clone --single-branch --depth 1 "$EXPANDER_URL" "$expander_dir"
git clone -b "$DISTGIT_REF" --single-branch --depth 1 "$DISTGIT_URL" "$outdir"

git -C "$rootdir" archive --prefix="selinux-policy-$base_head_id/" --format tgz HEAD \
	>"$outdir/selinux-policy-$base_short_head_id.tar.gz"

tar -C "$container_dir" -czf "$outdir/container-selinux.tgz" \
	container.if container.te container.fc

cp "$expander_dir/macro-expander.sh" "$outdir/macro-expander"

sed -i "s/%global commit [^ ]*$/%global commit $base_head_id/;
        s/%{?dist}/.$base_date.$base_short_head_id%{?dist}/" "$outdir/selinux-policy.spec"
rm -f "$outdir/sources"
