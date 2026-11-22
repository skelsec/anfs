#!/bin/sh
# Mounts a dedicated loopback filesystem on /srv.
#
# The exports must NOT live directly on a docker volume: a volume is just a
# directory on the host's filesystem, and NFS file handles are not confined to
# the exported directory. Anyone who can reach the server could craft a handle
# for the root of that filesystem (this is exactly what the export escape check
# of anfsanalyze does) and read or write the files of the docker host.
# With a filesystem of its own the escape ends at the root of the image.
set -e
IMG=/data/exports.img

if [ ! -f "$IMG" ]; then
	truncate -s 512M "$IMG"
	mkfs.ext4 -q -F "$IMG"
fi
mkdir -p /srv

# The device nodes in /dev are a snapshot taken when the container was created,
# the node of a freshly allocated loop device may be missing. Other containers
# starting at the same time compete for the same free device, hence the retry.
attempt=0
while ! mountpoint -q /srv && [ $attempt -lt 10 ]; do
	attempt=$((attempt + 1))
	LOOP=$(losetup -f)
	[ -b "$LOOP" ] || mknod "$LOOP" b 7 "${LOOP#/dev/loop}"
	if losetup "$LOOP" "$IMG" 2>/dev/null; then
		# autoclear: the device is released when the filesystem is unmounted
		mount "$LOOP" /srv && losetup -d "$LOOP"
	else
		sleep 1
	fi
done
mountpoint -q /srv || { echo "could not mount $IMG, refusing to start"; exit 1; }
