#!/bin/sh
set -e

/storage.sh
/fixtures.sh /srv

modprobe nfsd 2>/dev/null || true
mkdir -p /proc/fs/nfsd /run/rpcbind /var/lib/nfs/rpc_pipefs /var/lib/nfs/v4recovery
mountpoint -q /proc/fs/nfsd || mount -t nfsd nfsd /proc/fs/nfsd

rpcbind -w
exportfs -ra
rpc.mountd
rpc.nfsd
rpc.statd --no-notify || true

stop() {
	rpc.nfsd 0
	exportfs -ua
	exit 0
}
trap stop TERM INT

echo "knfsd ready"
exportfs -v
while :; do sleep 3600 & wait $!; done
