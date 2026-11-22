#!/bin/sh
set -e

/storage.sh
/fixtures.sh /srv
/krb5.sh knfsd

# see the comment in /etc/exports
for d in /srv/exports/*/; do
	d=${d%/}
	[ "$d" = /srv/exports/nomount ] && continue
	mountpoint -q "$d" || mount --bind "$d" "$d"
done

modprobe nfsd 2>/dev/null || true
# kerberos support of the kernel RPC code
modprobe rpcsec_gss_krb5 2>/dev/null || true
mkdir -p /proc/fs/nfsd /run/rpcbind /var/lib/nfs/rpc_pipefs /var/lib/nfs/v4recovery
mountpoint -q /proc/fs/nfsd || mount -t nfsd nfsd /proc/fs/nfsd

rpcbind -w
# the kernel asks these two to accept kerberos contexts and to map names to ids
rpc.svcgssd
rpc.idmapd -S
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
