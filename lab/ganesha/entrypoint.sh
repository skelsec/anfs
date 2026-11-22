#!/bin/sh
set -e

/storage.sh
/fixtures.sh /srv
/krb5.sh ganesha

mkdir -p /run/rpcbind /run/dbus /var/run/ganesha /var/lib/nfs/ganesha
rm -f /run/dbus/pid
dbus-daemon --system --fork || true
rpcbind -w

echo "ganesha starting"
exec ganesha.nfsd -F -L /dev/stdout -f /etc/ganesha/ganesha.conf
