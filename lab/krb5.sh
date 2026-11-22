#!/bin/sh
# Kerberos setup of an NFS server of the lab: the key of nfs/<hostname>.anfs.lab
# and the local accounts the principals of the realm are mapped to.
#
# The key is derived from a fixed password, the same one the KDC has for the
# principal (see kdc/entrypoint.sh), so no keytab has to travel between containers.
set -e
NAME=$1
PRINC="nfs/$NAME.anfs.lab@ANFS.LAB"

rm -f /etc/krb5.keytab
printf 'addent -password -p %s -k 1 -e aes256-cts-hmac-sha1-96\n%s\nwkt /etc/krb5.keytab\nq\n' "$PRINC" "Service-$NAME-pw1" | ktutil > /dev/null

# alice@ANFS.LAB is this user, owner of the user1000 directories.
# mallory@ANFS.LAB has no account here and ends up as nobody.
id alice > /dev/null 2>&1 || useradd -u 1000 -U -M -s /usr/sbin/nologin alice
