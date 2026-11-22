#!/bin/sh
# KDC of the ANFS.LAB realm. Everything is created from scratch on every start,
# all the secrets are fixed lab values.
set -e
AES256=aes256-cts-hmac-sha1-96:normal

rm -f /var/lib/krb5kdc/principal* /etc/krb5kdc/stash
kdb5_util create -s -r ANFS.LAB -P masterpw > /dev/null

# users
kadmin.local -q "addprinc -pw Passw0rd! alice" > /dev/null
kadmin.local -q "addprinc -pw Passw0rd! mallory" > /dev/null

# NFS servers, they derive the same key from the password (see krb5.sh)
for NAME in knfsd ganesha; do
	kadmin.local -q "addprinc -pw Service-$NAME-pw1 -e $AES256 nfs/$NAME.anfs.lab" > /dev/null
done

echo "kdc ready"
exec krb5kdc -n
