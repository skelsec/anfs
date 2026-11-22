#!/bin/sh
# Populates the export tree. Shared by every lab server so tests can rely on
# the same content everywhere. Idempotent.
set -e
ROOT=${1:-/srv}

mkdir -p "$ROOT/exports/rw" "$ROOT/exports/ro" "$ROOT/exports/squash" "$ROOT/exports/secure" "$ROOT/exports/nomount" "$ROOT/exports/krb5" "$ROOT/outside"

# a file outside of every export, target of the export escape checks
echo "this file is outside of every export" > "$ROOT/outside/secret.txt"

# fake shadow file at the root of the exported filesystem, this is what the
# shadow check of anfsanalyze finds after escaping an export
mkdir -p "$ROOT/etc"
printf 'root:$6$anfslab$notarealhash:19000:0:99999:7:::\nlabuser:$6$anfslab$alsonotarealhash:19000:0:99999:7:::\n' > "$ROOT/etc/shadow"
chown 0:42 "$ROOT/etc/shadow"; chmod 640 "$ROOT/etc/shadow"

for e in rw ro squash secure nomount krb5; do
	d="$ROOT/exports/$e"
	echo "hello from $e" > "$d/hello.txt"
	mkdir -p "$d/dir1/dir2/dir3" "$d/emptydir" "$d/private" "$d/user1000"
	echo "nested" > "$d/dir1/dir2/dir3/deep.txt"
	echo "root only" > "$d/private/rootonly.txt"
	echo "user 1000 only" > "$d/user1000/mine.txt"
	echo "unicode" > "$d/árvíztűrő tükörfúrógép.txt"
	echo "with space" > "$d/file with space.txt"
	ln -sf hello.txt "$d/link_to_hello"
	ln -sf /etc/passwd "$d/link_abs"
	# 3MiB of deterministic data, larger than any single READ
	[ -f "$d/big.bin" ] || head -c 3145728 /dev/zero | tr '\0' 'A' > "$d/big.bin"
	: > "$d/empty.txt"

	chown -R 0:0 "$d"
	chmod 755 "$d"
	chmod 700 "$d/private"; chmod 600 "$d/private/rootonly.txt"
	chown -R 1000:1000 "$d/user1000"
	chmod 700 "$d/user1000"; chmod 600 "$d/user1000/mine.txt"
done

# scratch area for write tests, wiped on every start
rm -rf "$ROOT/exports/rw/scratch"
mkdir -p "$ROOT/exports/rw/scratch"
chmod 1777 "$ROOT/exports/rw/scratch"
rm -rf "$ROOT/exports/krb5/scratch"
mkdir -p "$ROOT/exports/krb5/scratch"
chmod 1777 "$ROOT/exports/krb5/scratch"
