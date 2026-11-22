# anfs test lab

Two NFS servers in docker, with identical content, for testing anfs without a NAS.

| Service | IP | What | Versions |
|---|---|---|---|
| `knfsd` | 172.30.111.10 | Linux kernel NFS server | v3, v4.0, v4.1, v4.2 (TCP and UDP for v3) |
| `ganesha` | 172.30.111.11 | NFS-Ganesha (userspace) | v3, v4.0, v4.1 |

Nothing is published on the host, talk to the container IPs directly.
On both servers portmapper is on 111, mountd on 20048 and NFS on 2049.

Both containers run privileged: the kernel server needs it for nfsd, and both
need it to mount their data filesystem (see below).

## Why the exports live on a loopback filesystem

NFS file handles are not confined to the exported directory: a client can craft
the handle of any file on the *filesystem* the export is on (the export escape
check of `anfsanalyze` does exactly this). A docker volume is a plain directory
on the host's filesystem, so exporting one hands the files of the docker host
to anything that can reach the container.

`storage.sh` therefore creates a 512M ext4 image inside the volume and mounts
it on `/srv`, the servers refuse to start without it. An escape ends at the
root of that image, where it finds what the lab planted for it:
`/srv/outside/secret.txt` and a fake `/srv/etc/shadow` with dummy hashes.

Do not replace this with a bind mount or a bare volume.

## Usage

The kernel server needs the `nfsd` module on the host:

    sudo modprobe nfsd
    # to keep it across reboots
    echo nfsd | sudo tee /etc/modules-load.d/nfsd.conf

Then:

    docker compose -f lab/docker-compose.yml up -d --build
    anfsclient nfs://172.30.111.10
    python3 -m pytest tests

    docker compose -f lab/docker-compose.yml down       # stop
    docker compose -f lab/docker-compose.yml down -v    # stop and wipe the data

## Exports

The NFSv3 paths are the same on both servers. Under NFSv4 the kernel server
exposes them below its pseudo root as `/rw`, `/ro`, ... and so does Ganesha.

| Path | Options |
|---|---|
| `/srv/exports/rw` | read-write, `no_root_squash` |
| `/srv/exports/ro` | read-only, `root_squash` |
| `/srv/exports/squash` | read-write, `all_squash` |
| `/srv/exports/secure` | read-write, `root_squash`, client must use a source port below 1024 |

`/srv/outside/secret.txt` and `/srv/etc/shadow` (fake) are on the same
filesystem but outside of every export, they are the targets of the export
escape checks.

## Content

Every export gets the same tree, created by `fixtures.sh` on container start:

    hello.txt                      "hello from <export>"
    empty.txt                      0 bytes
    big.bin                        3MiB of 'A'
    file with space.txt
    árvíztűrő tükörfúrógép.txt
    link_to_hello -> hello.txt
    link_abs -> /etc/passwd
    emptydir/
    dir1/dir2/dir3/deep.txt
    private/rootonly.txt           root:root, 0700 / 0600
    user1000/mine.txt              1000:1000, 0700 / 0600

`/srv/exports/rw/scratch` (mode 1777) is wiped on every start, write tests go there.
