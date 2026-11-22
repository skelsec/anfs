![Supported Python versions](https://img.shields.io/badge/python-3.7+-blue.svg) [![Twitter](https://img.shields.io/twitter/follow/skelsec?label=skelsec&style=social)](https://twitter.com/intent/follow?screen_name=skelsec)

## :triangular_flag_on_post: Sponsors

If you like this project, consider purchasing licenses of [OctoPwn](https://octopwn.com/), our full pentesting suite that runs in your browser!  
For notifications on new builds/releases and other info, hop on to our [Discord](https://discord.gg/PM8utcNxMS)


# anfs
Asynchronous NFSv3 and NFSv4 (4.0, 4.1, 4.2) client in pure Python

## :triangular_flag_on_post: Runs in the browser

This project, alongside with many other pentester tools runs in the browser with the power of OctoPwn!  
Check out the community version at [OctoPwn - Live](https://live.octopwn.com/)

# Install
You have two options, either use `pip install anfs` or clone this repo and do `pip install .`  
Both commands will make a new binary appear called `anfsclient`.  

# anfsclient
A sample client -command line app- to browse/get/delete/create files and folders via NFSv3 or NFSv4.  
Basic usage:  
`anfsclient nfs://10.0.0.1`  
`anfsclient nfs://10.0.0.1/?privport=1` - this will force our client to use a source port <1024 for communicating with the server.  
This is a "security feature" of NFS whereby the server checks if the client is connecting from a lower port.  
Using lower ports is only allowed if you run the client as a high privileged user, or if you have capabilities set on linux systems.

## NFSv4
`anfsclient 'nfs://10.0.0.1/?version=4'` - uses NFSv4.1, `version=4.0` and `version=4.2` are also available.  
NFSv4 needs only the NFS port (2049 unless set otherwise), no portmapper and no mount service. There are no mountpoints either:
the client starts in the root directory of the server and all exports are somewhere below it, `ls` and `cd` gets you there.  
The same export can behave differently over the two protocol versions, it is worth checking both.

## URL parameters
Everything is set in the query part of the URL, parameters can be combined.

| Parameter | Meaning | Default |
|---|---|---|
| `version` | NFS version: `3`, `4.0`, `4` (same as `4.1`), `4.2` | `3` |
| port of the URL / `nfsport` | port of the NFS service | asks the portmapper (NFSv4: 2049) |
| `mountport` | port of the mount service (NFSv3 only) | asks the portmapper |
| `portmapport` | port of the portmapper (NFSv3 only) | 111 |
| `transport` | `tcp` or `udp` | `tcp` |
| `privport` | `1` to use a source port below 1024 | off |
| `uid`, `gid` | user and group id presented to the server (AUTH_SYS) | 0 |
| `sec` | `sys`, `none`, or `krb5` / `krb5i` / `krb5p` with a kerberos URL, see below | `sys` |
| `gids` | comma separated list of auxiliary group ids | none |
| `machinename` | client name presented to the server | `anfs` |
| `timeout` | timeout in seconds | 10 |
| `fragsize` | max size of an RPC fragment sent over TCP | 1048576 |

Examples:  
`anfsclient 'nfs://10.0.0.1/?uid=1000&gid=1000'` - be the user with id 1000. The server takes our word for it.  
`anfsclient 'nfs://10.0.0.1:2049/?mountport=20048'` - the portmapper is firewalled but you know the ports.  
`anfsclient 'nfs://10.0.0.1/?transport=udp'` - NFS over UDP.  

## Kerberos
`anfsclient 'nfs+kerberos-password://REALM\user:password@nas.corp.local/?dc=10.0.0.2'`  
RPCSEC_GSS with kerberos, for exports that have `sec=krb5`, `krb5i` or `krb5p`. It works with NFSv3 and NFSv4, over TCP and UDP.
The kerberos part comes from [asyauth](https://github.com/skelsec/asyauth), the credential is given the same way as in the other
tools built on it: besides `kerberos-password` there is `kerberos-aes`, `kerberos-rc4`, `kerberos-ccache`, `kerberos-keytab` and so on,
`dc` is the address of the KDC.

| Parameter | Meaning | Default |
|---|---|---|
| `sec` | `krb5` authentication only, `krb5i` requests and replies are signed, `krb5p` they are encrypted | `krb5` |
| `spn` | service principal of the server | `nfs/<host of the URL>` |
| `dc` | address of the KDC | |

The server is `nfs/<its hostname>` in kerberos. If you connect to an IP address, set `spn`:  
`anfsclient 'nfs+kerberos-password://REALM\user:password@10.0.0.1/?dc=10.0.0.2&spn=nfs/nas.corp.local&sec=krb5p&version=4'`

With kerberos the server knows who you are, `uid` and `gid` have no meaning. A user the server has no account for is usually treated as nobody.  
Portmapper and the mount service are still used without authentication when NFSv3 is selected.  
`sec=none` in a plain `nfs://` URL sends no credentials at all (AUTH_NONE).

# anfsanalyze
Checks an NFS server for the usual security problems and prints a report (`--json-file` saves it as JSON).  
`anfsanalyze nfs://10.0.0.1`

What it looks at:
- portmapper services, exports and their allowed clients, clients that have something mounted
- escaping the export to the root of the filesystem (Linux servers without `subtree_check`), reading `/etc/shadow` that way
- per export: is root squashed, does the server believe any uid we send (uid spoofing), who can write.
  This is asked from the server with ACCESS calls, nothing is written.
- NFSv4: supported minor versions, what the server tells about itself (the Linux server sends its full kernel version),
  the exports found by walking the NFSv4 namespace with their auth methods and the same access checks
- exports that have different rules over NFSv3 and NFSv4. The Linux server only switches exports at mount points
  when it is used over NFSv4, an export that is a plain subdirectory of another export gets the options of the parent there.
- server OS guess

The NFSv4 part only needs the NFS port, it works when the portmapper and mountd are firewalled. `--no-v3` / `--no-v4` skips one of the halves.  
`--check-no-root-squash` tests root squash by creating (and removing) a directory, this is the only check that writes to the server.

# anfsscan
The same checks for many targets, one result per line (TSV files in the current directory, or in the directory given with `-o`).  
`anfsscan <scanner> nfs://x 10.0.0.0/24 targets.txt`

| Scanner | Result |
|---|---|
| `exports` | exports, allowed clients, auth methods, file handles |
| `clients` | clients that have exports mounted |
| `os` | OS guess, portmapper services |
| `access` | root squash, uid spoofing, write access per NFSv3 export (writes nothing) |
| `nfs4` | NFSv4 versions, server identity, exports with the access checks (writes nothing). `--compare-v3` also reports the exports that have different rules over NFSv3 |
| `vuln` | export escape and `/etc/shadow` read, `--check-no-root-squash` writes to the server |

# Testing
The `lab` directory has a docker based test lab with two different NFS servers, see [lab/README.md](lab/README.md).  
`python3 -m pytest tests` runs the tests against it.

# Kudos
The NFSv3 structure encoding/decoding is taken from [NfsClient](https://github.com/CharmingYang0/NfsClient).  
@philipp-tg for the copious amount of bugfixes
