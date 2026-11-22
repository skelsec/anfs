![Supported Python versions](https://img.shields.io/badge/python-3.7+-blue.svg) [![Twitter](https://img.shields.io/twitter/follow/skelsec?label=skelsec&style=social)](https://twitter.com/intent/follow?screen_name=skelsec)

## :triangular_flag_on_post: Sponsors

If you like this project, consider purchasing licenses of [OctoPwn](https://octopwn.com/), our full pentesting suite that runs in your browser!  
For notifications on new builds/releases and other info, hop on to our [Discord](https://discord.gg/PM8utcNxMS)


# anfs
Asynchronous NFSv3 and NFSv4 (4.1, 4.2) client in pure Python

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
`anfsclient 'nfs://10.0.0.1/?version=4'` - uses NFSv4.1, `version=4.2` is also available.  
NFSv4 needs only the NFS port (2049 unless set otherwise), no portmapper and no mount service. There are no mountpoints either:
the client starts in the root directory of the server and all exports are somewhere below it, `ls` and `cd` gets you there.  
The same export can behave differently over the two protocol versions, it is worth checking both.

## URL parameters
Everything is set in the query part of the URL, parameters can be combined.

| Parameter | Meaning | Default |
|---|---|---|
| `version` | NFS version: `3`, `4` (same as `4.1`), `4.2` | `3` |
| port of the URL / `nfsport` | port of the NFS service | asks the portmapper (NFSv4: 2049) |
| `mountport` | port of the mount service (NFSv3 only) | asks the portmapper |
| `portmapport` | port of the portmapper (NFSv3 only) | 111 |
| `transport` | `tcp` or `udp` | `tcp` |
| `privport` | `1` to use a source port below 1024 | off |
| `uid`, `gid` | user and group id presented to the server (AUTH_SYS) | 0 |
| `gids` | comma separated list of auxiliary group ids | none |
| `machinename` | client name presented to the server | `anfs` |
| `timeout` | timeout in seconds | 10 |
| `fragsize` | max size of an RPC fragment sent over TCP | 1048576 |

Examples:  
`anfsclient 'nfs://10.0.0.1/?uid=1000&gid=1000'` - be the user with id 1000. The server takes our word for it.  
`anfsclient 'nfs://10.0.0.1:2049/?mountport=20048'` - the portmapper is firewalled but you know the ports.  
`anfsclient 'nfs://10.0.0.1/?transport=udp'` - NFS over UDP.  

# Testing
The `lab` directory has a docker based test lab with two different NFS servers, see [lab/README.md](lab/README.md).  
`python3 -m pytest tests` runs the tests against it.

# Kudos
The NFSv3 structure encoding/decoding is taken from [NfsClient](https://github.com/CharmingYang0/NfsClient).  
@philipp-tg for the copious amount of bugfixes
