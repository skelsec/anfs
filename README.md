![Supported Python versions](https://img.shields.io/badge/python-3.7+-blue.svg) [![Twitter](https://img.shields.io/twitter/follow/skelsec?label=skelsec&style=social)](https://twitter.com/intent/follow?screen_name=skelsec)

## :triangular_flag_on_post: Sponsors

If you like this project, consider purchasing licenses of [OctoPwn](https://octopwn.com/), our full pentesting suite that runs in your browser!  
For notifications on new builds/releases and other info, hop on to our [Discord](https://discord.gg/PM8utcNxMS)


# anfs
Asynchronous NFSv3 client in pure Python

## :triangular_flag_on_post: Runs in the browser

This project, alongside with many other pentester tools runs in the browser with the power of OctoPwn!  
Check out the community version at [OctoPwn - Live](https://live.octopwn.com/)

# Install
You have two options, either use `pip install anfs` or clone this repo and do `pip install .`  
Both commands will make a new binary appear called `anfsclient`.  

# anfsclient
A sample client -command line app- to browse/get/delete/create files and folders via nfs3.  
Basic usage:  
`anfsclient nfs://10.0.0.1`  
`anfsclient nfs://10.0.0.1/?privport=1` - this will force our client to use a source port <1024 for communicating with the server.  
This is a "security feature" of NFS whereby the server checks if the client is connecting from a lower port.  
Using lower ports is only allowed if you run the client as a high privileged user, or if you have capabilities set on linux systems.

# Kudos
The NFSv3 structure encoding/decoding is taken from [NfsClient](https://github.com/CharmingYang0/NfsClient).  
@philipp-tg for the copious amount of bugfixes
