# anfs
Asynchronous NFSv3 client in pure Python

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
