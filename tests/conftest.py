# Integration tests, they run against the docker lab in lab/ (see lab/README.md).
# Tests for a server that is not reachable are skipped.
import socket

import pytest

LAB_SERVERS = {
	'knfsd': '172.30.111.10',
	'ganesha': '172.30.111.11',
}

# kerberos: realm ANFS.LAB, the servers are nfs/<name>.anfs.lab
LAB_KDC = '172.30.111.5'

_reachable = {}

def is_reachable(ip, port = 111):
	if (ip, port) not in _reachable:
		try:
			socket.create_connection((ip, port), timeout = 2).close()
			_reachable[(ip, port)] = True
		except OSError:
			_reachable[(ip, port)] = False
	return _reachable[(ip, port)]

@pytest.fixture(params = list(LAB_SERVERS))
def server(request):
	"""IP address of a lab server, every test using this runs once per server"""
	ip = LAB_SERVERS[request.param]
	if is_reachable(ip) is False:
		pytest.skip('lab server %s (%s) is not running' % (request.param, ip))
	return ip

@pytest.fixture
def kdc():
	"""IP address of the KDC of the lab"""
	if is_reachable(LAB_KDC, 88) is False:
		pytest.skip('lab KDC (%s) is not running' % LAB_KDC)
	return LAB_KDC
