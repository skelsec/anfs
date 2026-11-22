import os

import pytest

from anfs.protocol.nfs3.common.factory import NFS3ConnectionFactory
from anfs.protocol.rpc.common.target import RPCTarget
from anfs.protocol.rpc.common.exceptions import RPCReplyDeniedException, RPCProgramNotRegisteredException
from anfs.protocol.rpc.messages import AUTH_SYS, auth_stat, authsys_params

pytestmark = pytest.mark.timeout(60)

# the lab servers use these on both implementations
LAB_MOUNT_PORT = 20048
LAB_NFS_PORT = 2049

async def read_hello(url, export = '/srv/exports/ro'):
	factory = NFS3ConnectionFactory.from_url(url)
	async with factory.get_mount() as mount:
		handle, err = await mount.mount(export)
		assert err is None
	async with factory.get_client(handle) as nfs:
		entry, err = await nfs.lookup(0, 'hello.txt')
		assert err is None
		data, err = await nfs.read(entry.handle)
		assert err is None
		return data

def test_url_defaults():
	target = RPCTarget.from_url('nfs://10.0.0.1')
	assert target.is_udp() is False
	assert target.get_portmap_target().port == 111
	# 0 means "ask the portmapper"
	assert target.get_mount_target().port == 0
	assert target.get_nfs_target().port == 0

def test_url_ports():
	target = RPCTarget.from_url('nfs://10.0.0.1:12049/?portmapport=1111&mountport=20048&transport=udp')
	assert target.is_udp() is True
	assert target.get_portmap_target().port == 1111
	assert target.get_mount_target().port == 20048
	assert target.get_nfs_target().port == 12049
	# the dedicated parameter wins over the port of the URL
	target = RPCTarget.from_url('nfs://10.0.0.1:1/?nfsport=2049')
	assert target.get_nfs_target().port == 2049

def test_url_authsys():
	cred = NFS3ConnectionFactory.from_url('nfs://10.0.0.1/?uid=1000&gid=1001&gids=4,24,27&machinename=client1').get_credential()
	assert isinstance(cred, AUTH_SYS)
	params = authsys_params.from_bytes(cred.body)
	assert params.uid == 1000
	assert params.gid == 1001
	assert params.gids == [4, 24, 27]
	assert params.machinename == 'client1'

@pytest.mark.asyncio
async def test_explicit_nfs_port(server):
	# the port of the URL is the NFS port, mountd is still looked up via the portmapper
	assert await read_hello('nfs://%s:%s' % (server, LAB_NFS_PORT)) == b'hello from ro\n'

@pytest.mark.asyncio
async def test_no_portmapper(server):
	# with both ports given the portmapper is never contacted, port 1 has nothing listening
	url = 'nfs://%s/?portmapport=1&mountport=%s&nfsport=%s' % (server, LAB_MOUNT_PORT, LAB_NFS_PORT)
	assert await read_hello(url) == b'hello from ro\n'

@pytest.mark.asyncio
async def test_wrong_portmapper_port(server):
	factory = NFS3ConnectionFactory.from_url('nfs://%s/?portmapport=1&timeout=3' % server)
	mount = factory.get_mount()
	_, err = await mount.connect()
	assert err is not None

@pytest.mark.asyncio
async def test_program_not_registered(server):
	from anfs.protocol.rpc import RPC
	target = RPCTarget.from_url('nfs://%s' % server).get_mount_target()
	rpc = RPC(target, None)
	_, err = await rpc.connect(400000, 1)
	assert isinstance(err, RPCProgramNotRegisteredException)

@pytest.mark.asyncio
async def test_udp(server):
	assert await read_hello('nfs://%s/?transport=udp' % server) == b'hello from ro\n'

@pytest.mark.asyncio
async def test_udp_big_file(server):
	# a read reply has to fit in one datagram, the client clamps the read size
	factory = NFS3ConnectionFactory.from_url('nfs://%s/?transport=udp' % server)
	async with factory.get_mount() as mount:
		handle, err = await mount.mount('/srv/exports/ro')
		assert err is None
	async with factory.get_client(handle) as nfs:
		entry, err = await nfs.lookup(0, 'big.bin')
		assert err is None
		total = 0
		while total < 3145728:
			data, err = await nfs.read(entry.handle, offset = total)
			assert err is None
			assert 0 < len(data) <= 32768
			total += len(data)
		assert total == 3145728

@pytest.mark.asyncio
async def test_authsys_from_url(server):
	# user1000/mine.txt is readable only by uid 1000
	async def read_mine(url):
		factory = NFS3ConnectionFactory.from_url(url)
		async with factory.get_mount() as mount:
			handle, err = await mount.mount('/srv/exports/ro')
			assert err is None
		async with factory.get_client(handle) as nfs:
			home, err = await nfs.lookup(0, 'user1000')
			assert err is None
			mine, err = await nfs.lookup(home.handle, 'mine.txt')
			if err is not None or mine is False:
				return None
			data, err = await nfs.read(mine.handle)
			return data if err is None else None

	assert await read_mine('nfs://%s/?uid=1000&gid=1000' % server) == b'user 1000 only\n'
	assert await read_mine('nfs://%s/?uid=1001&gid=1001' % server) is None

@pytest.mark.asyncio
async def test_secure_export_unprivileged_port(server):
	# the 'secure' export refuses clients coming from a source port above 1023.
	# knfsd refuses already at mount time, Ganesha hands out the handle and denies the NFS calls with AUTH_TOOWEAK
	factory = NFS3ConnectionFactory.from_url('nfs://%s' % server)
	async with factory.get_mount() as mount:
		handle, err = await mount.mount('/srv/exports/secure')
	if err is not None:
		return
	async with factory.get_client(handle) as nfs:
		_, err = await nfs.lookup(0, 'hello.txt')
		assert isinstance(err, RPCReplyDeniedException)
		assert err.auth_stat == auth_stat.AUTH_TOOWEAK
		assert 'AUTH_TOOWEAK' in str(err)

@pytest.mark.asyncio
@pytest.mark.skipif(os.geteuid() != 0, reason = 'binding a source port below 1024 needs root')
async def test_secure_export_privileged_port(server):
	assert await read_hello('nfs://%s/?privport=1' % server, '/srv/exports/secure') == b'hello from secure\n'
