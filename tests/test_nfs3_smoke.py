import pytest

from anfs.protocol.nfs3.common.factory import NFS3ConnectionFactory
from anfs.protocol.rpc.messages import AUTH_SYS

pytestmark = [pytest.mark.asyncio, pytest.mark.timeout(60)]

EXPORTS = ['/srv/exports/rw', '/srv/exports/ro', '/srv/exports/squash', '/srv/exports/secure']

def get_factory(server):
	return NFS3ConnectionFactory.from_url('nfs://%s' % server)

async def get_handle(factory, export):
	async with factory.get_mount() as mount:
		handle, err = await mount.mount(export)
		assert err is None
		return handle

async def listdir(nfs, handle = 0, auth = None):
	entries = {}
	async for entry, err in nfs.readdirplus(handle, auth = auth):
		assert err is None
		entries[entry.name] = entry
	return entries

async def test_portmap_dump(server):
	async with get_factory(server).get_portmap() as portmap:
		programs, err = await portmap.dump()
		assert err is None
		registered = set((p.program, p.version) for p in programs)
		assert (100003, 3) in registered
		assert (100005, 3) in registered

async def test_exports(server):
	async with get_factory(server).get_mount() as mount:
		exports, err = await mount.export()
		assert err is None
		paths = [e.filesys for e in exports]
		for export in EXPORTS:
			assert export in paths

async def test_list_root(server):
	factory = get_factory(server)
	handle = await get_handle(factory, '/srv/exports/ro')
	async with factory.get_client(handle) as nfs:
		entries = await listdir(nfs)
		for name in ['hello.txt', 'empty.txt', 'big.bin', 'file with space.txt', 'árvíztűrő tükörfúrógép.txt',
					'link_to_hello', 'link_abs', 'emptydir', 'dir1', 'private', 'user1000']:
			assert name in entries
		assert entries['big.bin'].size == 3145728
		assert entries['user1000'].uid == 1000
		assert entries['user1000'].gid == 1000

async def test_read_file(server):
	factory = get_factory(server)
	handle = await get_handle(factory, '/srv/exports/ro')
	async with factory.get_client(handle) as nfs:
		entries = await listdir(nfs)
		data, err = await nfs.read(entries['hello.txt'].handle)
		assert err is None
		assert data == b'hello from ro\n'

async def test_read_big_file(server):
	factory = get_factory(server)
	handle = await get_handle(factory, '/srv/exports/ro')
	async with factory.get_client(handle) as nfs:
		entries = await listdir(nfs)
		total = 0
		while total < 3145728:
			data, err = await nfs.read(entries['big.bin'].handle, offset = total, chunk_count = 65536)
			assert err is None
			assert len(data) > 0
			assert data.count(b'A') == len(data)
			total += len(data)
		assert total == 3145728

async def test_nested_lookup(server):
	factory = get_factory(server)
	handle = await get_handle(factory, '/srv/exports/ro')
	async with factory.get_client(handle) as nfs:
		current = 0
		for name in ['dir1', 'dir2', 'dir3', 'deep.txt']:
			entry, err = await nfs.lookup(current, name)
			assert err is None
			current = entry.handle
		data, err = await nfs.read(current)
		assert err is None
		assert data == b'nested\n'

async def test_readlink(server):
	factory = get_factory(server)
	handle = await get_handle(factory, '/srv/exports/ro')
	async with factory.get_client(handle) as nfs:
		entries = await listdir(nfs)
		target, err = await nfs.readlink(entries['link_abs'].handle)
		assert err is None
		assert target == '/etc/passwd'

async def test_root_squash(server):
	# root is squashed on this export, the root-only file is readable only on the no_root_squash one
	factory = get_factory(server)
	root = AUTH_SYS(uid = 0, gid = 0)
	for export, readable in [('/srv/exports/ro', False), ('/srv/exports/rw', True)]:
		handle = await get_handle(factory, export)
		async with factory.get_client(handle) as nfs:
			private, err = await nfs.lookup(0, 'private', auth = root)
			assert err is None
			secret, err = await nfs.lookup(private.handle, 'rootonly.txt', auth = root)
			if readable is False:
				assert secret is False or err is not None
				continue
			assert err is None
			data, err = await nfs.read(secret.handle, auth = root)
			assert err is None
			assert data == b'root only\n'

async def test_uid_spoofing(server):
	# AUTH_SYS is trusted by the server, claiming uid 1000 gives access to that user's files
	factory = get_factory(server)
	handle = await get_handle(factory, '/srv/exports/ro')
	user = AUTH_SYS(uid = 1000, gid = 1000)
	async with factory.get_client(handle) as nfs:
		home, err = await nfs.lookup(0, 'user1000', auth = user)
		assert err is None
		mine, err = await nfs.lookup(home.handle, 'mine.txt', auth = user)
		assert err is None
		data, err = await nfs.read(mine.handle, auth = user)
		assert err is None
		assert data == b'user 1000 only\n'
