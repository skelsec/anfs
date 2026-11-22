import uuid

import pytest

from anfs.protocol.nfs3.common.factory import NFS3ConnectionFactory
from anfs.protocol.nfs4.client import NFS4Error
from anfs.protocol.nfs4.constants import nfsstat4, NF4DIR, NF4LNK, NF4REG, NF4FIFO, ACCESS4_READ, ACCESS4_MODIFY
from anfs.protocol.rpc.messages import AUTH_SYS

pytestmark = [pytest.mark.asyncio, pytest.mark.timeout(60)]

# Under NFSv4 both lab servers present the exports directly below the root: /srv/exports/rw is /rw

@pytest.fixture(params = ['4.0', '4.1', '4.2'])
def factory(request, server):
	return NFS3ConnectionFactory.from_url('nfs://%s/?version=%s' % (server, request.param))

async def listdir(nfs, handle, auth = None):
	entries = {}
	async for entry, err in nfs.readdir(handle, auth = auth):
		assert err is None
		entries[entry.name] = entry
	return entries

async def path(nfs, path, auth = None):
	entry, err = await nfs.lookup_path(path, auth = auth)
	assert err is None
	return entry

class Scratch:
	"""A private directory below /rw/scratch, removed at the end"""
	def __init__(self, factory):
		self.nfs = factory.get_client4()
		self.name = 'test4-%s' % uuid.uuid4().hex[:12]
		self.scratch = None
		self.dir = None

	async def __aenter__(self):
		_, err = await self.nfs.connect()
		assert err is None
		self.scratch = await path(self.nfs, '/rw/scratch')
		self.dir, err = await self.nfs.mkdir(self.scratch.handle, self.name)
		assert err is None
		return self

	async def __aexit__(self, exc_type, exc, tb):
		async for entry, err in self.nfs.readdir(self.dir.handle):
			if err is None:
				await self.nfs.remove(self.dir.handle, entry.name)
		await self.nfs.remove(self.scratch.handle, self.name)
		await self.nfs.disconnect()

	async def names(self):
		return sorted(await listdir(self.nfs, self.dir.handle))

async def test_session(factory):
	async with factory.get_client4() as nfs:
		assert nfs.minorversion == factory.version[1]
		if nfs.minorversion == 0:
			# no sessions in NFSv4.0
			assert nfs.sessionid is None
		else:
			assert len(nfs.sessionid) == 16
			assert nfs.fore_chan_attrs['maxrequests'] >= 1
		_, err = await nfs.null()
		assert err is None

async def test_list_root(factory):
	async with factory.get_client4() as nfs:
		entries = await listdir(nfs, 0)
		for name in ['rw', 'ro', 'squash']:
			assert name in entries
			assert entries[name].type == NF4DIR

async def test_list_export(factory):
	async with factory.get_client4() as nfs:
		ro = await path(nfs, '/ro')
		entries = await listdir(nfs, ro.handle)
		for name in ['hello.txt', 'empty.txt', 'big.bin', 'file with space.txt', 'árvíztűrő tükörfúrógép.txt',
					'link_to_hello', 'link_abs', 'emptydir', 'dir1', 'private', 'user1000']:
			assert name in entries
		assert entries['big.bin'].size == 3145728
		assert entries['big.bin'].type == NF4REG
		assert entries['link_abs'].type == NF4LNK
		assert entries['user1000'].uid == 1000
		assert entries['user1000'].gid == 1000
		assert entries['user1000'].mode & 0o7777 == 0o700
		assert nfs.handle_to_path(entries['big.bin'].handle) == '/ro/big.bin'

async def test_read_file(factory):
	async with factory.get_client4() as nfs:
		hello = await path(nfs, '/ro/hello.txt')
		data, err = await nfs.read(hello.handle)
		assert err is None
		assert data == b'hello from ro\n'

async def test_read_big_file(factory):
	async with factory.get_client4() as nfs:
		big = await path(nfs, '/ro/big.bin')
		total = 0
		while total < big.size:
			data, err = await nfs.read(big.handle, offset = total, chunk_count = 65536)
			assert err is None
			assert len(data) > 0
			assert data.count(b'A') == len(data)
			total += len(data)
		assert total == 3145728

async def test_read_big_file_parallel(factory):
	# more requests in flight than the session has slots
	import asyncio
	async with factory.get_client4() as nfs:
		big = await path(nfs, '/ro/big.bin')
		results = await asyncio.gather(*[nfs.read(big.handle, offset = i * 65536, chunk_count = 65536) for i in range(48)])
		for data, err in results:
			assert err is None
			assert data == b'A' * 65536

async def test_nested_lookup_and_parent(factory):
	async with factory.get_client4() as nfs:
		deep = await path(nfs, '/ro/dir1/dir2/dir3/deep.txt')
		data, err = await nfs.read(deep.handle)
		assert err is None
		assert data == b'nested\n'
		dir3 = await path(nfs, '/ro/dir1/dir2/dir3')
		dir2 = await path(nfs, '/ro/dir1/dir2')
		parent, err = await nfs.lookup(dir3.handle, '..')
		assert err is None
		assert parent.fileid == dir2.fileid

async def test_lookup_missing(factory):
	async with factory.get_client4() as nfs:
		entry, err = await nfs.lookup_path('/ro/does-not-exist')
		assert entry is False
		assert isinstance(err, NFS4Error)
		assert err.status == nfsstat4.NFS4ERR_NOENT

async def test_readlink(factory):
	async with factory.get_client4() as nfs:
		link = await path(nfs, '/ro/link_abs')
		target, err = await nfs.readlink(link.handle)
		assert err is None
		assert target == '/etc/passwd'

async def test_access(factory):
	async with factory.get_client4() as nfs:
		hello = await path(nfs, '/ro/hello.txt')
		access, err = await nfs.access(hello.handle)
		assert err is None
		assert access & ACCESS4_READ
		assert not access & ACCESS4_MODIFY

async def test_root_squash(factory):
	root = AUTH_SYS(uid = 0, gid = 0)
	async with factory.get_client4() as nfs:
		entry, err = await nfs.lookup_path('/ro/private/rootonly.txt', auth = root)
		assert entry is False
		assert err.status == nfsstat4.NFS4ERR_ACCESS
		entry = await path(nfs, '/rw/private/rootonly.txt', auth = root)
		data, err = await nfs.read(entry.handle, auth = root)
		assert err is None
		assert data == b'root only\n'

async def test_uid_spoofing(factory):
	# the credential can be changed per call on the same session
	user = AUTH_SYS(uid = 1000, gid = 1000)
	other = AUTH_SYS(uid = 1001, gid = 1001)
	async with factory.get_client4() as nfs:
		mine = await path(nfs, '/ro/user1000/mine.txt', auth = user)
		data, err = await nfs.read(mine.handle, auth = user)
		assert err is None
		assert data == b'user 1000 only\n'
		data, err = await nfs.read(mine.handle, auth = other)
		assert data is False
		assert err.status == nfsstat4.NFS4ERR_ACCESS

async def test_authsys_from_url(server):
	factory = NFS3ConnectionFactory.from_url('nfs://%s/?version=4&uid=1000&gid=1000' % server)
	async with factory.get_client4() as nfs:
		mine = await path(nfs, '/ro/user1000/mine.txt')
		data, err = await nfs.read(mine.handle)
		assert err is None
		assert data == b'user 1000 only\n'

async def test_create_write_read(factory):
	async with Scratch(factory) as s:
		entry, err = await s.nfs.create(s.dir.handle, 'file.txt')
		assert err is None
		assert entry.type == NF4REG
		assert entry.mode & 0o7777 == 0o644
		content = b'written by anfs\n'
		written, err = await s.nfs.write(entry.handle, 0, content)
		assert err is None
		assert written == len(content)
		data, err = await s.nfs.read(entry.handle)
		assert err is None
		assert data == content
		attrs, err = await s.nfs.getattr(entry.handle)
		assert err is None
		assert attrs.size == len(content)

async def test_create_exclusive(factory):
	async with Scratch(factory) as s:
		_, err = await s.nfs.create(s.dir.handle, 'once.txt', exclusive = True)
		assert err is None
		_, err = await s.nfs.create(s.dir.handle, 'once.txt', exclusive = True)
		assert err.status == nfsstat4.NFS4ERR_EXIST
		_, err = await s.nfs.create(s.dir.handle, 'once.txt')
		assert err is None

async def test_open_write_close(factory):
	# the stateful way
	async with Scratch(factory) as s:
		res, err = await s.nfs.open(s.dir.handle, 'state.txt', create = True)
		assert err is None
		entry, stateid = res
		written, err = await s.nfs.write(entry.handle, 0, b'stateful', stateid = stateid)
		assert err is None
		data, err = await s.nfs.read(entry.handle, stateid = stateid)
		assert err is None
		assert data == b'stateful'
		_, err = await s.nfs.close(entry.handle, stateid)
		assert err is None

async def test_write_big(factory):
	# bigger than what fits in one request, the client has to split it
	async with Scratch(factory) as s:
		entry, err = await s.nfs.create(s.dir.handle, 'big.bin')
		assert err is None
		content = bytes(range(256)) * 4096 * 3
		written, err = await s.nfs.write(entry.handle, 0, content)
		assert err is None
		assert written == len(content)
		total = b''
		while len(total) < len(content):
			data, err = await s.nfs.read(entry.handle, offset = len(total))
			assert err is None
			assert len(data) > 0
			total += data
		assert total == content

async def test_mkdir_remove(factory):
	async with Scratch(factory) as s:
		entry, err = await s.nfs.mkdir(s.dir.handle, 'subdir', mode = 0o750)
		assert err is None
		assert entry.type == NF4DIR
		assert entry.mode & 0o7777 == 0o750
		_, err = await s.nfs.create(entry.handle, 'inside.txt')
		assert err is None
		_, err = await s.nfs.rmdir(s.dir.handle, 'subdir')
		assert err.status == nfsstat4.NFS4ERR_NOTEMPTY
		_, err = await s.nfs.remove(entry.handle, 'inside.txt')
		assert err is None
		_, err = await s.nfs.rmdir(s.dir.handle, 'subdir')
		assert err is None
		assert await s.names() == []

async def test_rename_and_link(factory):
	async with Scratch(factory) as s:
		entry, err = await s.nfs.create(s.dir.handle, 'old.txt')
		assert err is None
		_, err = await s.nfs.rename(s.dir.handle, 'old.txt', s.dir.handle, 'new.txt')
		assert err is None
		assert await s.names() == ['new.txt']
		_, err = await s.nfs.link(entry.handle, s.dir.handle, 'hardlink.txt')
		assert err is None
		assert await s.names() == ['hardlink.txt', 'new.txt']
		attrs, err = await s.nfs.getattr(entry.handle)
		assert err is None
		assert attrs.nlink == 2

async def test_symlink_and_mknod(factory):
	async with Scratch(factory) as s:
		entry, err = await s.nfs.symlink(s.dir.handle, 'link', '/some/where')
		assert err is None
		assert entry.type == NF4LNK
		target, err = await s.nfs.readlink(entry.handle)
		assert err is None
		assert target == '/some/where'
		entry, err = await s.nfs.mknod(s.dir.handle, 'fifo', NF4FIFO)
		assert err is None
		assert entry.type == NF4FIFO

async def test_setattr(factory):
	async with Scratch(factory) as s:
		entry, err = await s.nfs.create(s.dir.handle, 'attrs.txt')
		assert err is None
		_, err = await s.nfs.write(entry.handle, 0, b'0123456789')
		assert err is None
		# no_root_squash export: uid 0 may give the file away
		_, err = await s.nfs.setattr(entry.handle, mode = 0o600, uid = 1000, gid = 1000, size = 4)
		assert err is None
		attrs, err = await s.nfs.getattr(entry.handle)
		assert err is None
		assert attrs.mode & 0o7777 == 0o600
		assert attrs.uid == 1000
		assert attrs.gid == 1000
		assert attrs.size == 4

async def test_readonly_export_refuses_write(factory):
	async with factory.get_client4() as nfs:
		ro = await path(nfs, '/ro')
		entry, err = await nfs.create(ro.handle, 'nope.txt')
		assert entry is False
		assert err.status == nfsstat4.NFS4ERR_ROFS
		hello = await path(nfs, '/ro/hello.txt')
		_, err = await nfs.write(hello.handle, 0, b'nope')
		assert err.status == nfsstat4.NFS4ERR_ROFS

async def test_session_recovery(factory):
	# the server forgets the session (here: we destroy it behind the client's back),
	# the next call transparently sets up a new one
	from anfs.protocol.nfs4.xdr import Compound
	from anfs.protocol.nfs4.constants import NFS_PROGRAM, NFS_V4, NFSPROC4_COMPOUND
	if factory.version[1] == 0:
		pytest.skip('no sessions in NFSv4.0')
	async with factory.get_client4() as nfs:
		hello = await path(nfs, '/ro/hello.txt')
		old = nfs.sessionid
		_, err = await nfs.rpc.call(NFS_PROGRAM, NFS_V4, NFSPROC4_COMPOUND, Compound(nfs.minorversion).destroy_session(old).to_bytes())
		assert err is None
		data, err = await nfs.read(hello.handle)
		assert err is None
		assert data == b'hello from ro\n'
		assert nfs.sessionid != old

async def test_nfs40_clientid_expiry(server):
	# NFSv4.0: the server forgets our registration once the lease is over (15 seconds in the lab)
	# with nothing open, the next open registers again
	import asyncio
	factory = NFS3ConnectionFactory.from_url('nfs://%s/?version=4.0' % server)
	async with Scratch(factory) as s:
		_, err = await s.nfs.create(s.dir.handle, 'first')
		assert err is None
		clientid = s.nfs.clientid
		assert clientid is not None
		await asyncio.sleep(35)
		_, err = await s.nfs.create(s.dir.handle, 'second')
		assert err is None
		assert await s.names() == ['first', 'second']
