import io
import os
import uuid

import pytest

from anfs.protocol.nfs3.client import NFSAccessError
from anfs.protocol.nfs3.common.factory import NFS3ConnectionFactory
from anfs.protocol.nfs3.messages import NFS3ERR_ACCES, NFS3ERR_PERM, NFS3ERR_EXIST, SET_TO_CLIENT_TIME
from anfs.protocol.rpc.messages import AUTH_SYS

pytestmark = [pytest.mark.asyncio, pytest.mark.timeout(60)]

UNCHECKED = 0
FILE_SYNC = 2

class Scratch:
	"""A private directory below /srv/exports/rw/scratch, removed at the end"""
	def __init__(self, server, params = ''):
		self.factory = NFS3ConnectionFactory.from_url('nfs://%s/%s' % (server, params))
		self.name = 'test-%s' % uuid.uuid4().hex[:12]
		self.nfs = None
		self.scratch = None
		self.dir = None

	async def __aenter__(self):
		async with self.factory.get_mount() as mount:
			handle, err = await mount.mount('/srv/exports/rw')
			assert err is None
		self.nfs = self.factory.get_client(handle)
		_, err = await self.nfs.connect()
		assert err is None
		self.scratch, err = await self.nfs.lookup(0, 'scratch')
		assert err is None
		self.dir, err = await self.nfs.mkdir(self.scratch.handle, self.name, mode = 0o755)
		assert err is None
		return self

	async def __aexit__(self, exc_type, exc, tb):
		async for entry, err in self.nfs.readdirplus(self.dir.handle):
			if err is not None or entry.name in ('.', '..'):
				continue
			if entry.type == 2:
				await self.nfs.rmdir(self.dir.handle, entry.name)
			else:
				await self.nfs.remove(self.dir.handle, entry.name)
		await self.nfs.rmdir(self.scratch.handle, self.name)
		await self.nfs.disconnect()

	async def names(self):
		names = []
		async for entry, err in self.nfs.readdirplus(self.dir.handle):
			assert err is None
			if entry.name not in ('.', '..'):
				names.append(entry.name)
		return sorted(names)

async def test_create_write_read(server):
	async with Scratch(server) as s:
		entry, err = await s.nfs.create(s.dir.handle, 'file.txt', UNCHECKED, mode = 0o644)
		assert err is None
		content = b'written by anfs\n'
		_, err = await s.nfs.write(entry.handle, 0, len(content), content, FILE_SYNC)
		assert err is None
		data, err = await s.nfs.read(entry.handle)
		assert err is None
		assert data == content
		attrs, err = await s.nfs.getattr(entry.handle)
		assert err is None
		assert attrs.size == len(content)

async def test_write_at_offset(server):
	async with Scratch(server) as s:
		entry, err = await s.nfs.create(s.dir.handle, 'offset.bin', UNCHECKED, mode = 0o644)
		assert err is None
		for offset, content in [(0, b'AAAA'), (4, b'BBBB'), (2, b'cc')]:
			_, err = await s.nfs.write(entry.handle, offset, len(content), content, FILE_SYNC)
			assert err is None
		data, err = await s.nfs.read(entry.handle)
		assert err is None
		assert data == b'AAccBBBB'

async def test_mkdir_rmdir(server):
	async with Scratch(server) as s:
		_, err = await s.nfs.mkdir(s.dir.handle, 'subdir', mode = 0o755)
		assert err is None
		assert await s.names() == ['subdir']
		_, err = await s.nfs.rmdir(s.dir.handle, 'subdir')
		assert err is None
		assert await s.names() == []

async def test_remove(server):
	async with Scratch(server) as s:
		_, err = await s.nfs.create(s.dir.handle, 'gone.txt', UNCHECKED, mode = 0o644)
		assert err is None
		_, err = await s.nfs.remove(s.dir.handle, 'gone.txt')
		assert err is None
		assert await s.names() == []
		_, err = await s.nfs.remove(s.dir.handle, 'gone.txt')
		assert err is not None

async def test_rename(server):
	async with Scratch(server) as s:
		_, err = await s.nfs.create(s.dir.handle, 'old.txt', UNCHECKED, mode = 0o644)
		assert err is None
		_, err = await s.nfs.rename(s.dir.handle, 'old.txt', s.dir.handle, 'new.txt')
		assert err is None
		assert await s.names() == ['new.txt']

async def test_symlink(server):
	async with Scratch(server) as s:
		_, err = await s.nfs.symlink(s.dir.handle, 'link', '/some/where')
		assert err is None
		entry, err = await s.nfs.lookup(s.dir.handle, 'link')
		assert err is None
		target, err = await s.nfs.readlink(entry.handle)
		assert err is None
		assert target == '/some/where'

async def test_setattr(server):
	async with Scratch(server) as s:
		entry, err = await s.nfs.create(s.dir.handle, 'attrs.txt', UNCHECKED, mode = 0o644)
		assert err is None
		# no_root_squash export: uid 0 may give the file away
		_, err = await s.nfs.setattr(entry.handle, mode = 0o600, uid = 1000, gid = 1000)
		assert err is None
		attrs, err = await s.nfs.getattr(entry.handle)
		assert err is None
		assert attrs.mode & 0o7777 == 0o600
		assert attrs.uid == 1000
		assert attrs.gid == 1000

async def test_write_over_udp(server):
	async with Scratch(server, '?transport=udp') as s:
		entry, err = await s.nfs.create(s.dir.handle, 'udp.txt', UNCHECKED, mode = 0o644)
		assert err is None
		content = b'B' * 8192
		_, err = await s.nfs.write(entry.handle, 0, len(content), content, FILE_SYNC)
		assert err is None
		data, err = await s.nfs.read(entry.handle)
		assert err is None
		assert data == content

async def test_readonly_export_refuses_write(server):
	factory = NFS3ConnectionFactory.from_url('nfs://%s' % server)
	async with factory.get_mount() as mount:
		handle, err = await mount.mount('/srv/exports/ro')
		assert err is None
	async with factory.get_client(handle) as nfs:
		entry, err = await nfs.create(0, 'nope.txt', UNCHECKED, mode = 0o644)
		assert err is not None
		assert entry is False

async def test_write_file_chunked(server):
	# more than the server takes in one WRITE
	async with Scratch(server) as s:
		entry, err = await s.nfs.create(s.dir.handle, 'chunks.bin', UNCHECKED, mode = 0o644)
		assert err is None
		limit = await s.nfs.max_write_size()
		content = os.urandom(limit * 2 + 4321)
		written, err = await s.nfs.write_file(entry.handle, content)
		assert err is None
		assert written == len(content)
		attrs, err = await s.nfs.getattr(entry.handle)
		assert err is None
		assert attrs.size == len(content)

@pytest.mark.parametrize('params', ['', '?transport=udp'])
async def test_upload_download(server, params, tmp_path):
	local = tmp_path / 'local.bin'
	local.write_bytes(os.urandom(300000))
	async with Scratch(server, params) as s:
		progress = []
		entry, err = await s.nfs.upload_file(s.dir.handle, 'up.bin', str(local), mode = 0o640, progress_cb = progress.append)
		assert err is None
		assert sum(progress) == 300000
		attrs, err = await s.nfs.getattr(entry.handle)
		assert err is None
		assert attrs.size == 300000
		assert attrs.mode & 0o7777 == 0o640

		progress = []
		back, err = await s.nfs.download_file(entry.handle, tmp_path / 'back.bin', progress_cb = progress.append)
		assert err is None
		assert back.read_bytes() == local.read_bytes()
		assert sum(progress) == 300000
		# into a directory: the file keeps its name
		back, err = await s.nfs.download_file(entry.handle, tmp_path, max_size = 1000)
		assert err is None
		assert back.name == 'up.bin'
		assert back.read_bytes() == local.read_bytes()[:len(back.read_bytes())]
		assert 1000 <= back.stat().st_size < 300000

		# uploading again replaces the content, a shorter file leaves nothing of the old one behind
		entry, err = await s.nfs.upload_file(s.dir.handle, 'up.bin', io.BytesIO(b'short'))
		assert err is None
		data, err = await s.nfs.read(entry.handle)
		assert err is None
		assert data == b'short'
		entry, err = await s.nfs.upload_file(s.dir.handle, 'up.bin', io.BytesIO(b'nope'), exclusive = True)
		assert entry is False
		assert err.status == NFS3ERR_EXIST

async def test_setattr_keeps_times(server):
	async with Scratch(server) as s:
		entry, err = await s.nfs.create(s.dir.handle, 'times.txt', UNCHECKED, mode = 0o644)
		assert err is None
		_, err = await s.nfs.setattr(entry.handle, mtime_flag = SET_TO_CLIENT_TIME, mtime_s = 1000000000, atime_flag = SET_TO_CLIENT_TIME, atime_s = 1000000000)
		assert err is None
		_, err = await s.nfs.setattr(entry.handle, mode = 0o600)
		assert err is None
		attrs, err = await s.nfs.getattr(entry.handle)
		assert err is None
		assert attrs.mode & 0o7777 == 0o600
		assert int(attrs.mtime.timestamp()) == 1000000000
		assert int(attrs.atime.timestamp()) == 1000000000

async def test_errors_are_reported(server):
	# the calls that change something fail loudly when the server refuses them
	user = AUTH_SYS(uid = 1000, gid = 1000)
	async with Scratch(server) as s:
		entry, err = await s.nfs.create(s.dir.handle, 'root.txt', UNCHECKED, mode = 0o644)
		assert err is None
		res, err = await s.nfs.write(entry.handle, 0, 4, b'nope', FILE_SYNC, auth = user)
		assert res is False
		assert isinstance(err, NFSAccessError)
		assert err.status == NFS3ERR_ACCES
		assert str(err) == 'NFS3ERR_ACCES'
		res, err = await s.nfs.write_file(entry.handle, b'nope', auth = user)
		assert res is False
		assert err.status == NFS3ERR_ACCES
		res, err = await s.nfs.setattr(entry.handle, mode = 0o777, auth = user)
		assert res is False
		assert err.status == NFS3ERR_PERM
		res, err = await s.nfs.link(entry.handle, s.dir.handle, 'hardlink', auth = user)
		assert res is False
		assert err.status == NFS3ERR_ACCES
		_, err = await s.nfs.link(entry.handle, s.dir.handle, 'hardlink')
		assert err is None
		assert await s.names() == ['hardlink', 'root.txt']

async def test_set_credential(server):
	async with Scratch(server) as s:
		_, err = await s.nfs.setattr(s.dir.handle, mode = 0o777)
		assert err is None
		s.nfs.set_credential(AUTH_SYS(uid = 1000, gid = 1000))
		entry, err = await s.nfs.create(s.dir.handle, 'user.txt', UNCHECKED, mode = 0o600)
		assert err is None
		attrs, err = await s.nfs.getattr(entry.handle)
		assert err is None
		assert (attrs.uid, attrs.gid) == (1000, 1000)
		s.nfs.set_credential(AUTH_SYS(uid = 1001, gid = 1001))
		data, err = await s.nfs.read(entry.handle)
		assert data is False
		assert err.status == NFS3ERR_ACCES
		s.nfs.set_credential(AUTH_SYS(uid = 0, gid = 0))
		data, err = await s.nfs.read(entry.handle)
		assert err is None

async def test_readdir_pages(server):
	# plain READDIR with a reply size that does not fit the directory in one page
	async with Scratch(server) as s:
		expected = []
		for i in range(60):
			name = 'file-with-a-long-name-to-fill-the-page-%03d.txt' % i
			_, err = await s.nfs.create(s.dir.handle, name, UNCHECKED, mode = 0o644)
			assert err is None
			expected.append(name)
		names = []
		async for entry, err in s.nfs.readdir(s.dir.handle, count = 1024):
			assert err is None
			assert entry.fileid is not None
			if entry.name not in ('.', '..'):
				names.append(entry.name)
		assert sorted(names) == expected
		# and the same directory with READDIRPLUS in small pages
		names = []
		async for entry, err in s.nfs.readdirplus(s.dir.handle, dircount = 512, maxcount = 2048):
			assert err is None
			if entry.name not in ('.', '..'):
				assert entry.handle is not None
				names.append(entry.name)
		assert sorted(names) == expected
		for name in expected:
			await s.nfs.remove(s.dir.handle, name)
