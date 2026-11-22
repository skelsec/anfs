import uuid

import pytest

from anfs.protocol.nfs3.common.factory import NFS3ConnectionFactory

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
