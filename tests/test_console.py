# The commands of anfsclient, run the way the command line runs them
import os
import uuid

import pytest

from anfs.examples.anfsclient import NFSClientConsole
from anfs.protocol.nfs4.xdr import nfsace4

from conftest import LAB_SERVERS, LAB_KDC, is_reachable

class Console:
	"""anfsclient in a private directory below the scratch directory of the rw export"""
	def __init__(self, server, version, capsys):
		self.v4 = version != '3'
		self.console = NFSClientConsole('nfs://%s/?version=%s' % (server, version))
		self.capsys = capsys
		self.name = 'console-%s' % uuid.uuid4().hex[:12]

	async def run(self, command, *args):
		"""Returns what the command printed"""
		self.capsys.readouterr()
		res = await self.console._run_single_command(command, list(args))
		out = self.capsys.readouterr().out
		assert res is True, out
		return out

	async def fails(self, command, *args):
		self.capsys.readouterr()
		res = await self.console._run_single_command(command, list(args))
		assert res is not True
		return self.capsys.readouterr().out

	async def __aenter__(self):
		await self.run('connect')
		if self.v4 is True:
			await self.run('cd', 'rw')
		else:
			await self.run('mount', '/srv/exports/rw')
		await self.run('cd', 'scratch')
		await self.run('mkdir', self.name)
		await self.run('cd', self.name)
		return self

	async def __aexit__(self, exc_type, exc, tb):
		await self.console._run_single_command('su', ['0'])
		await self.console._run_single_command('cd', ['..'])
		nfs = self.console.connection
		scratch, err = await nfs.lookup_path('/rw/scratch') if self.v4 is True else await nfs.lookup(0, 'scratch')
		if err is None:
			await remove_tree(nfs, scratch.handle, self.name)
		await nfs.disconnect()
		if self.console.mount is not None:
			await self.console.mount.disconnect()

async def remove_tree(nfs, parent_handle, name):
	entry, err = await nfs.lookup(parent_handle, name)
	if err is not None:
		return
	if entry.type == 2:
		children = []
		async for child, err in nfs.readdirplus(entry.handle):
			if err is None and child.name not in ('.', '..'):
				children.append(child.name)
		for child in children:
			await remove_tree(nfs, entry.handle, child)
		await nfs.rmdir(parent_handle, name)
	else:
		await nfs.remove(parent_handle, name)

@pytest.fixture(params = ['3', '4.0', '4.1', '4.2'])
def version(request):
	return request.param

@pytest.fixture
def workdir(tmp_path, monkeypatch):
	"""get and getdir download to the current directory"""
	monkeypatch.chdir(tmp_path)
	return tmp_path

@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_put_cat_get(server, version, capsys, workdir):
	content = os.urandom(200000)
	(workdir / 'src').mkdir()
	(workdir / 'src' / 'data.bin').write_bytes(content)
	(workdir / 'src' / 'note.txt').write_text('hello from anfs\n')
	os.chmod(workdir / 'src' / 'note.txt', 0o640)
	async with Console(server, version, capsys) as c:
		await c.run('put', 'src/note.txt')
		await c.run('put', 'src/data.bin', 'renamed.bin')
		listing = await c.run('ls')
		assert 'note.txt' in listing
		assert 'renamed.bin' in listing
		assert '-rw-r-----' in listing
		assert await c.run('cat', 'note.txt') == 'hello from anfs\n'
		await c.run('get', 'renamed.bin')
		assert (workdir / 'renamed.bin').read_bytes() == content
		assert 'Local file not found!' in await c.fails('put', 'src/missing.txt')
		assert 'File not found!' in await c.fails('cat', 'missing.txt')

@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_putdir_getdir(server, version, capsys, workdir):
	(workdir / 'tree' / 'sub' / 'deeper').mkdir(parents = True)
	(workdir / 'tree' / 'top.txt').write_text('top')
	(workdir / 'tree' / 'sub' / 'mid.txt').write_text('mid')
	(workdir / 'tree' / 'sub' / 'deeper' / 'low.bin').write_bytes(b'\x00' * 70000)
	os.symlink('top.txt', workdir / 'tree' / 'link')
	async with Console(server, version, capsys) as c:
		assert 'it is a symlink' in await c.run('putdir', 'tree')
		assert 'tree' in await c.run('ls')
		# uploading over an existing directory is fine
		await c.run('putdir', 'tree')
		os.rename(workdir / 'tree', workdir / 'original')
		await c.run('getdir', 'tree')
		assert (workdir / 'tree' / 'top.txt').read_text() == 'top'
		assert (workdir / 'tree' / 'sub' / 'mid.txt').read_text() == 'mid'
		assert (workdir / 'tree' / 'sub' / 'deeper' / 'low.bin').read_bytes() == b'\x00' * 70000
		assert not (workdir / 'tree' / 'link').exists()

@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_mv_chmod_chown_stat(server, version, capsys, workdir):
	async with Console(server, version, capsys) as c:
		await c.run('touch', 'a.txt')
		await c.run('mkdir', 'dir')
		await c.run('mv', 'a.txt', 'b.txt')
		listing = await c.run('ls')
		assert 'b.txt' in listing and 'a.txt' not in listing
		await c.run('chown', '1000:1001', 'b.txt')
		await c.run('chmod', '4750', 'b.txt')
		assert '-rwsr-x---  1 1000 1001' in await c.run('ls')
		stat = await c.run('stat', 'b.txt')
		assert 'Type:    file' in stat
		assert 'Mode:    4750 (-rwsr-x---)' in stat
		assert 'Owner:   1000' in stat
		assert 'Group:   1001' in stat
		await c.run('chown', ':1002', 'b.txt')
		assert 'Group:   1002' in await c.run('stat', 'b.txt')
		await c.run('chmod', '1777', 'dir')
		assert 'drwxrwxrwt' in await c.run('ls')
		assert 'Type:    directory' in await c.run('stat', 'dir')
		# a directory as the new name: moved into it
		await c.run('mv', 'b.txt', 'dir')
		assert 'b.txt' not in await c.run('ls')
		await c.run('cd', 'dir')
		assert 'b.txt' in await c.run('ls')
		assert 'octal' in await c.fails('chmod', 'rwx', 'b.txt')
		assert 'not found' in await c.fails('mv', 'missing', 'x')
		if version == '3':
			assert 'numeric' in await c.fails('chown', 'alice@anfs.lab', 'b.txt')

@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_su(server, version, capsys, workdir):
	async with Console(server, version, capsys) as c:
		assert 'uid=0 gid=0' in await c.run('whoami')
		await c.run('cd', '..')
		await c.run('chmod', '777', c.name)
		await c.run('cd', c.name)
		(workdir / 'secret.txt').write_text('for 1000 only\n')
		os.chmod(workdir / 'secret.txt', 0o600)

		assert 'uid=1000 gid=1000' in await c.run('su', '1000')
		await c.run('put', 'secret.txt')
		assert '-rw-------  1 1000 1000' in await c.run('ls')
		assert await c.run('cat', 'secret.txt') == 'for 1000 only\n'

		assert 'uid=1001 gid=5 gids=7,8' in await c.run('su', '1001', '5', '7,8')
		assert 'Command failed' in await c.fails('cat', 'secret.txt')
		assert 'Ids are numbers' in await c.fails('su', 'alice')
		await c.run('su', '1000')
		await c.run('rm', 'secret.txt')

@pytest.mark.asyncio
@pytest.mark.timeout(60)
@pytest.mark.parametrize('version4', ['4.0', '4.1', '4.2'])
async def test_acl_commands(version4, capsys, workdir):
	server = LAB_SERVERS['knfsd']
	if is_reachable(server) is False:
		pytest.skip('lab server knfsd is not running')
	async with Console(server, version4, capsys) as c:
		await c.run('touch', 'acl.txt')
		assert await c.run('getacl', 'acl.txt') == 'A::OWNER@:rwatTcCy\nA::GROUP@:rtcy\nA::EVERYONE@:rtcy\n'
		out = await c.run('setacl', 'acl.txt', 'A::OWNER@:rwatTcCy,A::1001:rwatcy,A::GROUP@:rwatcy,A::EVERYONE@:tcy')
		assert out == 'A::OWNER@:rwatTcCy\nA::1001:rwatcy\nA::GROUP@:rwatcy\nA::EVERYONE@:tcy\n'
		assert 'ACL:     A::OWNER@:rwatTcCy A::1001:rwatcy' in await c.run('stat', 'acl.txt')
		assert 'Command failed' in await c.fails('setacl', 'acl.txt', 'bogus')

@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_acl_commands_need_v4(server, capsys, workdir):
	async with Console(server, '3', capsys) as c:
		await c.run('touch', 'acl.txt')
		assert 'only with NFSv4' in await c.fails('getacl', 'acl.txt')
		assert 'only with NFSv4' in await c.fails('setacl', 'acl.txt', 'A::EVERYONE@:r')

@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_kerberos_identity(kdc, capsys):
	server = LAB_SERVERS['knfsd']
	if is_reachable(server) is False:
		pytest.skip('lab server knfsd is not running')
	url = 'nfs+kerberos-password://ANFS.LAB\\alice:Passw0rd!@%s/?dc=%s&spn=nfs/knfsd.anfs.lab&version=4' % (server, kdc)
	console = NFSClientConsole(url)
	try:
		assert await console._run_single_command('connect', []) is True
		capsys.readouterr()
		assert await console._run_single_command('whoami', []) is True
		assert 'ANFS.LAB\\alice' in capsys.readouterr().out
		# the ticket says who we are
		assert await console._run_single_command('su', ['0']) is False
		assert 'kerberos' in capsys.readouterr().out
	finally:
		if console.connection is not None:
			await console.connection.disconnect()

def test_ace_text():
	ace = nfsace4.from_string('A:fdg:staff@example.com:rwaxdDtTnNcCoy')
	assert ace.type == 0
	assert ace.flag == 0x43
	assert ace.is_group() is True
	assert ace.who == 'staff@example.com'
	assert ace.access_mask == 0x1f01ff
	assert nfsace4.from_string(str(ace)) == ace
	assert str(nfsace4.from_string('D::EVERYONE@:w')) == 'D::EVERYONE@:w'
	assert nfsace4.from_string('A::S-1-5-21:with:colons:r').who == 'S-1-5-21:with:colons'
	for bad in ['A:EVERYONE@:r', 'X::EVERYONE@:r', 'A:q:EVERYONE@:r', 'A::EVERYONE@:z']:
		with pytest.raises(ValueError):
			nfsace4.from_string(bad)

