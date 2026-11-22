import copy
import uuid
import asyncio

import pytest

from anfs.protocol.nfs3.common.factory import NFS3ConnectionFactory
from anfs.protocol.nfs3.client import NFSAccessError
from anfs.protocol.nfs4.client import NFS4Error
from anfs.protocol.nfs4.constants import nfsstat4
from anfs.protocol.rpc.common.exceptions import RPCReplyDeniedException
from anfs.protocol.rpc.messages import AUTH_NULL, AUTH_SYS, auth_flavor
from anfs.protocol.rpc.gss import RPCSEC_GSS, RPCGSSException, rpc_gss_service

from conftest import LAB_SERVERS

pytestmark = pytest.mark.timeout(60)

# RPCSEC_GSS with kerberos. The lab has a KDC for the realm ANFS.LAB with two users:
# alice has an account (uid 1000) on the servers, mallory does not and is nobody for them.
# /srv/exports/krb5 (/krb5 over NFSv4) can not be used with AUTH_SYS.

PASSWORD = 'Passw0rd!'
FILE_SYNC = 2

def name_of(server):
	return [name for name in LAB_SERVERS if LAB_SERVERS[name] == server][0]

def krb_url(server, kdc, user = 'alice', password = PASSWORD, sec = None, version = None, extra = ''):
	url = 'nfs+kerberos-password://ANFS.LAB\\%s:%s@%s/?dc=%s&spn=nfs/%s.anfs.lab' % (user, password, server, kdc, name_of(server))
	if sec is not None:
		url += '&sec=%s' % sec
	if version is not None:
		url += '&version=%s' % version
	return url + extra

@pytest.fixture(params = ['krb5', 'krb5i', 'krb5p'])
def sec(request):
	return request.param

@pytest.fixture(params = ['4.0', '4.1', '4.2'])
def version4(request):
	return request.param

async def client3(url):
	factory = NFS3ConnectionFactory.from_url(url)
	async with factory.get_mount() as mount:
		handle, err = await mount.mount('/srv/exports/krb5')
		assert err is None
	return factory.get_client(handle)

async def path4(nfs, path):
	entry, err = await nfs.lookup_path(path)
	assert err is None
	return entry

def is_alice(entry):
	# under kerberos the Linux server sends names in the owner attribute of NFSv4, Ganesha stays with the ids
	return str(entry.uid) in ('1000', 'alice@anfs.lab')

def is_nobody(entry):
	return str(entry.uid) in ('65534', '4294967294', 'nobody@anfs.lab')

##### the URL
def test_url():
	factory = NFS3ConnectionFactory.from_url('nfs+kerberos-password://ANFS.LAB\\alice:pw@10.0.0.1/?dc=10.0.0.2')
	cred = factory.get_credential()
	assert isinstance(cred, RPCSEC_GSS)
	assert cred.flavor == auth_flavor.RPCSEC_GSS
	assert cred.service == rpc_gss_service.NONE
	assert cred.get_spn(factory.get_target()) == 'nfs/10.0.0.1'

	factory = NFS3ConnectionFactory.from_url('nfs+kerberos-password://ANFS.LAB\\alice:pw@nas.anfs.lab/?dc=10.0.0.2&sec=krb5i')
	cred = factory.get_credential()
	assert cred.service == rpc_gss_service.INTEGRITY
	assert cred.get_spn(factory.get_target()) == 'nfs/nas.anfs.lab'

	factory = NFS3ConnectionFactory.from_url('nfs+kerberos-password://ANFS.LAB\\alice:pw@10.0.0.1/?dc=10.0.0.2&sec=krb5p&spn=nfs/nas.anfs.lab')
	cred = factory.get_credential()
	assert cred.service == rpc_gss_service.PRIVACY
	assert cred.get_spn(factory.get_target()) == 'nfs/nas.anfs.lab'

	# portmap and mount stay without authentication
	assert isinstance(factory.get_mount().credential, AUTH_NULL)

def test_url_errors():
	assert isinstance(NFS3ConnectionFactory.from_url('nfs://10.0.0.1/?sec=none').get_credential(), AUTH_NULL)
	assert isinstance(NFS3ConnectionFactory.from_url('nfs://10.0.0.1/?sec=sys').get_credential(), AUTH_SYS)
	# kerberos without credentials
	with pytest.raises(Exception):
		NFS3ConnectionFactory.from_url('nfs://10.0.0.1/?sec=krb5')
	with pytest.raises(Exception):
		NFS3ConnectionFactory.from_url('nfs+kerberos-password://ANFS.LAB\\alice:pw@10.0.0.1/?dc=10.0.0.2&sec=sys')
	# not a GSS mechanism
	with pytest.raises(Exception):
		NFS3ConnectionFactory.from_url('nfs+ntlm-password://ANFS\\alice:pw@10.0.0.1')

def test_copy_has_no_context():
	factory = NFS3ConnectionFactory.from_url('nfs+kerberos-password://ANFS.LAB\\alice:pw@10.0.0.1/?dc=10.0.0.2&sec=krb5i')
	cred = factory.get_credential()
	cred.handle = b'context of someone else'
	cred.seq_num = 10
	other = copy.deepcopy(cred)
	assert other is not cred
	assert other.is_established() is False
	assert other.seq_num == 0
	assert other.service == cred.service

##### NFSv4
@pytest.mark.asyncio
async def test_nfs4_read(server, kdc, sec, version4):
	factory = NFS3ConnectionFactory.from_url(krb_url(server, kdc, sec = sec, version = version4))
	async with factory.get_client4() as nfs:
		assert nfs.rpc.credential.is_established()
		names = []
		krb5 = await path4(nfs, '/krb5')
		async for entry, err in nfs.readdir(krb5.handle):
			assert err is None
			names.append(entry.name)
		for name in ['hello.txt', 'big.bin', 'user1000', 'scratch', 'árvíztűrő tükörfúrógép.txt']:
			assert name in names

		# readable only by the owner: the server knows who we are
		mine = await path4(nfs, '/krb5/user1000/mine.txt')
		assert is_alice(mine)
		data, err = await nfs.read(mine.handle)
		assert err is None
		assert data == b'user 1000 only\n'

		# kerberos does not make us root
		_, err = await nfs.lookup_path('/krb5/private/rootonly.txt')
		assert isinstance(err, NFS4Error)
		assert err.status == nfsstat4.NFS4ERR_ACCESS

		big = await path4(nfs, '/krb5/big.bin')
		total = 0
		while total < big.size:
			data, err = await nfs.read(big.handle, offset = total, chunk_count = 1024 * 1024)
			assert err is None
			assert data == b'A' * len(data)
			assert len(data) > 0
			total += len(data)
		assert total == 3145728

@pytest.mark.asyncio
async def test_nfs4_write(server, kdc, sec, version4):
	factory = NFS3ConnectionFactory.from_url(krb_url(server, kdc, sec = sec, version = version4))
	async with factory.get_client4() as nfs:
		scratch = await path4(nfs, '/krb5/scratch')
		name = 'gss4-%s' % uuid.uuid4().hex[:12]
		entry, err = await nfs.create(scratch.handle, name)
		assert err is None
		try:
			assert is_alice(entry)
			# more than one request
			content = bytes(range(256)) * 8192
			written, err = await nfs.write(entry.handle, 0, content)
			assert err is None
			assert written == len(content)
			readback = b''
			while len(readback) < len(content):
				data, err = await nfs.read(entry.handle, offset = len(readback), chunk_count = 1024 * 1024)
				assert err is None
				assert len(data) > 0
				readback += data
			assert readback == content
		finally:
			_, err = await nfs.remove(scratch.handle, name)
			assert err is None

@pytest.mark.asyncio
async def test_nfs4_parallel(server, kdc, sec, version4):
	# replies arrive in any order, each has to be matched with the sequence number of its call
	factory = NFS3ConnectionFactory.from_url(krb_url(server, kdc, sec = sec, version = version4))
	async with factory.get_client4() as nfs:
		big = await path4(nfs, '/krb5/big.bin')
		results = await asyncio.gather(*[nfs.read(big.handle, offset = i * 2000, chunk_count = 2000) for i in range(48)])
		for data, err in results:
			assert err is None
			assert data == b'A' * 2000

@pytest.mark.asyncio
async def test_nfs4_parallel_big(server, kdc, sec, version4):
	factory = NFS3ConnectionFactory.from_url(krb_url(server, kdc, sec = sec, version = version4))
	async with factory.get_client4() as nfs:
		big = await path4(nfs, '/krb5/big.bin')
		results = await asyncio.gather(*[nfs.read(big.handle, offset = i * 65536, chunk_count = 65536) for i in range(48)])
		errors = [err for _, err in results if err is not None]
		if len(errors) > 0 and name_of(server) == 'knfsd' and sec == 'krb5i' and any(isinstance(err, RPCGSSException) for err in errors):
			# Seen with the NFSv4 server of Linux 7.0: when READ replies that do not fit in one page
			# are produced at the same time, several of them leave the server with the very same
			# signature (the one of the reply that was signed last) after the results. The bytes
			# are like that on the wire, only one of those replies can be verified.
			pytest.xfail("server sent the signature of another reply (%s)" % set(repr(e) for e in errors))
		for data, err in results:
			assert err is None
			assert data == b'A' * 65536

@pytest.mark.asyncio
async def test_nfs4_unknown_user(server, kdc, sec):
	# a valid ticket, but the server has no account for the user
	factory = NFS3ConnectionFactory.from_url(krb_url(server, kdc, user = 'mallory', sec = sec, version = '4.1'))
	async with factory.get_client4() as nfs:
		_, err = await nfs.lookup_path('/krb5/user1000/mine.txt')
		assert isinstance(err, NFS4Error)
		assert err.status == nfsstat4.NFS4ERR_ACCESS

		scratch = await path4(nfs, '/krb5/scratch')
		name = 'gss4-%s' % uuid.uuid4().hex[:12]
		entry, err = await nfs.create(scratch.handle, name)
		assert err is None
		try:
			assert is_nobody(entry)
		finally:
			await nfs.remove(scratch.handle, name)

@pytest.mark.asyncio
async def test_nfs4_authsys_refused(server, version4):
	factory = NFS3ConnectionFactory.from_url('nfs://%s/?version=%s&uid=1000&gid=1000' % (server, version4))
	async with factory.get_client4() as nfs:
		_, err = await nfs.lookup_path('/krb5')
		assert isinstance(err, NFS4Error)
		assert err.status == nfsstat4.NFS4ERR_WRONGSEC

@pytest.mark.asyncio
async def test_nfs4_kerberos_on_other_exports(server, kdc, sec):
	# the exports of the lab that do not list kerberos refuse it
	factory = NFS3ConnectionFactory.from_url(krb_url(server, kdc, sec = sec, version = '4.1'))
	async with factory.get_client4() as nfs:
		_, err = await nfs.lookup_path('/ro')
		assert isinstance(err, NFS4Error)
		assert err.status == nfsstat4.NFS4ERR_WRONGSEC

@pytest.mark.asyncio
async def test_wrong_password(server, kdc):
	factory = NFS3ConnectionFactory.from_url(krb_url(server, kdc, password = 'NotThePassword', version = '4.1'))
	nfs = factory.get_client4()
	_, err = await nfs.connect()
	assert err is not None
	await nfs.disconnect()

@pytest.mark.asyncio
async def test_wrong_spn(server, kdc):
	# no such service in the realm
	url = krb_url(server, kdc, version = '4.1').replace('spn=nfs/', 'spn=nfs/nope-')
	nfs = NFS3ConnectionFactory.from_url(url).get_client4()
	_, err = await nfs.connect()
	assert err is not None
	await nfs.disconnect()

@pytest.mark.asyncio
async def test_nfs4_context_lost(server, kdc, sec, version4):
	# the server forgets the context (restart, timeout): a new one is created and the call is sent again
	factory = NFS3ConnectionFactory.from_url(krb_url(server, kdc, sec = sec, version = version4))
	async with factory.get_client4() as nfs:
		mine = await path4(nfs, '/krb5/user1000/mine.txt')
		cred = nfs.rpc.credential
		old = cred.handle
		cred.handle = bytes(len(old))
		data, err = await nfs.read(mine.handle)
		assert err is None
		assert data == b'user 1000 only\n'
		assert cred.handle != bytes(len(old))

@pytest.mark.asyncio
async def test_context_destroyed(server, kdc, sec):
	factory = NFS3ConnectionFactory.from_url(krb_url(server, kdc, sec = sec, version = '4.1'))
	nfs = factory.get_client4()
	_, err = await nfs.connect()
	assert err is None
	cred = nfs.rpc.credential
	assert cred.is_established()
	await nfs.disconnect()
	assert cred.is_established() is False

@pytest.mark.asyncio
async def test_two_clients(server, kdc):
	# every client of a factory has a context of its own
	factory = NFS3ConnectionFactory.from_url(krb_url(server, kdc, sec = 'krb5i', version = '4.1'))
	async with factory.get_client4() as first:
		async with factory.get_client4() as second:
			assert first.rpc.credential is not second.rpc.credential
			assert first.rpc.credential.handle != second.rpc.credential.handle
			for nfs in (first, second, first):
				mine = await path4(nfs, '/krb5/user1000/mine.txt')
				data, err = await nfs.read(mine.handle)
				assert err is None
				assert data == b'user 1000 only\n'

##### NFSv3
@pytest.mark.asyncio
async def test_nfs3_read(server, kdc, sec):
	async with await client3(krb_url(server, kdc, sec = sec)) as nfs:
		names = []
		async for entry, err in nfs.readdirplus(0):
			assert err is None
			names.append(entry.name)
		for name in ['hello.txt', 'big.bin', 'user1000', 'scratch', 'árvíztűrő tükörfúrógép.txt']:
			assert name in names

		home, err = await nfs.lookup(0, 'user1000')
		assert err is None
		mine, err = await nfs.lookup(home.handle, 'mine.txt')
		assert err is None
		assert mine.uid == 1000
		data, err = await nfs.read(mine.handle)
		assert err is None
		assert data == b'user 1000 only\n'

		private, err = await nfs.lookup(0, 'private')
		assert err is None
		_, err = await nfs.lookup(private.handle, 'rootonly.txt')
		assert isinstance(err, NFSAccessError)

		big, err = await nfs.lookup(0, 'big.bin')
		assert err is None
		total = 0
		while total < big.size:
			data, err = await nfs.read(big.handle, offset = total, chunk_count = 1024 * 1024)
			assert err is None
			assert len(data) > 0
			assert data == b'A' * len(data)
			total += len(data)
		assert total == 3145728

@pytest.mark.asyncio
async def test_nfs3_write(server, kdc, sec):
	async with await client3(krb_url(server, kdc, sec = sec)) as nfs:
		scratch, err = await nfs.lookup(0, 'scratch')
		assert err is None
		name = 'gss3-%s' % uuid.uuid4().hex[:12]
		entry, err = await nfs.create(scratch.handle, name, 0, mode = 0o644)
		assert err is None
		try:
			assert entry.uid == 1000
			content = bytes(range(256)) * 256
			_, err = await nfs.write(entry.handle, 0, len(content), content, FILE_SYNC)
			assert err is None
			data, err = await nfs.read(entry.handle, 0, len(content))
			assert err is None
			assert data == content
		finally:
			_, err = await nfs.remove(scratch.handle, name)
			assert err is None

@pytest.mark.asyncio
async def test_nfs3_unknown_user(server, kdc, sec):
	async with await client3(krb_url(server, kdc, user = 'mallory', sec = sec)) as nfs:
		home, err = await nfs.lookup(0, 'user1000')
		assert err is None
		_, err = await nfs.lookup(home.handle, 'mine.txt')
		assert isinstance(err, NFSAccessError)

		scratch, err = await nfs.lookup(0, 'scratch')
		assert err is None
		name = 'gss3-%s' % uuid.uuid4().hex[:12]
		entry, err = await nfs.create(scratch.handle, name, 0, mode = 0o644)
		assert err is None
		try:
			assert is_nobody(entry)
		finally:
			await nfs.remove(scratch.handle, name)

@pytest.mark.asyncio
async def test_nfs3_authsys_refused(server):
	# the mount service gives the handle to anyone, the NFS service is the one that asks for kerberos
	async with await client3('nfs://%s/?uid=1000&gid=1000' % server) as nfs:
		_, err = await nfs.lookup(0, 'hello.txt')
		assert err is not None
		if isinstance(err, RPCReplyDeniedException):
			assert 'AUTH_TOOWEAK' in str(err)
		else:
			assert isinstance(err, NFSAccessError)

@pytest.mark.asyncio
async def test_nfs3_context_lost(server, kdc, sec):
	async with await client3(krb_url(server, kdc, sec = sec)) as nfs:
		_, err = await nfs.lookup(0, 'hello.txt')
		assert err is None
		cred = nfs.rpc.credential
		cred.handle = bytes(len(cred.handle))
		hello, err = await nfs.lookup(0, 'hello.txt')
		assert err is None
		data, err = await nfs.read(hello.handle)
		assert err is None
		assert data == b'hello from krb5\n'

@pytest.mark.asyncio
async def test_nfs3_udp(server, kdc, sec):
	if name_of(server) == 'ganesha' and sec != 'krb5':
		pytest.skip('Ganesha can not protect the replies it sends over UDP')
	async with await client3(krb_url(server, kdc, sec = sec, extra = '&transport=udp')) as nfs:
		home, err = await nfs.lookup(0, 'user1000')
		assert err is None
		mine, err = await nfs.lookup(home.handle, 'mine.txt')
		assert err is None
		data, err = await nfs.read(mine.handle)
		assert err is None
		assert data == b'user 1000 only\n'
