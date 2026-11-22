# RPCSEC_GSS (RFC 2203) for the RPC client.
#
# The GSSAPI part is done by asyauth: any credential that has build_gss_context()
# and gives a context with authenticate / get_mic / verify_mic / wrap / unwrap works
# here, at the moment that is the kerberos one (krb5, krb5i, krb5p of NFS).
#
#	cred = RPCSEC_GSS(kerberos_credential, service = rpc_gss_service.PRIVACY)
#	rpc = RPC(target, cred)
#
# The security context is created with the first call that uses the credential and
# belongs to this object: copies of the credential set up contexts of their own.

import io
import copy
import enum
import asyncio
import logging

from anfs.protocol.rpc.common.exceptions import RPCException, RPCReplyDeniedException
from anfs.protocol.rpc.messages import opaque_auth, auth_flavor, auth_stat, AUTH_NULL

logger = logging.getLogger(__name__)

RPCSEC_GSS_VERS_1 = 1
# sequence numbers of a context end here, a new context is needed after that
MAXSEQ = 0x80000000

GSS_S_COMPLETE = 0
GSS_S_CONTINUE_NEEDED = 1

class rpc_gss_proc(enum.Enum):
	DATA = 0
	INIT = 1
	CONTINUE_INIT = 2
	DESTROY = 3

class rpc_gss_service(enum.Enum):
	# Note: the enumerated value for 0 is reserved.
	NONE = 1      # authentication only (krb5)
	INTEGRITY = 2 # arguments and results are signed (krb5i)
	PRIVACY = 3   # arguments and results are encrypted (krb5p)

# the names NFS uses for the services of the kerberos mechanism
SEC_NAMES = {
	'krb5' : rpc_gss_service.NONE,
	'krb5i' : rpc_gss_service.INTEGRITY,
	'krb5p' : rpc_gss_service.PRIVACY,
}

class RPCGSSException(RPCException):
	pass

def pack_uint(value):
	return value.to_bytes(4, byteorder = 'big', signed = False)

def pack_opaque(data):
	return pack_uint(len(data)) + data + b'\x00' * ((4 - len(data) % 4) % 4)

def unpack_uint(buff):
	data = buff.read(4)
	if len(data) != 4:
		raise RPCGSSException('RPCSEC_GSS message is too short')
	return int.from_bytes(data, byteorder = 'big', signed = False)

def unpack_opaque(buff):
	size = unpack_uint(buff)
	data = buff.read(size)
	if len(data) != size:
		raise RPCGSSException('RPCSEC_GSS message is too short')
	buff.read((4 - size % 4) % 4)
	return data

class rpc_gss_cred:
	def __init__(self, gss_proc, seq_num, service, handle):
		self.gss_proc = gss_proc
		self.seq_num = seq_num
		self.service = service
		self.handle = handle

	def to_auth(self):
		res = opaque_auth()
		res.flavor = auth_flavor.RPCSEC_GSS
		res.body = pack_uint(RPCSEC_GSS_VERS_1) + pack_uint(self.gss_proc.value) + \
			pack_uint(self.seq_num) + pack_uint(self.service.value) + pack_opaque(self.handle)
		return res

class rpc_gss_init_res:
	def __init__(self):
		self.handle = None
		self.gss_major = None
		self.gss_minor = None
		self.seq_window = None
		self.gss_token = None

	@staticmethod
	def from_bytes(data):
		buff = io.BytesIO(data)
		res = rpc_gss_init_res()
		res.handle = unpack_opaque(buff)
		res.gss_major = unpack_uint(buff)
		res.gss_minor = unpack_uint(buff)
		res.seq_window = unpack_uint(buff)
		res.gss_token = unpack_opaque(buff)
		return res

class RPCSEC_GSS:
	def __init__(self, credential, service = rpc_gss_service.NONE, spn = None):
		# asyauth credential, eg. KerberosCredential
		self.credential = credential
		self.service = service
		# service principal of the server, nfs/<name of the server> if not set
		self.spn = spn
		self.flavor = auth_flavor.RPCSEC_GSS

		self.gssctx = None
		self.handle = None
		self.seq_num = 0
		self.seq_window = None
		self.__lock = None

	def __deepcopy__(self, memo):
		# a copy starts without a security context
		return RPCSEC_GSS(copy.deepcopy(self.credential, memo), self.service, self.spn)

	def __str__(self):
		return 'RPCSEC_GSS(%s, service=%s)' % (self.spn, self.service.name)

	def is_established(self):
		return self.handle is not None

	def get_spn(self, target):
		if self.spn is not None:
			return self.spn
		hostname = target.hostname if target.hostname is not None else target.ip
		return 'nfs/%s' % hostname

	def reset(self):
		self.gssctx = None
		self.handle = None
		self.seq_num = 0
		self.seq_window = None

	def next_seq(self):
		self.seq_num += 1
		if self.seq_num >= MAXSEQ:
			raise RPCGSSException('RPCSEC_GSS sequence numbers of the context are used up')
		return self.seq_num

	async def establish(self, rpc, program, version):
		"""
		Creates the security context: the tokens of the GSS mechanism go to the server
		in the arguments of the NULL procedure of the program the context will be used with.
		"""
		if self.__lock is None:
			self.__lock = asyncio.Lock()
		async with self.__lock:
			if self.handle is not None:
				return
			from asyauth.protocols.kerberos.gssapi import GSSAPIFlags
			# Replies can arrive in any order, the sequence and replay checks of
			# GSS must stay off. RPCSEC_GSS has sequence numbers of its own.
			flags = GSSAPIFlags.GSS_C_MUTUAL_FLAG | GSSAPIFlags.GSS_C_INTEG_FLAG | GSSAPIFlags.GSS_C_CONF_FLAG
			gssctx = self.credential.build_gss_context()
			token, to_continue, err = await gssctx.authenticate(None, flags = flags, spn = self.get_spn(rpc.target))
			if err is not None:
				raise err

			handle = b''
			gss_proc = rpc_gss_proc.INIT
			res = None
			areply = None
			for _ in range(10):
				cred = rpc_gss_cred(gss_proc, 0, self.service, handle).to_auth()
				areply = await rpc.call_raw(program, version, 0, pack_opaque(token), cred)
				res = rpc_gss_init_res.from_bytes(areply.results)
				if res.gss_major not in (GSS_S_COMPLETE, GSS_S_CONTINUE_NEEDED):
					raise RPCGSSException('Server refused to create the RPCSEC_GSS context. GSS major status: 0x%08x minor status: %s' % (res.gss_major, res.gss_minor))
				handle = res.handle
				if to_continue is True or len(res.gss_token) > 0:
					token, to_continue, err = await gssctx.authenticate(res.gss_token)
					if err is not None:
						raise err
				if res.gss_major == GSS_S_COMPLETE:
					break
				if token is None:
					raise RPCGSSException('Server expects more RPCSEC_GSS tokens, but the GSS context has none')
				gss_proc = rpc_gss_proc.CONTINUE_INIT
			else:
				raise RPCGSSException('RPCSEC_GSS context creation did not finish')

			if gssctx.is_established() is False:
				raise RPCGSSException('RPCSEC_GSS context created, but the GSS context is not complete')
			# the server proves it has the context by signing the sequence window
			if areply.verf.flavor != auth_flavor.RPCSEC_GSS:
				raise RPCGSSException('Server did not sign the reply creating the RPCSEC_GSS context')
			_, err = await gssctx.verify_mic(pack_uint(res.seq_window), areply.verf.body)
			if err is not None:
				raise RPCGSSException('Signature of the server on the RPCSEC_GSS context is not valid! %s' % err)

			self.gssctx = gssctx
			self.seq_window = res.seq_window
			self.seq_num = 0
			self.handle = handle

	async def prepare(self, xid, program, version, procedure, data, gss_proc = rpc_gss_proc.DATA):
		"""
		Credential, verifier and the protected arguments of a call
		"""
		seq_num = self.next_seq()
		cred = rpc_gss_cred(gss_proc, seq_num, self.service, self.handle).to_auth()
		# the verifier is the signature of the header of the call up to and including the credential
		header = pack_uint(xid) + pack_uint(0) + pack_uint(2) + pack_uint(program) + pack_uint(version) + pack_uint(procedure) + cred.to_bytes()
		mic, err = await self.gssctx.get_mic(header)
		if err is not None:
			raise err
		verf = opaque_auth()
		verf.flavor = auth_flavor.RPCSEC_GSS
		verf.body = mic

		if gss_proc == rpc_gss_proc.DATA and self.service != rpc_gss_service.NONE:
			body = pack_uint(seq_num) + data
			if self.service == rpc_gss_service.INTEGRITY:
				mic, err = await self.gssctx.get_mic(body)
				if err is not None:
					raise err
				data = pack_opaque(body) + pack_opaque(mic)
			else:
				token, err = await self.gssctx.wrap(body, confidential = True)
				if err is not None:
					raise err
				data = pack_opaque(token)
		return seq_num, cred, verf, data

	async def process_reply(self, seq_num, areply, gss_proc = rpc_gss_proc.DATA):
		"""
		Checks the verifier of the reply and removes the protection from the results
		"""
		if areply.verf.flavor != auth_flavor.RPCSEC_GSS:
			raise RPCGSSException('Reply of the server is not signed')
		_, err = await self.gssctx.verify_mic(pack_uint(seq_num), areply.verf.body)
		if err is not None:
			raise RPCGSSException('Signature of the server on the reply is not valid! %s' % err)

		results = areply.results
		if results is None or gss_proc != rpc_gss_proc.DATA or self.service == rpc_gss_service.NONE:
			return results

		buff = io.BytesIO(results)
		if self.service == rpc_gss_service.INTEGRITY:
			body = unpack_opaque(buff)
			mic = unpack_opaque(buff)
			_, err = await self.gssctx.verify_mic(body, mic)
			if err is not None:
				raise RPCGSSException('Signature of the server on the results is not valid! %s' % err)
		else:
			body, confidential, err = await self.gssctx.unwrap(unpack_opaque(buff))
			if err is not None:
				raise RPCGSSException('Could not decrypt the results! %s' % err)
			if confidential is False:
				raise RPCGSSException('Server sent the results without encryption')
		if len(body) < 4 or int.from_bytes(body[:4], byteorder = 'big', signed = False) != seq_num:
			raise RPCGSSException('Results are not for this call (sequence number mismatch)')
		return body[4:]

	async def call(self, rpc, program, version, procedure, data):
		"""
		Performs a call on the RPC connection with this credential, returns the results
		"""
		for attempt in range(2):
			await self.establish(rpc, program, version)
			handle = self.handle
			try:
				seq_num = None
				async def prepare(xid):
					nonlocal seq_num
					seq_num, cred, verf, pdata = await self.prepare(xid, program, version, procedure, data)
					return cred, verf, pdata
				areply = await rpc.call_raw(program, version, procedure, None, prepare)
				return await self.process_reply(seq_num, areply)
			except RPCReplyDeniedException as e:
				# the server does not have the context (any more), eg. it was restarted
				if attempt == 0 and e.auth_stat in (auth_stat.RPCSEC_GSS_CREDPROBLEM, auth_stat.RPCSEC_GSS_CTXPROBLEM):
					logger.debug('Server dropped the RPCSEC_GSS context, creating a new one')
					if self.handle == handle:
						self.reset()
					continue
				raise

	async def destroy(self, rpc, program, version):
		"""
		Tells the server that the context is not needed any more
		"""
		if self.handle is None:
			return
		try:
			seq_num = None
			async def prepare(xid):
				nonlocal seq_num
				seq_num, cred, verf, pdata = await self.prepare(xid, program, version, 0, b'', gss_proc = rpc_gss_proc.DESTROY)
				return cred, verf, pdata
			await rpc.call_raw(program, version, 0, None, prepare)
		except Exception as e:
			logger.debug('RPCSEC_GSS context destroy failed: %s' % e)
		finally:
			self.reset()
