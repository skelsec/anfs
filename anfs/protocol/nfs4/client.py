#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import os
import asyncio

from anfs.protocol.rpc import RPC
from anfs.protocol.rpc.common.exceptions import RPCException
from anfs.protocol.nfs3.pack import NFSFileEntry
from anfs.protocol.nfs4 import logger
from anfs.protocol.nfs4.constants import *
from anfs.protocol.nfs4.xdr import Compound, stateid4, STATEID_ANONYMOUS, FATTR4_DEFAULT

# https://datatracker.ietf.org/doc/html/rfc8881

# The room left for the RPC and COMPOUND headers when the IO size is derived from the size limits of the session
NFS4_IO_OVERHEAD = 1024
# NFSv4.0 IO size: what is used when the server does not tell its limits, and what is never exceeded
NFS4_IO_DEFAULT = 65536
NFS4_IO_MAX = 1024 * 1024

# The session is gone on the server (eg. the lease ran out while we were idle), a new one is needed
NFS4_SESSION_LOST = (
	nfsstat4.NFS4ERR_BADSESSION, nfsstat4.NFS4ERR_DEADSESSION, nfsstat4.NFS4ERR_STALE_CLIENTID,
	nfsstat4.NFS4ERR_EXPIRED, nfsstat4.NFS4ERR_SEQ_MISORDERED, nfsstat4.NFS4ERR_SEQ_FALSE_RETRY,
	nfsstat4.NFS4ERR_BADSLOT, nfsstat4.NFS4ERR_CONN_NOT_BOUND_TO_SESSION,
)
# The server asks us to come back later
NFS4_RETRY_LATER = (nfsstat4.NFS4ERR_DELAY, nfsstat4.NFS4ERR_GRACE)
NFS4_RETRY_COUNT = 10

class NFS4Error(Exception):
	def __init__(self, status, op = None):
		self.code = status
		self.op = op
		try:
			self.status = nfsstat4(status)
			name = self.status.name
		except ValueError:
			self.status = status
			name = 'unknown error %s' % status
		opname = op.name if isinstance(op, OP) else str(op)
		super().__init__('%s failed: %s' % (opname, name) if op is not None else name)

def owner_to_id(owner):
	"""
	NFSv4 sends the owner of a file as a string. It is either "name@domain" or, when the
	server does no id mapping (the usual case with AUTH_SYS), the numeric id as a string.
	"""
	if owner is None:
		return None
	if owner.isdigit():
		return int(owner)
	return owner

def entry_from_attrs(attrs, name = None):
	entry = NFSFileEntry()
	entry.name = name
	entry.type = attrs.get('type')
	entry.mode = attrs.get('mode')
	entry.nlink = attrs.get('numlinks')
	entry.owner = attrs.get('owner')
	entry.group = attrs.get('owner_group')
	entry.uid = owner_to_id(entry.owner)
	entry.gid = owner_to_id(entry.group)
	entry.size = attrs.get('size')
	entry.used = attrs.get('space_used')
	entry.fsid = attrs.get('fsid')
	entry.fileid = attrs.get('fileid')
	entry.atime = attrs.get('time_access')
	entry.mtime = attrs.get('time_modify')
	entry.ctime = attrs.get('time_metadata')
	return entry

class NFSv4Client:
	"""
	NFSv4.0 / NFSv4.1 / NFSv4.2 client.

	There is no mount protocol in NFSv4: the server has one namespace, all exports are below
	its root. Handle 0 is the root of the server, everything else is reached by lookups.

	Files are read and written with the anonymous stateid by default, no open state
	is kept on the server.

	NFSv4.1 and above run everything in a session. NFSv4.0 has none: its operations are
	sent as they are, and the client registers itself (SETCLIENTID) only when a file is opened.
	"""
	def __init__(self, target, credential = None, encoding = 'utf-8', minorversion = 1):
		self.target = target
		self.credential = credential
		self.encoding = encoding
		self.minorversion = minorversion
		self.rpc:RPC = None
		self.host = ''
		self.root_handle = None
		self.server_info = None

		self.clientid = None
		self.sessionid = None
		self.fore_chan_attrs = None
		self.__slots = None
		self.__highest_slot = 0
		self.__session_generation = 0
		self.__session_lock = asyncio.Lock()
		self.__open_owner = b'anfs-' + os.urandom(4).hex().encode()
		# NFSv4.0: IO size limits of the server and the next seqid of the open-owner behind each open stateid
		self.__io_limits = None
		self.__open_seqids = {}
		self.__clientid_lock = asyncio.Lock()

		self.__handle_id = 1
		self.__handles = {}
		self.__handle_name_map = {}
		self.__parent_handles = {}
		self.__handle_reverse_map = {}

	async def __aenter__(self):
		_, err = await self.connect()
		if err is not None:
			raise err
		return self

	async def __aexit__(self, exc_type, exc, tb):
		await self.disconnect()

	##### handle bookkeeping, same as in the NFSv3 client
	def handle_to_path(self, handle, parts = None):
		if isinstance(handle, int):
			handle = self.__handles[handle]
		if handle not in self.__handle_name_map:
			return ''
		if parts is None:
			parts = []
		if self.__handle_name_map[handle] in parts:
			return '/'.join(parts)

		parts.insert(0, self.__handle_name_map[handle])
		if handle == self.root_handle:
			return '/'.join(parts)[1:]
		return self.handle_to_path(self.__parent_handles[handle], parts)

	def register_handle(self, handle, name, parent_handle):
		if handle is None:
			return None
		if handle in self.__handle_reverse_map:
			return self.__handle_reverse_map[handle]
		self.__handles[self.__handle_id] = handle
		self.__handle_reverse_map[handle] = self.__handle_id
		self.__handle_id += 1
		rethandle = self.__handle_id - 1
		if name == '.' or name == '..':
			return rethandle
		self.__handle_name_map[handle] = name
		self.__parent_handles[handle] = parent_handle
		return rethandle

	def get_raw_handle(self, handle):
		"""The filehandle as the server knows it"""
		return self.__handles[handle]

	def __encode(self, name):
		if isinstance(name, bytes):
			return name
		return name.encode(self.encoding)

	##### connection and session
	async def connect(self):
		try:
			self.rpc = RPC(self.target, self.credential)
			_, err = await self.rpc.connect(NFS_PROGRAM, NFS_V4)
			if err is not None:
				raise err
			self.host = self.target.get_hostname_or_ip()
			if self.minorversion > 0:
				await self.__establish_session(0)

			res = await self.compound(Compound(self.minorversion).putrootfh().getfh())
			self.root_handle = res[1]
			if self.minorversion == 0:
				await self.__get_io_limits()
			self.__handles[0] = self.root_handle
			self.__handle_name_map[self.root_handle] = '/'
			self.__handle_reverse_map[self.root_handle] = 0
			return True, None
		except Exception as e:
			await self.disconnect()
			return False, e

	async def disconnect(self):
		if self.rpc is None:
			return
		try:
			if self.minorversion > 0 and self.sessionid is not None:
				await self.__call(Compound(self.minorversion).destroy_session(self.sessionid))
				await self.__call(Compound(self.minorversion).destroy_clientid(self.clientid))
		except Exception:
			pass
		self.sessionid = None
		self.clientid = None
		rpc = self.rpc
		self.rpc = None
		return await rpc.disconnect()

	async def __call(self, compound, data = None, auth = None):
		"""Sends one COMPOUND as it is"""
		if data is None:
			data = compound.to_bytes()
		res, err = await self.rpc.call(NFS_PROGRAM, NFS_V4, NFSPROC4_COMPOUND, data, auth)
		if err is not None:
			raise err
		return compound.results(res)

	async def __establish_session(self, generation):
		"""
		Registers a new client and creates a session. 'generation' is the session the
		caller found broken, if someone else has replaced that already nothing is done.
		"""
		async with self.__session_lock:
			if generation != self.__session_generation:
				return
			status, results = await self.__call(Compound(self.minorversion).exchange_id(os.urandom(NFS4_VERIFIER_SIZE), b'anfs-' + os.urandom(8).hex().encode()))
			if status != 0:
				raise NFS4Error(status, results[-1][0] if len(results) > 0 else OP.EXCHANGE_ID)
			exchange = results[0][2]
			self.clientid = exchange['clientid']
			self.server_info = exchange

			status, results = await self.__call(Compound(self.minorversion).create_session(self.clientid, exchange['sequenceid']))
			if status != 0:
				raise NFS4Error(status, OP.CREATE_SESSION)
			session = results[0][2]
			self.sessionid = session['sessionid']
			self.fore_chan_attrs = session['fore_chan_attrs']

			self.__highest_slot = max(1, self.fore_chan_attrs['maxrequests']) - 1
			self.__slots = asyncio.Queue()
			for slotid in range(self.__highest_slot + 1):
				self.__slots.put_nowait([slotid, 1])
			self.__session_generation += 1
			logger.debug('NFSv4 session %s established on %s' % (self.sessionid.hex(), self.host))

		# tells the server that we have no state to reclaim from before its restart
		try:
			await self.compound(Compound(self.minorversion).reclaim_complete(), _recover = False)
		except NFS4Error as e:
			if e.status != nfsstat4.NFS4ERR_COMPLETE_ALREADY:
				raise

	async def __get_io_limits(self):
		"""NFSv4.0: there is no session to tell the size limits, the server has them as attributes"""
		self.__io_limits = {'maxread' : NFS4_IO_DEFAULT, 'maxwrite' : NFS4_IO_DEFAULT}
		try:
			res = await self.compound(Compound(0).putrootfh().getattr([FATTR4_MAXREAD, FATTR4_MAXWRITE]))
			for name in self.__io_limits:
				if res[1].get(name):
					self.__io_limits[name] = min(res[1][name], NFS4_IO_MAX)
		except NFS4Error:
			pass

	async def __setclientid(self, auth = None):
		"""NFSv4.0: registers the client, needed only for opening files"""
		async with self.__clientid_lock:
			res = await self.compound(Compound(0).setclientid(os.urandom(NFS4_VERIFIER_SIZE), b'anfs-' + os.urandom(8).hex().encode()), auth)
			await self.compound(Compound(0).setclientid_confirm(res[0]['clientid'], res[0]['confirm']), auth)
			self.clientid = res[0]['clientid']

	async def __compound40(self, compound, auth = None):
		for attempt in range(NFS4_RETRY_COUNT):
			status, results = await self.__call(compound, auth = auth)
			if status == 0:
				# same layout as with a session, where the result of the SEQUENCE is cut off
				return [r[2] for r in results]
			failed = results[-1] if len(results) > 0 else (None, status, None)
			if status in NFS4_RETRY_LATER:
				await asyncio.sleep(min(0.1 * (2 ** attempt), 5))
				continue
			break
		raise NFS4Error(status, failed[0])

	async def compound(self, compound, auth = None, _recover = True):
		"""
		Runs the operations in 'compound' (on a slot of the session, if the protocol version
		has sessions) and returns the list of their results. Raises NFS4Error if one of the
		operations failed.
		"""
		if self.minorversion == 0:
			return await self.__compound40(compound, auth)
		for attempt in range(NFS4_RETRY_COUNT):
			generation = self.__session_generation
			sessionid = self.sessionid
			slots = self.__slots
			slot = await slots.get()
			try:
				seq = Compound(self.minorversion).sequence(sessionid, slot[1], slot[0], self.__highest_slot)
				# the operations of both compounds go into one argument array
				data = self.__merge(seq, compound)
				res, err = await self.rpc.call(NFS_PROGRAM, NFS_V4, NFSPROC4_COMPOUND, data, auth)
				if err is not None:
					raise err
				status, results = self.__merged_results(seq, compound, res)
				if len(results) > 0 and results[0][1] == 0:
					# the server has executed the SEQUENCE, the slot moves on
					slot[1] += 1
				elif status == nfsstat4.NFS4ERR_RETRY_UNCACHED_REP:
					slot[1] += 1
			finally:
				slots.put_nowait(slot)

			if status == 0:
				return [r[2] for r in results[1:]]

			failed = results[-1] if len(results) > 0 else (OP.SEQUENCE, status, None)
			if status == nfsstat4.NFS4ERR_RETRY_UNCACHED_REP:
				# The reply of the previous call on this slot did not arrive (or was not valid),
				# the server takes this call for a repeat of that one. The slot is past that now.
				continue
			if status in NFS4_SESSION_LOST and failed[0] == OP.SEQUENCE and _recover is True:
				logger.debug('NFSv4 session lost (%s), creating a new one' % nfsstat4(status).name)
				await self.__establish_session(generation)
				continue
			if status in NFS4_RETRY_LATER:
				await asyncio.sleep(min(0.1 * (2 ** attempt), 5))
				continue
			raise NFS4Error(status, failed[0])
		raise NFS4Error(status, failed[0])

	@staticmethod
	def __merge(first, second):
		header = Compound(first.minorversion, second.tag).to_header(len(first) + len(second))
		return header + first.packer.get_buffer() + second.packer.get_buffer()

	@staticmethod
	def __merged_results(first, second, data):
		merged = Compound(first.minorversion)
		merged.decoders = first.decoders + second.decoders
		return merged.results(data)

	async def null(self):
		return await self.rpc.call(NFS_PROGRAM, NFS_V4, NFSPROC4_NULL, b'')

	def max_read_size(self):
		if self.minorversion == 0:
			return self.__io_limits['maxread']
		return max(4096, self.fore_chan_attrs['maxresponsesize'] - NFS4_IO_OVERHEAD)

	def max_write_size(self):
		if self.minorversion == 0:
			return self.__io_limits['maxwrite']
		return max(4096, self.fore_chan_attrs['maxrequestsize'] - NFS4_IO_OVERHEAD)

	def __entry(self, fh, attrs, name, parent_handle):
		entry = entry_from_attrs(attrs, name)
		entry.handle = self.register_handle(fh, name, parent_handle)
		return entry

	##### reading
	async def getattr(self, file_handle, auth = None):
		try:
			fh = self.__handles[file_handle]
			logger.debug('NFSv4 GETATTR on %s' % self.host)
			res = await self.compound(Compound(self.minorversion).putfh(fh).getattr(), auth)
			entry = entry_from_attrs(res[1], self.__handle_name_map.get(fh))
			entry.handle = file_handle
			return entry, None
		except Exception as e:
			return False, e

	async def lookup(self, dir_handle, file_folder, auth = None):
		try:
			dir_fh = self.__handles[dir_handle]
			logger.debug('NFSv4 LOOKUP on %s' % self.host)
			c = Compound(self.minorversion).putfh(dir_fh)
			if file_folder == '..':
				c.lookupp()
			elif file_folder != '.':
				c.lookup(self.__encode(file_folder))
			res = await self.compound(c.getfh().getattr(), auth)
			return self.__entry(res[-2], res[-1], file_folder, dir_fh), None
		except Exception as e:
			return False, e

	async def lookup_path(self, path, auth = None):
		"""Resolves a path relative to the root of the server, eg. '/srv/exports/rw/hello.txt'"""
		try:
			entry, err = await self.getattr(0, auth)
			if err is not None:
				raise err
			for part in path.split('/'):
				if part == '':
					continue
				entry, err = await self.lookup(entry.handle, part, auth)
				if err is not None:
					raise err
			return entry, None
		except Exception as e:
			return False, e

	async def access(self, file_handle, access_option = 0x3f, auth = None):
		"""Returns the subset of the ACCESS4_* rights in 'access_option' that the server would grant"""
		try:
			fh = self.__handles[file_handle]
			logger.debug('NFSv4 ACCESS on %s' % self.host)
			res = await self.compound(Compound(self.minorversion).putfh(fh).access(access_option), auth)
			return res[1]['access'], None
		except Exception as e:
			return False, e

	async def secinfo(self, file_handle, name = None, auth = None):
		"""
		The security flavors the server accepts for the handle, or for 'name' in the directory
		of the handle. Returns a list of dictionaries, 'flavor' is the RPC auth flavor,
		for RPCSEC_GSS (6) the mechanism 'oid' and the 'service' is also there.
		"""
		try:
			fh = self.__handles[file_handle]
			logger.debug('NFSv4 SECINFO on %s' % self.host)
			c = Compound(self.minorversion).putfh(fh)
			if name is None:
				if self.minorversion == 0:
					raise NotImplementedError('NFSv4.0 can ask the security flavors only by name')
				c.secinfo_no_name()
			else:
				c.secinfo(self.__encode(name))
			res = await self.compound(c, auth)
			return res[1], None
		except Exception as e:
			return False, e

	async def readlink(self, file_handle, auth = None):
		try:
			fh = self.__handles[file_handle]
			logger.debug('NFSv4 READLINK on %s' % self.host)
			res = await self.compound(Compound(self.minorversion).putfh(fh).readlink(), auth)
			return res[1].decode(self.encoding), None
		except Exception as e:
			return False, e

	async def read(self, file_handle, offset = 0, chunk_count = 1024 * 1024, auth = None, stateid = None):
		"""Reads at most chunk_count bytes, the server may return less"""
		try:
			fh = self.__handles[file_handle]
			if stateid is None:
				stateid = STATEID_ANONYMOUS
			chunk_count = min(chunk_count, self.max_read_size())
			logger.debug('NFSv4 READ on %s' % self.host)
			res = await self.compound(Compound(self.minorversion).putfh(fh).read(stateid, offset, chunk_count), auth)
			return res[1]['data'], None
		except Exception as e:
			return False, e

	async def readdir(self, dir_handle, auth = None, maxcount = 32768):
		"""
		Yields the entries of a directory with their attributes and handles.
		Unlike in NFSv3 the server does not list '.' and '..'
		"""
		try:
			dir_fh = self.__handles[dir_handle]
			maxcount = min(maxcount, self.max_read_size())
			attrs = FATTR4_DEFAULT + [FATTR4_FILEHANDLE, FATTR4_RDATTR_ERROR]
			cookie = 0
			cookieverf = b'\x00' * NFS4_VERIFIER_SIZE
			while True:
				logger.debug('NFSv4 READDIR on %s' % self.host)
				c = Compound(self.minorversion).putfh(dir_fh).readdir(cookie, cookieverf, maxcount // 4, maxcount, attrs)
				res = (await self.compound(c, auth))[1]
				cookieverf = res['cookieverf']
				for item in res['entries']:
					cookie = item['cookie']
					name = item['name'].decode(self.encoding, errors = 'replace')
					fh = item['attrs'].get('filehandle')
					if fh is None or item['attrs'].get('rdattr_error', 0) != 0:
						# eg. the entry is the root of another export, ask for it directly
						entry, err = await self.lookup(dir_handle, name, auth)
						if err is not None:
							entry = entry_from_attrs(item['attrs'], name)
						yield entry, None
						continue
					yield self.__entry(fh, item['attrs'], name, dir_fh), None
				if res['eof'] is True or len(res['entries']) == 0:
					break
		except Exception as e:
			yield False, e

	# the name the NFSv3 client uses
	readdirplus = readdir

	##### writing
	async def open(self, dir_handle, file_name, write = False, create = False, exclusive = False, mode = None, auth = None):
		"""
		Opens (and optionally creates) a file, creating open state on the server.
		Returns the entry of the file and the stateid that must be given to close()
		"""
		try:
			dir_fh = self.__handles[dir_handle]
			share = OPEN4_SHARE_ACCESS_BOTH if write is True or create is True else OPEN4_SHARE_ACCESS_READ
			createmode = GUARDED4 if exclusive is True else UNCHECKED4
			logger.debug('NFSv4 OPEN on %s' % self.host)
			if self.minorversion == 0:
				return await self.__open40(dir_fh, file_name, share, create, createmode, mode, auth), None
			c = Compound(self.minorversion).putfh(dir_fh)
			c.open(self.clientid, self.__open_owner, share, self.__encode(file_name), create, createmode, mode = mode)
			res = await self.compound(c.getfh().getattr(), auth)
			return (self.__entry(res[2], res[3], file_name, dir_fh), res[1]['stateid']), None
		except Exception as e:
			return False, e

	async def __open40(self, dir_fh, file_name, share, create, createmode, mode, auth):
		"""
		NFSv4.0: the opens of an open-owner are ordered by a sequence number. Every open gets
		an owner of its own here, so the opens do not have to wait for each other.
		"""
		for attempt in range(2):
			if self.clientid is None:
				await self.__setclientid(auth)
			owner = b'anfs-' + os.urandom(8).hex().encode()
			c = Compound(0).putfh(dir_fh)
			c.open(self.clientid, owner, share, self.__encode(file_name), create, createmode, seqid = 0, mode = mode)
			try:
				res = await self.compound(c.getfh().getattr(), auth)
				break
			except NFS4Error as e:
				# the registration is forgotten when nothing is open for the time of the lease
				if attempt == 0 and e.status in (nfsstat4.NFS4ERR_STALE_CLIENTID, nfsstat4.NFS4ERR_EXPIRED):
					self.clientid = None
					continue
				raise
		stateid = res[1]['stateid']
		seqid = 1
		if res[1]['rflags'] & OPEN4_RESULT_CONFIRM:
			confirm = await self.compound(Compound(0).putfh(res[2]).open_confirm(stateid, seqid), auth)
			stateid = confirm[1]
			seqid += 1
		self.__open_seqids[stateid.other] = seqid
		return self.__entry(res[2], res[3], file_name, dir_fh), stateid

	async def close(self, file_handle, stateid, auth = None):
		try:
			fh = self.__handles[file_handle]
			logger.debug('NFSv4 CLOSE on %s' % self.host)
			seqid = self.__open_seqids.pop(stateid.other, 0)
			await self.compound(Compound(self.minorversion).putfh(fh).close(stateid, seqid), auth)
			return True, None
		except Exception as e:
			return False, e

	async def create(self, dir_handle, file_name, exclusive = False, mode = 0o644, auth = None):
		"""Creates a regular file. With exclusive the call fails if the file exists already"""
		try:
			res, err = await self.open(dir_handle, file_name, create = True, exclusive = exclusive, mode = mode, auth = auth)
			if err is not None:
				raise err
			entry, stateid = res
			_, err = await self.close(entry.handle, stateid, auth)
			if err is not None:
				raise err
			return entry, None
		except Exception as e:
			return False, e

	async def write(self, file_handle, offset, content, stable_how = FILE_SYNC4, auth = None, stateid = None):
		"""Writes all of content, returns the number of bytes written"""
		try:
			fh = self.__handles[file_handle]
			if stateid is None:
				stateid = STATEID_ANONYMOUS
			chunk = self.max_write_size()
			total = 0
			while total < len(content):
				logger.debug('NFSv4 WRITE on %s' % self.host)
				c = Compound(self.minorversion).putfh(fh).write(stateid, offset + total, content[total : total + chunk], stable_how)
				res = await self.compound(c, auth)
				if res[1]['count'] == 0:
					raise Exception('Server wrote 0 bytes')
				total += res[1]['count']
			return total, None
		except Exception as e:
			return False, e

	async def commit(self, file_handle, count = 0, offset = 0, auth = None):
		try:
			fh = self.__handles[file_handle]
			logger.debug('NFSv4 COMMIT on %s' % self.host)
			await self.compound(Compound(self.minorversion).putfh(fh).commit(offset, count), auth)
			return True, None
		except Exception as e:
			return False, e

	async def __create(self, dir_handle, name, ftype, auth, **kwargs):
		dir_fh = self.__handles[dir_handle]
		logger.debug('NFSv4 CREATE on %s' % self.host)
		c = Compound(self.minorversion).putfh(dir_fh).create(ftype, self.__encode(name), **kwargs)
		res = await self.compound(c.getfh().getattr(), auth)
		return self.__entry(res[2], res[3], name, dir_fh)

	async def mkdir(self, dir_handle, dir_name, mode = 0o755, auth = None):
		try:
			return await self.__create(dir_handle, dir_name, NF4DIR, auth, mode = mode), None
		except Exception as e:
			return False, e

	async def symlink(self, dir_handle, link_name, link_to_path, auth = None):
		try:
			return await self.__create(dir_handle, link_name, NF4LNK, auth, linkdata = self.__encode(link_to_path)), None
		except Exception as e:
			return False, e

	async def mknod(self, dir_handle, file_name, ftype, mode = 0o644, spec_major = 0, spec_minor = 0, auth = None):
		try:
			if ftype not in (NF4BLK, NF4CHR, NF4SOCK, NF4FIFO):
				raise ValueError('ftype must be one of [%d, %d, %d, %d]' % (NF4BLK, NF4CHR, NF4SOCK, NF4FIFO))
			return await self.__create(dir_handle, file_name, ftype, auth, specdata = (spec_major, spec_minor), mode = mode), None
		except Exception as e:
			return False, e

	async def remove(self, dir_handle, file_name, auth = None):
		"""Removes a file or an empty directory"""
		try:
			dir_fh = self.__handles[dir_handle]
			logger.debug('NFSv4 REMOVE on %s' % self.host)
			await self.compound(Compound(self.minorversion).putfh(dir_fh).remove(self.__encode(file_name)), auth)
			return True, None
		except Exception as e:
			return False, e

	# NFSv4 has one operation for both
	rmdir = remove

	async def rename(self, dir_handle_from, from_name, dir_handle_to, to_name, auth = None):
		try:
			fh_from = self.__handles[dir_handle_from]
			fh_to = self.__handles[dir_handle_to]
			logger.debug('NFSv4 RENAME on %s' % self.host)
			c = Compound(self.minorversion).putfh(fh_from).savefh().putfh(fh_to)
			await self.compound(c.rename(self.__encode(from_name), self.__encode(to_name)), auth)
			return True, None
		except Exception as e:
			return False, e

	async def link(self, file_handle, link_to_dir_handle, link_name, auth = None):
		try:
			fh = self.__handles[file_handle]
			dir_fh = self.__handles[link_to_dir_handle]
			logger.debug('NFSv4 LINK on %s' % self.host)
			c = Compound(self.minorversion).putfh(fh).savefh().putfh(dir_fh)
			await self.compound(c.link(self.__encode(link_name)), auth)
			return True, None
		except Exception as e:
			return False, e

	async def setattr(self, file_handle, mode = None, uid = None, gid = None, size = None, auth = None, stateid = None):
		"""
		Changes the attributes that are not None. uid and gid can be numbers or
		"name@domain" strings, the latter needs id mapping to be set up on the server.
		"""
		try:
			fh = self.__handles[file_handle]
			if stateid is None:
				stateid = STATEID_ANONYMOUS
			logger.debug('NFSv4 SETATTR on %s' % self.host)
			c = Compound(self.minorversion).putfh(fh).setattr(stateid, mode = mode, size = size, owner = uid, owner_group = gid)
			await self.compound(c, auth)
			return True, None
		except Exception as e:
			return False, e
