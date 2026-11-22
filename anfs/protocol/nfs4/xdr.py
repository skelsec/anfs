import datetime

try:
	from xdrlib import Packer, Unpacker
except ImportError:
	from xdrlib3 import Packer, Unpacker

from anfs.protocol.nfs4.constants import *

# https://datatracker.ietf.org/doc/html/rfc5662

class stateid4:
	def __init__(self, seqid = 0, other = b'\x00' * NFS4_OTHER_SIZE):
		self.seqid = seqid
		self.other = other

	def pack(self, packer):
		packer.pack_uint(self.seqid)
		packer.pack_fopaque(NFS4_OTHER_SIZE, self.other)

	@staticmethod
	def unpack(unpacker):
		return stateid4(unpacker.unpack_uint(), unpacker.unpack_fopaque(NFS4_OTHER_SIZE))

	def __repr__(self):
		return 'stateid4(%s, %s)' % (self.seqid, self.other.hex())

# Special stateids: IO with these is done without any open state on the server
STATEID_ANONYMOUS = stateid4(0, b'\x00' * NFS4_OTHER_SIZE)
STATEID_BYPASS = stateid4(0xffffffff, b'\xff' * NFS4_OTHER_SIZE)
# 4.1: "the stateid of the OPEN earlier in this compound"
STATEID_CURRENT = stateid4(1, b'\x00' * NFS4_OTHER_SIZE)

##### bitmap4
def pack_bitmap(packer, attrs):
	words = []
	for attr in attrs:
		idx = attr // 32
		while len(words) <= idx:
			words.append(0)
		words[idx] |= 1 << (attr % 32)
	packer.pack_uint(len(words))
	for word in words:
		packer.pack_uint(word)

def unpack_bitmap(unpacker):
	"""Returns the sorted list of the attribute numbers set in the bitmap"""
	attrs = []
	for idx in range(unpacker.unpack_uint()):
		word = unpacker.unpack_uint()
		for bit in range(32):
			if word & (1 << bit):
				attrs.append(idx * 32 + bit)
	return attrs

##### fattr4
def unpack_nfstime4(unpacker):
	seconds = unpacker.unpack_hyper()
	nseconds = unpacker.unpack_uint()
	try:
		return datetime.datetime.fromtimestamp(seconds + (nseconds / 1_000_000_000.0))
	except (OverflowError, OSError, ValueError):
		return None

def unpack_fsid4(unpacker):
	return (unpacker.unpack_uhyper(), unpacker.unpack_uhyper())

def unpack_specdata4(unpacker):
	return (unpacker.unpack_uint(), unpacker.unpack_uint())

##### nfsace4
ACE4_TYPES = {0 : 'A', 1 : 'D', 2 : 'U', 3 : 'L'}
ACE4_FLAGS = [(0x01, 'f'), (0x02, 'd'), (0x04, 'n'), (0x08, 'i'), (0x10, 'S'), (0x20, 'F'), (0x40, 'g')]
ACE4_MASKS = [
	(0x00000001, 'r'), (0x00000002, 'w'), (0x00000004, 'a'), (0x00000020, 'x'), (0x00010000, 'd'), (0x00000040, 'D'),
	(0x00000080, 't'), (0x00000100, 'T'), (0x00000008, 'n'), (0x00000010, 'N'), (0x00020000, 'c'), (0x00040000, 'C'),
	(0x00080000, 'o'), (0x00100000, 'y'),
]
ACE4_IDENTIFIER_GROUP = 0x40

class nfsace4:
	"""
	One entry of an NFSv4 ACL. The text form is the one nfs4_getfacl prints: type:flags:who:permissions

	type         A allow, D deny, U audit, L alarm
	flags        f file inherit, d directory inherit, n no propagate, i inherit only, g 'who' is a group
	who          OWNER@, GROUP@, EVERYONE@, or a user / group like the owner of a file: name@domain or a numeric id
	permissions  r read / list, w write / create file, a append / create directory, x execute / enter,
	             d delete, D delete child, t read attributes, T write attributes, n read named attributes,
	             N write named attributes, c read ACL, C write ACL, o change owner, y synchronize
	"""
	def __init__(self, acetype = 0, flag = 0, access_mask = 0, who = 'EVERYONE@'):
		self.type = acetype
		self.flag = flag
		self.access_mask = access_mask
		self.who = who

	def pack(self, packer):
		packer.pack_uint(self.type)
		packer.pack_uint(self.flag)
		packer.pack_uint(self.access_mask)
		packer.pack_opaque(str(self.who).encode('utf-8'))

	@staticmethod
	def unpack(unpacker):
		return nfsace4(unpacker.unpack_uint(), unpacker.unpack_uint(), unpacker.unpack_uint(), unpack_utf8(unpacker))

	@staticmethod
	def from_string(line):
		parts = line.strip().split(':')
		if len(parts) < 4:
			raise ValueError('Not an ACE: "%s", the format is type:flags:who:permissions eg. A::1000:rx' % line)
		# the name in the middle may have colons in it
		acetype, flags, who, perms = parts[0], parts[1], ':'.join(parts[2:-1]), parts[-1]
		ace = nfsace4(who = who)
		for value, letter in ACE4_TYPES.items():
			if letter == acetype.upper():
				ace.type = value
				break
		else:
			raise ValueError('Unknown ACE type "%s"' % acetype)
		for letters, table, name in [(flags, ACE4_FLAGS, 'flag'), (perms, ACE4_MASKS, 'permission')]:
			value = 0
			for letter in letters:
				for bit, bitletter in table:
					if bitletter == letter:
						value |= bit
						break
				else:
					raise ValueError('Unknown ACE %s "%s"' % (name, letter))
			if name == 'flag':
				ace.flag = value
			else:
				ace.access_mask = value
		return ace

	def is_group(self):
		return bool(self.flag & ACE4_IDENTIFIER_GROUP)

	def to_dict(self):
		return {'type' : self.type, 'flag' : self.flag, 'access_mask' : self.access_mask, 'who' : self.who}

	def __eq__(self, other):
		return isinstance(other, nfsace4) and self.to_dict() == other.to_dict()

	def __str__(self):
		flags = ''.join(letter for bit, letter in ACE4_FLAGS if self.flag & bit)
		perms = ''.join(letter for bit, letter in ACE4_MASKS if self.access_mask & bit)
		return '%s:%s:%s:%s' % (ACE4_TYPES.get(self.type, self.type), flags, self.who, perms)

	def __repr__(self):
		return 'nfsace4(%s)' % self

def unpack_acl(unpacker):
	return [nfsace4.unpack(unpacker) for _ in range(unpacker.unpack_uint())]

def unpack_utf8(unpacker):
	return unpacker.unpack_opaque().decode('utf-8', errors = 'replace')

# attribute number -> (name, decoder). The attributes are encoded in the order of
# their numbers, an attribute missing from this table can not be skipped over.
FATTR4_DECODERS = {
	FATTR4_SUPPORTED_ATTRS : ('supported_attrs', unpack_bitmap),
	FATTR4_TYPE : ('type', Unpacker.unpack_uint),
	FATTR4_FH_EXPIRE_TYPE : ('fh_expire_type', Unpacker.unpack_uint),
	FATTR4_CHANGE : ('change', Unpacker.unpack_uhyper),
	FATTR4_SIZE : ('size', Unpacker.unpack_uhyper),
	FATTR4_LINK_SUPPORT : ('link_support', Unpacker.unpack_bool),
	FATTR4_SYMLINK_SUPPORT : ('symlink_support', Unpacker.unpack_bool),
	FATTR4_NAMED_ATTR : ('named_attr', Unpacker.unpack_bool),
	FATTR4_FSID : ('fsid', unpack_fsid4),
	FATTR4_UNIQUE_HANDLES : ('unique_handles', Unpacker.unpack_bool),
	FATTR4_LEASE_TIME : ('lease_time', Unpacker.unpack_uint),
	FATTR4_RDATTR_ERROR : ('rdattr_error', Unpacker.unpack_uint),
	FATTR4_ACL : ('acl', unpack_acl),
	FATTR4_ACLSUPPORT : ('aclsupport', Unpacker.unpack_uint),
	FATTR4_FILEHANDLE : ('filehandle', Unpacker.unpack_opaque),
	FATTR4_FILEID : ('fileid', Unpacker.unpack_uhyper),
	FATTR4_MAXREAD : ('maxread', Unpacker.unpack_uhyper),
	FATTR4_MAXWRITE : ('maxwrite', Unpacker.unpack_uhyper),
	FATTR4_MODE : ('mode', Unpacker.unpack_uint),
	FATTR4_NUMLINKS : ('numlinks', Unpacker.unpack_uint),
	FATTR4_OWNER : ('owner', unpack_utf8),
	FATTR4_OWNER_GROUP : ('owner_group', unpack_utf8),
	FATTR4_RAWDEV : ('rawdev', unpack_specdata4),
	FATTR4_SPACE_USED : ('space_used', Unpacker.unpack_uhyper),
	FATTR4_TIME_ACCESS : ('time_access', unpack_nfstime4),
	FATTR4_TIME_METADATA : ('time_metadata', unpack_nfstime4),
	FATTR4_TIME_MODIFY : ('time_modify', unpack_nfstime4),
	FATTR4_MOUNTED_ON_FILEID : ('mounted_on_fileid', Unpacker.unpack_uhyper),
}

# What is asked for every file by default, everything the 'ls -l' style listing needs
FATTR4_DEFAULT = [
	FATTR4_TYPE, FATTR4_CHANGE, FATTR4_SIZE, FATTR4_FSID, FATTR4_FILEID, FATTR4_MODE, FATTR4_NUMLINKS,
	FATTR4_OWNER, FATTR4_OWNER_GROUP, FATTR4_SPACE_USED, FATTR4_TIME_ACCESS, FATTR4_TIME_METADATA, FATTR4_TIME_MODIFY,
]

def unpack_fattr4(unpacker):
	"""Returns the attributes as a dictionary"""
	present = unpack_bitmap(unpacker)
	data = unpacker.unpack_opaque()
	attrs = {}
	au = Unpacker(data)
	for attr in present:
		if attr not in FATTR4_DECODERS:
			# everything after this one is undecodable, it's position is unknown
			attrs['undecoded'] = [a for a in present if a >= attr]
			break
		name, decoder = FATTR4_DECODERS[attr]
		attrs[name] = decoder(au)
	return attrs

def pack_fattr4(packer, mode = None, size = None, owner = None, owner_group = None, acl = None):
	"""
	Packs the settable attributes, the ones left on None are not sent.
	owner and owner_group are strings, either "user@domain" or a numeric id as string.
	acl is a list of nfsace4.
	"""
	present = []
	ap = Packer()
	# the values follow each other in the order of the attribute numbers
	if size is not None:
		present.append(FATTR4_SIZE)
		ap.pack_uhyper(size)
	if acl is not None:
		present.append(FATTR4_ACL)
		ap.pack_uint(len(acl))
		for ace in acl:
			ace.pack(ap)
	if mode is not None:
		present.append(FATTR4_MODE)
		ap.pack_uint(mode)
	if owner is not None:
		present.append(FATTR4_OWNER)
		ap.pack_opaque(str(owner).encode('utf-8'))
	if owner_group is not None:
		present.append(FATTR4_OWNER_GROUP)
		ap.pack_opaque(str(owner_group).encode('utf-8'))
	pack_bitmap(packer, present)
	packer.pack_opaque(ap.get_buffer())

def unpack_change_info4(unpacker):
	return {
		'atomic' : unpacker.unpack_bool(),
		'before' : unpacker.unpack_uhyper(),
		'after' : unpacker.unpack_uhyper(),
	}

def pack_channel_attrs4(packer, maxrequestsize, maxresponsesize, maxresponsesize_cached, maxoperations, maxrequests):
	packer.pack_uint(0) # headerpadsize
	packer.pack_uint(maxrequestsize)
	packer.pack_uint(maxresponsesize)
	packer.pack_uint(maxresponsesize_cached)
	packer.pack_uint(maxoperations)
	packer.pack_uint(maxrequests)
	packer.pack_uint(0) # rdma_ird<1>

def unpack_channel_attrs4(unpacker):
	res = {
		'headerpadsize' : unpacker.unpack_uint(),
		'maxrequestsize' : unpacker.unpack_uint(),
		'maxresponsesize' : unpacker.unpack_uint(),
		'maxresponsesize_cached' : unpacker.unpack_uint(),
		'maxoperations' : unpacker.unpack_uint(),
		'maxrequests' : unpacker.unpack_uint(),
	}
	for _ in range(unpacker.unpack_uint()):
		unpacker.unpack_uint()
	return res

def unpack_nfsace4(unpacker):
	return {
		'type' : unpacker.unpack_uint(),
		'flag' : unpacker.unpack_uint(),
		'access_mask' : unpacker.unpack_uint(),
		'who' : unpack_utf8(unpacker),
	}

def unpack_open_delegation4(unpacker):
	dtype = unpacker.unpack_uint()
	res = {'type' : dtype}
	if dtype == OPEN_DELEGATE_READ:
		res['stateid'] = stateid4.unpack(unpacker)
		res['recall'] = unpacker.unpack_bool()
		res['permissions'] = unpack_nfsace4(unpacker)
	elif dtype == OPEN_DELEGATE_WRITE:
		res['stateid'] = stateid4.unpack(unpacker)
		res['recall'] = unpacker.unpack_bool()
		limitby = unpacker.unpack_uint()
		if limitby == NFS_LIMIT_SIZE:
			res['space_limit'] = unpacker.unpack_uhyper()
		elif limitby == NFS_LIMIT_BLOCKS:
			res['space_limit'] = (unpacker.unpack_uint(), unpacker.unpack_uint())
		res['permissions'] = unpack_nfsace4(unpacker)
	elif dtype == OPEN_DELEGATE_NONE_EXT:
		why = unpacker.unpack_uint()
		res['why'] = why
		if why in (WND4_CONTENTION, WND4_RESOURCE):
			unpacker.unpack_bool()
	return res


class Compound:
	"""
	Builds the argument list of one COMPOUND call and decodes the results.

	Every method appends one operation. After the call results() gives back a list
	with one entry per operation the server executed: (OP, status, result). The server
	stops at the first failing operation, that one is the last in the list.
	"""
	def __init__(self, minorversion = 1, tag = b''):
		self.minorversion = minorversion
		self.tag = tag
		self.packer = Packer()
		self.decoders = []

	def __len__(self):
		return len(self.decoders)

	def __add(self, op, decoder = None):
		self.packer.pack_uint(op.value)
		self.decoders.append((op, decoder))
		return self.packer

	def to_header(self, opcount):
		packer = Packer()
		packer.pack_opaque(self.tag)
		packer.pack_uint(self.minorversion)
		packer.pack_uint(opcount)
		return packer.get_buffer()

	def to_bytes(self):
		return self.to_header(len(self.decoders)) + self.packer.get_buffer()

	def results(self, data):
		"""Returns the status of the compound and the list of (OP, status, result)"""
		unpacker = Unpacker(data)
		status = unpacker.unpack_uint()
		unpacker.unpack_opaque() # tag
		results = []
		for i in range(unpacker.unpack_uint()):
			resop = unpacker.unpack_uint()
			opstatus = unpacker.unpack_uint()
			if i >= len(self.decoders) or self.decoders[i][0].value != resop:
				# eg. OP_ILLEGAL for an operation the server does not know
				results.append((resop, opstatus, None))
				break
			op, decoder = self.decoders[i]
			result = None
			if opstatus == 0 and decoder is not None:
				result = decoder(unpacker)
			results.append((op, opstatus, result))
			if opstatus != 0:
				break
		return status, results

	##### session
	def exchange_id(self, verifier, ownerid, flags = 0):
		p = self.__add(OP.EXCHANGE_ID, self.__exchange_id_res)
		p.pack_fopaque(NFS4_VERIFIER_SIZE, verifier)
		p.pack_opaque(ownerid)
		p.pack_uint(flags)
		p.pack_uint(SP4_NONE)
		p.pack_uint(0) # client_impl_id<1>
		return self

	@staticmethod
	def __exchange_id_res(u):
		res = {
			'clientid' : u.unpack_uhyper(),
			'sequenceid' : u.unpack_uint(),
			'flags' : u.unpack_uint(),
		}
		how = u.unpack_uint()
		if how != SP4_NONE:
			raise Exception('Server asked for state protection %s that was not offered' % how)
		res['server_minor_id'] = u.unpack_uhyper()
		res['server_major_id'] = u.unpack_opaque()
		res['server_scope'] = u.unpack_opaque()
		res['server_impl'] = None
		for _ in range(u.unpack_uint()):
			res['server_impl'] = {
				'domain' : unpack_utf8(u),
				'name' : unpack_utf8(u),
				'date' : unpack_nfstime4(u),
			}
		return res

	def create_session(self, clientid, sequenceid, maxrequestsize = 1049620, maxresponsesize = 1049480, maxoperations = 16, maxrequests = 8):
		p = self.__add(OP.CREATE_SESSION, self.__create_session_res)
		p.pack_uhyper(clientid)
		p.pack_uint(sequenceid)
		p.pack_uint(0) # flags: no persistence, no backchannel
		pack_channel_attrs4(p, maxrequestsize, maxresponsesize, 4096, maxoperations, maxrequests)
		pack_channel_attrs4(p, 4096, 4096, 0, 2, 1)
		p.pack_uint(NFS4_CALLBACK_PROGRAM)
		p.pack_uint(1) # sec_parms<>
		p.pack_uint(0) # AUTH_NONE
		return self

	@staticmethod
	def __create_session_res(u):
		return {
			'sessionid' : u.unpack_fopaque(NFS4_SESSIONID_SIZE),
			'sequenceid' : u.unpack_uint(),
			'flags' : u.unpack_uint(),
			'fore_chan_attrs' : unpack_channel_attrs4(u),
			'back_chan_attrs' : unpack_channel_attrs4(u),
		}

	##### NFSv4.0 client registration, sessions took the place of these
	def setclientid(self, verifier, ownerid):
		p = self.__add(OP.SETCLIENTID, lambda u: {'clientid' : u.unpack_uhyper(), 'confirm' : u.unpack_fopaque(NFS4_VERIFIER_SIZE)})
		p.pack_fopaque(NFS4_VERIFIER_SIZE, verifier)
		p.pack_opaque(ownerid)
		# the callback address: there is none, the server can not give us delegations then
		p.pack_uint(NFS4_CALLBACK_PROGRAM)
		p.pack_opaque(b'tcp')
		p.pack_opaque(b'0.0.0.0.0.0')
		p.pack_uint(0) # callback_ident
		return self

	def setclientid_confirm(self, clientid, verifier):
		p = self.__add(OP.SETCLIENTID_CONFIRM)
		p.pack_uhyper(clientid)
		p.pack_fopaque(NFS4_VERIFIER_SIZE, verifier)
		return self

	def renew(self, clientid):
		self.__add(OP.RENEW).pack_uhyper(clientid)
		return self

	def destroy_session(self, sessionid):
		self.__add(OP.DESTROY_SESSION).pack_fopaque(NFS4_SESSIONID_SIZE, sessionid)
		return self

	def destroy_clientid(self, clientid):
		self.__add(OP.DESTROY_CLIENTID).pack_uhyper(clientid)
		return self

	def reclaim_complete(self, one_fs = False):
		self.__add(OP.RECLAIM_COMPLETE).pack_bool(one_fs)
		return self

	def sequence(self, sessionid, sequenceid, slotid, highest_slotid, cachethis = False):
		p = self.__add(OP.SEQUENCE, self.__sequence_res)
		p.pack_fopaque(NFS4_SESSIONID_SIZE, sessionid)
		p.pack_uint(sequenceid)
		p.pack_uint(slotid)
		p.pack_uint(highest_slotid)
		p.pack_bool(cachethis)
		return self

	@staticmethod
	def __sequence_res(u):
		return {
			'sessionid' : u.unpack_fopaque(NFS4_SESSIONID_SIZE),
			'sequenceid' : u.unpack_uint(),
			'slotid' : u.unpack_uint(),
			'highest_slotid' : u.unpack_uint(),
			'target_highest_slotid' : u.unpack_uint(),
			'status_flags' : u.unpack_uint(),
		}

	##### filehandles
	def putrootfh(self):
		self.__add(OP.PUTROOTFH)
		return self

	def putfh(self, fh):
		self.__add(OP.PUTFH).pack_opaque(fh)
		return self

	def getfh(self):
		self.__add(OP.GETFH, Unpacker.unpack_opaque)
		return self

	def savefh(self):
		self.__add(OP.SAVEFH)
		return self

	def restorefh(self):
		self.__add(OP.RESTOREFH)
		return self

	def lookup(self, name):
		self.__add(OP.LOOKUP).pack_opaque(name)
		return self

	def lookupp(self):
		self.__add(OP.LOOKUPP)
		return self

	##### security
	def secinfo(self, name):
		"""The security flavors the server accepts for 'name' in the current directory. Consumes the current filehandle."""
		self.__add(OP.SECINFO, self.__secinfo_res).pack_opaque(name)
		return self

	def secinfo_no_name(self, style = SECINFO_STYLE4_CURRENT_FH):
		"""Same for the current filehandle itself (or its parent). Consumes the current filehandle."""
		self.__add(OP.SECINFO_NO_NAME, self.__secinfo_res).pack_uint(style)
		return self

	@staticmethod
	def __secinfo_res(u):
		res = []
		for _ in range(u.unpack_uint()):
			entry = {'flavor' : u.unpack_uint()}
			if entry['flavor'] == RPCSEC_GSS:
				entry['oid'] = u.unpack_opaque()
				entry['qop'] = u.unpack_uint()
				entry['service'] = u.unpack_uint()
			res.append(entry)
		return res

	##### reading
	def getattr(self, attrs = FATTR4_DEFAULT):
		pack_bitmap(self.__add(OP.GETATTR, unpack_fattr4), attrs)
		return self

	def access(self, access):
		self.__add(OP.ACCESS, lambda u: {'supported' : u.unpack_uint(), 'access' : u.unpack_uint()}).pack_uint(access)
		return self

	def readlink(self):
		self.__add(OP.READLINK, Unpacker.unpack_opaque)
		return self

	def readdir(self, cookie = 0, cookieverf = b'\x00' * NFS4_VERIFIER_SIZE, dircount = 8192, maxcount = 32768, attrs = FATTR4_DEFAULT):
		p = self.__add(OP.READDIR, self.__readdir_res)
		p.pack_uhyper(cookie)
		p.pack_fopaque(NFS4_VERIFIER_SIZE, cookieverf)
		p.pack_uint(dircount)
		p.pack_uint(maxcount)
		pack_bitmap(p, attrs)
		return self

	@staticmethod
	def __readdir_res(u):
		res = {
			'cookieverf' : u.unpack_fopaque(NFS4_VERIFIER_SIZE),
			'entries' : [],
		}
		while u.unpack_bool():
			res['entries'].append({
				'cookie' : u.unpack_uhyper(),
				'name' : u.unpack_opaque(),
				'attrs' : unpack_fattr4(u),
			})
		res['eof'] = u.unpack_bool()
		return res

	def read(self, stateid, offset, count):
		p = self.__add(OP.READ, lambda u: {'eof' : u.unpack_bool(), 'data' : u.unpack_opaque()})
		stateid.pack(p)
		p.pack_uhyper(offset)
		p.pack_uint(count)
		return self

	##### writing
	def write(self, stateid, offset, data, stable = FILE_SYNC4):
		p = self.__add(OP.WRITE, lambda u: {'count' : u.unpack_uint(), 'committed' : u.unpack_uint(), 'writeverf' : u.unpack_fopaque(NFS4_VERIFIER_SIZE)})
		stateid.pack(p)
		p.pack_uhyper(offset)
		p.pack_uint(stable)
		p.pack_opaque(data)
		return self

	def commit(self, offset = 0, count = 0):
		p = self.__add(OP.COMMIT, lambda u: u.unpack_fopaque(NFS4_VERIFIER_SIZE))
		p.pack_uhyper(offset)
		p.pack_uint(count)
		return self

	def create(self, ftype, name, linkdata = None, specdata = (0, 0), **attrs):
		"""Creates anything but a regular file (those are created by OPEN) in the current directory"""
		p = self.__add(OP.CREATE, lambda u: {'cinfo' : unpack_change_info4(u), 'attrset' : unpack_bitmap(u)})
		p.pack_uint(ftype)
		if ftype == NF4LNK:
			p.pack_opaque(linkdata)
		elif ftype in (NF4BLK, NF4CHR):
			p.pack_uint(specdata[0])
			p.pack_uint(specdata[1])
		p.pack_opaque(name)
		pack_fattr4(p, **attrs)
		return self

	def remove(self, name):
		self.__add(OP.REMOVE, unpack_change_info4).pack_opaque(name)
		return self

	def rename(self, oldname, newname):
		"""The saved filehandle is the source directory, the current one is the target directory"""
		p = self.__add(OP.RENAME, lambda u: {'source_cinfo' : unpack_change_info4(u), 'target_cinfo' : unpack_change_info4(u)})
		p.pack_opaque(oldname)
		p.pack_opaque(newname)
		return self

	def link(self, newname):
		"""The saved filehandle is the file, the current one is the target directory"""
		self.__add(OP.LINK, unpack_change_info4).pack_opaque(newname)
		return self

	def setattr(self, stateid, **attrs):
		p = self.__add(OP.SETATTR, unpack_bitmap)
		stateid.pack(p)
		pack_fattr4(p, **attrs)
		return self

	def open(self, clientid, owner, share_access, name = None, create = False, createmode = UNCHECKED4, seqid = 0, **attrs):
		"""
		Opens a file. With a name the current filehandle is the directory the file is in (CLAIM_NULL),
		without one it is the file itself (CLAIM_FH). The current filehandle becomes the file.
		"""
		p = self.__add(OP.OPEN, self.__open_res)
		p.pack_uint(seqid) # not used with sessions
		if self.minorversion > 0:
			share_access |= OPEN4_SHARE_ACCESS_WANT_NO_DELEG
		p.pack_uint(share_access)
		p.pack_uint(OPEN4_SHARE_DENY_NONE)
		p.pack_uhyper(clientid)
		p.pack_opaque(owner)
		if create is True:
			p.pack_uint(OPEN4_CREATE)
			p.pack_uint(createmode)
			pack_fattr4(p, **attrs)
		else:
			p.pack_uint(OPEN4_NOCREATE)
		if name is not None:
			p.pack_uint(CLAIM_NULL)
			p.pack_opaque(name)
		else:
			p.pack_uint(CLAIM_FH)
		return self

	@staticmethod
	def __open_res(u):
		return {
			'stateid' : stateid4.unpack(u),
			'cinfo' : unpack_change_info4(u),
			'rflags' : u.unpack_uint(),
			'attrset' : unpack_bitmap(u),
			'delegation' : unpack_open_delegation4(u),
		}

	def open_confirm(self, stateid, seqid):
		"""NFSv4.0 only"""
		p = self.__add(OP.OPEN_CONFIRM, stateid4.unpack)
		stateid.pack(p)
		p.pack_uint(seqid)
		return self

	def close(self, stateid, seqid = 0):
		p = self.__add(OP.CLOSE, stateid4.unpack)
		p.pack_uint(seqid) # not used with sessions
		stateid.pack(p)
		return self
