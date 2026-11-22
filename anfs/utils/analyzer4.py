#!/usr/bin/env python3
#
# NFSv4 part of the security analyzer, and the access checks shared by both
# protocol versions. Used by anfs.utils.analyzer, see there for the entry point.
#
# Checks implemented:
#   - Supported NFSv4 minor versions
#   - Server identity from EXCHANGE_ID (the Linux server tells its kernel version there)
#   - Walk of the server namespace: exports are found without mountd or portmapper
#   - Security flavors accepted for every export (SECINFO)
#   - Root squash, uid spoofing and write access, tested with ACCESS only: nothing is written
#   - The same export behaving differently over NFSv3 and NFSv4
#   - CVE-2026-99362 of the Linux server (overflow of the session reply cache), by the
#     order SEQUENCE is checked in. The overflow itself is not triggered.
import binascii
import os

from anfs.protocol.rpc import RPC
from anfs.protocol.rpc.messages import AUTH_SYS
from anfs.protocol.nfs4.client import NFS4Error, owner_to_id
from anfs.protocol.nfs4.constants import (
	NFS_PROGRAM, NFS_V4, NFSPROC4_COMPOUND, NF4DIR, nfsstat4, RPCSEC_GSS, NFS4_VERIFIER_SIZE,
	RPC_GSS_SVC_NONE, RPC_GSS_SVC_INTEGRITY, RPC_GSS_SVC_PRIVACY,
)
from anfs.protocol.nfs4.xdr import Compound
from anfs.utils.analyzer_common import JSONStatus, AUTH_FLAVOR_NAMES, auth_flavor_to_str, format_table

# The ACCESS bits have the same values in NFSv3 and NFSv4
ACCESS_READ = 0x01
ACCESS_MODIFY = 0x04
ACCESS_EXTEND = 0x08

NOBODY = 65534
KRB5_OID = bytes.fromhex('2a864886f712010202')
GSS_SERVICE_FLAVORS = {
	RPC_GSS_SVC_NONE : 390003,
	RPC_GSS_SVC_INTEGRITY : 390004,
	RPC_GSS_SVC_PRIVACY : 390005,
}

# Who wrote the server, by the domain it gives in EXCHANGE_ID
IMPL_DOMAINS = {
	'kernel.org' : 'Linux',
	'netapp.com' : 'NetApp',
	'freebsd.org' : 'FreeBSD',
	'microsoft.com' : 'Windows',
	'oracle.com' : 'Solaris',
	'sun.com' : 'Solaris',
	'nfs-ganesha.org' : 'NFS-Ganesha',
	'emc.com' : 'EMC',
	'isilon.com' : 'Isilon',
}

# CVE-2026-99362: the smallest reply size the Linux server takes for a session, a SEQUENCE
# result does not fit in it. The reply cache of the slots has to be larger than any reply
# of the session, so that nothing the server may cache during the check is near its end.
SEQ_PROBE_MAXRESPONSE = 64
SEQ_PROBE_MIN_CACHED = 1024

VULNERABLE = JSONStatus.VULNERABLE
OK = JSONStatus.OK
UNKNOWN = JSONStatus.UNKNOWN
ERROR = JSONStatus.ERROR


class ProbeEntry:
	"""What the access checks need to know about a file, 'handle' is whatever the access function takes"""
	def __init__(self, name, handle, uid, gid, mode, is_dir = False):
		self.name = name
		self.handle = handle
		self.uid = uid
		self.gid = gid
		self.mode = mode
		self.is_dir = is_dir


def empty_access_result():
	return {
		"root_squash": {"status": UNKNOWN, "reason": "", "object": None},
		"uid_spoofing": {"status": UNKNOWN, "reason": "", "object": None, "uid": None},
		"writable": {"status": UNKNOWN, "reason": "", "as": []},
	}


async def probe_access(root, entries, access):
	"""
	Finds out how the server treats the user ids we claim to be, without writing anything.

	The server is asked (ACCESS) what a given user could do with files that only their
	owner can read. If "root" may read a root-only file, root is not squashed. If the
	owner of a file may read it, the server takes our word for who we are.

	root: ProbeEntry of the directory, entries: ProbeEntry list of what is in it
	access: async function(handle, mask, credential) -> granted bits, or None on error
	"""
	res = empty_access_result()
	nobody = AUTH_SYS(uid = NOBODY, gid = NOBODY, gids = [NOBODY])
	candidates = [root] + [e for e in entries if e.name not in ('.', '..')]
	candidates = [e for e in candidates if isinstance(e.uid, int) and isinstance(e.mode, int)]

	async def owner_only_readable(entry):
		# the file must be closed for everyone else, otherwise it tells nothing
		granted = await access(entry.handle, ACCESS_READ, nobody)
		return granted is not None and (granted & ACCESS_READ) == 0

	# root squash
	entry = res["root_squash"]
	entry["reason"] = "no_root_only_object"
	for cand in candidates:
		if cand.uid != 0 or (cand.mode & 0o004) != 0 or (cand.mode & 0o400) == 0:
			continue
		if await owner_only_readable(cand) is False:
			continue
		granted = await access(cand.handle, ACCESS_READ, AUTH_SYS(uid = 0, gid = 0, gids = [0]))
		if granted is None:
			continue
		entry["object"] = cand.name
		if granted & ACCESS_READ:
			entry["status"] = VULNERABLE
			entry["reason"] = "root_not_squashed"
		else:
			entry["status"] = OK
			entry["reason"] = "root_squashed"
		break

	# uid spoofing
	entry = res["uid_spoofing"]
	entry["reason"] = "no_user_only_object"
	for cand in candidates:
		if cand.uid in (0, NOBODY) or (cand.mode & 0o004) != 0 or (cand.mode & 0o400) == 0:
			continue
		if await owner_only_readable(cand) is False:
			continue
		# a group that is surely not the group of the file: only the uid should matter
		gid = NOBODY - 1 if cand.gid != NOBODY - 1 else NOBODY - 2
		granted = await access(cand.handle, ACCESS_READ, AUTH_SYS(uid = cand.uid, gid = gid, gids = [gid]))
		if granted is None:
			continue
		entry["object"] = cand.name
		entry["uid"] = cand.uid
		if granted & ACCESS_READ:
			entry["status"] = VULNERABLE
			entry["reason"] = "uid_trusted"
		else:
			entry["status"] = OK
			entry["reason"] = "all_squashed"
		break

	# write access to the directory itself
	entry = res["writable"]
	identities = [("root", 0, 0)]
	if isinstance(root.uid, int) and root.uid not in (0, NOBODY):
		identities.append(("uid %s" % root.uid, root.uid, root.gid if isinstance(root.gid, int) else NOBODY))
	identities.append(("nobody", NOBODY, NOBODY))
	answered = False
	for label, uid, gid in identities:
		granted = await access(root.handle, ACCESS_MODIFY | ACCESS_EXTEND, AUTH_SYS(uid = uid, gid = gid, gids = [gid]))
		if granted is None:
			continue
		answered = True
		if granted & (ACCESS_MODIFY | ACCESS_EXTEND):
			entry["as"].append(label)
	if answered is False:
		entry["reason"] = "access_failed"
	elif len(entry["as"]) > 0:
		entry["status"] = VULNERABLE if "nobody" in entry["as"] else OK
		entry["reason"] = "writable"
	else:
		entry["status"] = OK
		entry["reason"] = "not_writable"
	return res


def access_labels(colors, res):
	"""The three columns of the report for a result of probe_access"""
	squash = res["root_squash"]
	if squash["status"] == VULNERABLE:
		squash_text = colors.error("DISABLED (root is root)")
	elif squash["status"] == OK:
		squash_text = colors.ok("enabled")
	else:
		squash_text = colors.warn("unknown")

	spoof = res["uid_spoofing"]
	if spoof["status"] == VULNERABLE:
		spoof_text = colors.error("possible (tested: uid %s)" % spoof["uid"])
	elif spoof["status"] == OK:
		spoof_text = colors.ok("no (all squashed)")
	else:
		spoof_text = colors.warn("unknown")

	writable = res["writable"]
	if writable["reason"] == "writable":
		writable_text = colors.warn(", ".join(writable["as"]))
		if "nobody" in writable["as"]:
			writable_text = colors.error(", ".join(writable["as"]))
	elif writable["reason"] == "not_writable":
		writable_text = colors.ok("no one")
	else:
		writable_text = colors.warn("unknown")
	return squash_text, spoof_text, writable_text


def access_differences(first, second):
	"""The checks of probe_access that came out differently in the two results"""
	diffs = []
	for check in ("root_squash", "uid_spoofing"):
		a = first[check]["status"]
		b = second[check]["status"]
		if UNKNOWN in (a, b):
			continue
		if a != b:
			diffs.append(check)
	a = first["writable"]
	b = second["writable"]
	if "access_failed" not in (a["reason"], b["reason"]) and sorted(a["as"]) != sorted(b["as"]):
		diffs.append("writable")
	return diffs


def export_key(fh, fsid):
	"""
	Something that is the same for all files of an export and changes when a lookup
	crosses into another one. The fsid is that by the protocol, but servers that export
	several directories of one filesystem tell them apart only inside their filehandles.
	"""
	key = None
	if fh is not None and len(fh) >= 4:
		if fh[0] == 1 and fh[1] == 0:
			# Linux knfsd: version, auth type, fsid type, fileid type, fsid
			fsid_len = {0: 8, 1: 4, 2: 12, 3: 8, 4: 8, 5: 8, 6: 16, 7: 24}.get(fh[2])
			if fsid_len is not None:
				key = bytes(fh[2:3]) + bytes(fh[4:4 + fsid_len])
		elif fh[0] == 0x43:
			# NFS-Ganesha: version, flags, export id
			key = bytes(fh[2:4])
	return (fsid, key)


def secinfo_to_flavors(secinfo):
	flavors = []
	for item in secinfo:
		flavor = item['flavor']
		if flavor == RPCSEC_GSS:
			if item.get('oid') == KRB5_OID and item.get('service') in GSS_SERVICE_FLAVORS:
				flavor = GSS_SERVICE_FLAVORS[item['service']]
			else:
				flavors.append("gss(%s)" % binascii.hexlify(item.get('oid', b'')).decode())
				continue
		flavors.append(flavor)
	return flavors


def empty_nfs4_report():
	return {
		"status": UNKNOWN,
		"reason": "",
		"minor_versions": [],
		"used_minor_version": None,
		"server": {"major_id": None, "scope": None, "impl_domain": None, "impl_name": None, "impl_date": None},
		"root_fh": "",
		"exports": {},
		"cve_2026_99362": {"status": UNKNOWN, "reason": ""},
	}


def empty_nfs4_export():
	return {
		"type": "export",
		"file_handle": "",
		"fsid": None,
		"auth_methods": None,
		"access": OK,
		"access_error": "",
		"checks": empty_access_result(),
	}


class NFS4Analyzer:
	"""
	The NFSv4 checks. 'parent' is the NFS3Analyzer driving the run, its report gets
	the results under the "nfs4" key and it does the printing.
	"""
	def __init__(self, parent, max_depth = 3, max_dirs = 200, max_entries = 1000):
		self.parent = parent
		self.factory = parent.factory
		self.colors = parent.colors
		self.max_depth = max_depth
		self.max_dirs = max_dirs
		self.max_entries = max_entries
		self.report = parent.report["nfs4"]
		self.nfs = None
		self.__probe_cache = {}

	def _out(self, text = ""):
		self.parent._out(text)

	def get_target(self):
		target = self.factory.get_target().get_nfs_target()
		if target.port == 0:
			target.port = 2049
		return target

	# ----------------------------------------------------------------- #
	# Minor versions
	# ----------------------------------------------------------------- #
	async def check_versions(self):
		"""
		Asks the server for its root with every minor version. One that has sessions
		refuses that (no session yet), but with a different error than an unknown version.
		"""
		versions = []
		for minor in (0, 1, 2):
			rpc = RPC(self.get_target(), self.factory.get_credential())
			try:
				_, err = await rpc.connect(NFS_PROGRAM, NFS_V4)
				if err is not None:
					raise err
				c = Compound(minor).putrootfh()
				res, err = await rpc.call(NFS_PROGRAM, NFS_V4, NFSPROC4_COMPOUND, c.to_bytes())
				if err is not None:
					raise err
				status, _ = c.results(res)
				if status != nfsstat4.NFS4ERR_MINOR_VERS_MISMATCH:
					versions.append(minor)
			except Exception as e:
				if len(versions) == 0 and minor == 0:
					# not even the first one got an answer: no NFSv4 here
					self.report["status"] = ERROR
					self.report["reason"] = str(e)
					self._out(self.colors.warn("NFSv4 is not available: %s" % e))
					return None
			finally:
				await rpc.disconnect()

		self.report["minor_versions"] = versions
		if len(versions) == 0:
			self.report["status"] = ERROR
			self.report["reason"] = "no_supported_minor_version"
			self._out(self.colors.warn("The server speaks NFSv4, but none of the minor versions 0, 1, 2"))
			return None
		self.report["status"] = OK
		self._out("Supported NFSv4 minor versions: %s" % ", ".join("4.%s" % v for v in versions))
		return versions

	def pick_version(self, versions):
		if self.factory.is_v4() and self.factory.version[1] in versions:
			return self.factory.version[1]
		# one with sessions if possible: the server introduces itself in those
		for minor in (1, 2, 0):
			if minor in versions:
				return minor

	# ----------------------------------------------------------------- #
	# Connection, server identity
	# ----------------------------------------------------------------- #
	async def connect(self, versions):
		minor = self.pick_version(versions)
		nfs = self.factory.get_client4()
		nfs.minorversion = minor
		_, err = await nfs.connect()
		if err is not None:
			self.report["status"] = ERROR
			self.report["reason"] = str(err)
			self._out(self.colors.error("Could not set up an NFSv4.%s connection: %s" % (minor, err)))
			return err
		self.nfs = nfs
		self.report["used_minor_version"] = minor
		self.report["root_fh"] = binascii.hexlify(nfs.root_handle).decode()
		return None

	async def disconnect(self):
		if self.nfs is not None:
			await self.nfs.disconnect()
			self.nfs = None

	def check_server(self):
		info = self.nfs.server_info
		if info is None:
			# NFSv4.0, there is no EXCHANGE_ID
			return
		server = self.report["server"]
		server["major_id"] = info['server_major_id'].rstrip(b'\x00').decode('utf-8', errors = 'replace')
		server["scope"] = info['server_scope'].rstrip(b'\x00').decode('utf-8', errors = 'replace')
		self._out("Server owner: %s (scope: %s)" % (server["major_id"], server["scope"]))
		impl = info.get('server_impl')
		if impl is None:
			return
		server["impl_domain"] = impl['domain']
		server["impl_name"] = impl['name']
		server["impl_date"] = str(impl['date']) if impl['date'] is not None else None
		text = "Server implementation: %s, %s" % (impl['domain'], impl['name'])
		if impl['domain'] == 'kernel.org':
			text += " " + self.colors.warn("(kernel version of the server)")
		self._out(text)

	# ----------------------------------------------------------------- #
	# CVE-2026-99362
	# ----------------------------------------------------------------- #
	def _is_linux(self):
		server = self.report["server"]
		if server["impl_domain"] is not None:
			return IMPL_DOMAINS.get(server["impl_domain"].lower()) == 'Linux'
		# kernels that do not introduce themselves: by the file handle
		return self.report["root_fh"].startswith("0100")

	async def check_sequence_preflight(self):
		"""
		CVE-2026-99362: the Linux server accepted the seqid of a slot before it knew that the
		SEQUENCE result fits in the reply, and with the right sizes the reply was then copied
		past the end of the reply cache of the slot. The fixed server refuses the SEQUENCE
		first and leaves the slot alone.

		That order is what is tested: a session of its own whose replies are too small for
		any SEQUENCE, then two of them with the seqids 1 and 2. Both fail. If the second is
		refused for its size and not for its seqid, the first one has moved the slot. Nothing
		is asked to be cached, and the reply cache is left at its normal size.
		"""
		res = self.report["cve_2026_99362"]
		if not any(v > 0 for v in self.report["minor_versions"]):
			res["reason"] = "no_sessions"
			return
		minor = self.report["used_minor_version"] or 1
		# the sizes of the replies are known with AUTH_SYS only
		rpc = RPC(self.get_target(), AUTH_SYS(uid = NOBODY, gid = NOBODY, gids = [NOBODY]))
		clientid = None
		sessionid = None

		async def call(compound):
			data, err = await rpc.call(NFS_PROGRAM, NFS_V4, NFSPROC4_COMPOUND, compound.to_bytes())
			if err is not None:
				raise err
			return compound.results(data)

		try:
			_, err = await rpc.connect(NFS_PROGRAM, NFS_V4)
			if err is not None:
				raise err
			status, results = await call(Compound(minor).exchange_id(os.urandom(NFS4_VERIFIER_SIZE), b'anfs-' + os.urandom(8).hex().encode()))
			if status != 0:
				res["reason"] = "exchange_id_%s" % self._statname(status)
				return
			clientid = results[0][2]['clientid']
			status, results = await call(Compound(minor).create_session(
				clientid, results[0][2]['sequenceid'], maxresponsesize = SEQ_PROBE_MAXRESPONSE, maxrequests = 1))
			if status != 0:
				# NFS-Ganesha for one does not take a session this small
				res["reason"] = "create_session_%s" % self._statname(status)
				return
			sessionid = results[0][2]['sessionid']
			attrs = results[0][2]['fore_chan_attrs']
			if attrs['maxresponsesize'] != SEQ_PROBE_MAXRESPONSE or attrs['maxresponsesize_cached'] < SEQ_PROBE_MIN_CACHED:
				res["reason"] = "sizes_not_accepted"
				return

			statuses = []
			for seqid in (1, 2):
				status, _ = await call(Compound(minor).sequence(sessionid, seqid, 0, 0))
				statuses.append(status)
			if statuses[0] != nfsstat4.NFS4ERR_REP_TOO_BIG:
				res["reason"] = "sequence_%s" % self._statname(statuses[0])
			elif statuses[1] == nfsstat4.NFS4ERR_SEQ_MISORDERED:
				res["status"] = OK
				res["reason"] = "slot_kept_on_error"
			elif statuses[1] != nfsstat4.NFS4ERR_REP_TOO_BIG:
				res["reason"] = "sequence_%s" % self._statname(statuses[1])
			elif self._is_linux() is False:
				res["reason"] = "slot_consumed_not_linux"
			else:
				res["status"] = VULNERABLE
				res["reason"] = "slot_consumed_on_error"
		except Exception as e:
			res["status"] = ERROR
			res["reason"] = str(e)
		finally:
			try:
				if sessionid is not None:
					await call(Compound(minor).destroy_session(sessionid))
				if clientid is not None:
					await call(Compound(minor).destroy_clientid(clientid))
			except Exception:
				pass
			await rpc.disconnect()
			self._print_sequence_preflight()

	def _print_sequence_preflight(self):
		res = self.report["cve_2026_99362"]
		if res["status"] == VULNERABLE:
			self._out(self.colors.error(
				"CVE-2026-99362: the server accepts a slot before it checks that the SEQUENCE reply fits. "
				"Its session reply cache can be overflowed without authentication (fixed in Linux 6.12.117, 6.18.61, 7.3.2)"))
		elif res["status"] == OK:
			self._out(self.colors.ok("CVE-2026-99362: not affected, a SEQUENCE that does not fit leaves the slot alone"))
		elif res["status"] == ERROR:
			self._out(self.colors.warn("CVE-2026-99362: check failed: %s" % res["reason"]))
		elif self._is_linux():
			self._out(self.colors.warn("CVE-2026-99362: could not be tested (%s)" % res["reason"]))
		else:
			self._out("CVE-2026-99362: not tested, not a Linux server (%s)" % res["reason"])

	@staticmethod
	def _statname(status):
		try:
			return nfsstat4(status).name
		except ValueError:
			return str(status)

	# ----------------------------------------------------------------- #
	# Namespace
	# ----------------------------------------------------------------- #
	def _auth_labels(self, flavors):
		labels = []
		for flavor in flavors:
			if isinstance(flavor, int):
				labels.append(self.parent._auth_label(flavor))
			else:
				labels.append(flavor)
		return ", ".join(labels)

	async def _access(self, handle, mask, cred):
		granted, err = await self.nfs.access(handle, mask, auth = cred)
		if err is not None:
			return None
		return granted

	@staticmethod
	def _probe_entry(entry, name = None):
		uid = owner_to_id(entry.owner)
		gid = owner_to_id(entry.group)
		if isinstance(uid, str) and uid.split('@')[0] == 'root':
			uid = 0
		if isinstance(gid, str) and gid.split('@')[0] == 'root':
			gid = 0
		return ProbeEntry(name if name is not None else entry.name, entry.handle, uid, gid, entry.mode, entry.type == NF4DIR)

	async def _list(self, handle):
		entries = []
		async for entry, err in self.nfs.readdir(handle):
			if err is not None:
				return entries, err
			entries.append(entry)
			if len(entries) >= self.max_entries:
				break
		return entries, None

	async def probe(self, dir_entry, entries = None):
		"""The access checks for a directory, 'entries' is its listing if that is at hand"""
		raw = self.nfs.get_raw_handle(dir_entry.handle)
		if raw in self.__probe_cache:
			return self.__probe_cache[raw]
		if entries is None:
			entries, _ = await self._list(dir_entry.handle)
		res = await probe_access(
			self._probe_entry(dir_entry, '.'),
			[self._probe_entry(e) for e in entries if e.handle is not None],
			self._access)
		self.__probe_cache[raw] = res
		return res

	async def walk(self):
		"""
		Finds the exports. In NFSv4 they are all somewhere below the root of the server, the
		directories on the way to them are either real ones or made up by the server (pseudo
		filesystem). An export starts where the filesystem (or the export id in the handle) changes.
		"""
		root, err = await self.nfs.getattr(0)
		if err is not None:
			self.report["status"] = ERROR
			self.report["reason"] = str(err)
			self._out(self.colors.error("Could not get the attributes of the NFSv4 root: %s" % err))
			return
		root.name = '/'
		root_key = export_key(self.nfs.root_handle, root.fsid)

		exports = self.report["exports"]
		listed = 0
		truncated = False
		# (path, entry, depth), breadth first
		queue = [('/', root, 0)]
		while len(queue) > 0:
			path, directory, depth = queue.pop(0)
			if listed >= self.max_dirs:
				truncated = True
				break
			listed += 1
			entries, err = await self._list(directory.handle)
			if path == '/':
				item = empty_nfs4_export()
				item["type"] = "root"
				item["file_handle"] = self.report["root_fh"]
				item["fsid"] = root.fsid
				if err is not None:
					item["access"] = ERROR
					item["access_error"] = self._errname(err)
				else:
					item["checks"] = await self.probe(root, entries)
				exports['/'] = item

			for entry in entries:
				child_path = path.rstrip('/') + '/' + entry.name
				if entry.handle is None:
					# the server did not even give a handle for it, eg. our security flavor is not accepted there
					_, lerr = await self.nfs.lookup(directory.handle, entry.name)
					item = empty_nfs4_export()
					item["access"] = ERROR
					item["access_error"] = self._errname(lerr)
					item["auth_methods"] = await self._secinfo(directory.handle, entry.name)
					exports[child_path] = item
					continue
				if entry.type != NF4DIR:
					continue
				raw = self.nfs.get_raw_handle(entry.handle)
				if export_key(raw, entry.fsid) == root_key:
					# still in the filesystem of the root
					if depth + 1 < self.max_depth:
						queue.append((child_path, entry, depth + 1))
					continue

				item = empty_nfs4_export()
				item["file_handle"] = binascii.hexlify(raw).decode()
				item["fsid"] = entry.fsid
				item["auth_methods"] = await self._secinfo(directory.handle, entry.name)
				children, lerr = await self._list(entry.handle)
				if lerr is not None:
					item["access"] = ERROR
					item["access_error"] = self._errname(lerr)
				else:
					item["checks"] = await self.probe(entry, children)
				exports[child_path] = item

		self._print_exports(truncated)

	@staticmethod
	def _errname(err):
		if isinstance(err, NFS4Error):
			return err.status.name if isinstance(err.status, nfsstat4) else str(err.status)
		return str(err)

	async def _secinfo(self, dir_handle, name):
		secinfo, err = await self.nfs.secinfo(dir_handle, name)
		if err is not None:
			return None
		return [self._flavor_name(f) for f in secinfo_to_flavors(secinfo)]

	@staticmethod
	def _flavor_name(flavor):
		if isinstance(flavor, int):
			return auth_flavor_to_str(flavor)
		return flavor

	@staticmethod
	def _short_handle(handle):
		# NFS-Ganesha pads the handle of its root to 128 bytes, the full one is in the report
		if handle is not None and len(handle) > 80:
			return handle[:80] + '...'
		return handle

	def _print_exports(self, truncated):
		names_to_flavor = {v: k for k, v in AUTH_FLAVOR_NAMES.items()}
		privport = self.factory.get_target().use_privileged_source_port is True
		data = [("Path", "Auth methods", "Access", "Root squash", "UID spoofing", "Writable as", "File handle")]
		reachable = 0
		for path, item in self.report["exports"].items():
			auth_text = ""
			if item["auth_methods"] is not None:
				auth_text = self._auth_labels([names_to_flavor.get(a, a) for a in item["auth_methods"]])
			label = path if item["type"] != "root" else "/ (root)"
			if item["access"] != OK:
				hint = ""
				if item["access_error"] == "NFS4ERR_PERM" and not privport:
					hint = " (source port below 1024 needed?)"
				elif item["access_error"] == "NFS4ERR_WRONGSEC":
					hint = " (AUTH_SYS not accepted)"
				data.append((label, auth_text, self.colors.ok(item["access_error"]) + hint, "", "", "", self._short_handle(item["file_handle"])))
				continue
			if item["type"] != "root":
				reachable += 1
			data.append((label, auth_text, "yes") + access_labels(self.colors, item["checks"]) + (self._short_handle(item["file_handle"]),))

		self._out("")
		self._out("NFSv4 namespace, walked with NFSv4.%s (nothing is written):" % self.report["used_minor_version"])
		self._out(format_table(data))
		if truncated:
			self._out(self.colors.warn("The walk was stopped after %s directories, there may be more exports" % self.max_dirs))
		if reachable > 0 and not privport:
			self._out(self.colors.warn(
				"%s export(s) reached from a source port above 1023: any local user of an allowed client can talk to the server directly" % reachable))

	# ----------------------------------------------------------------- #
	# NFSv3 against NFSv4
	# ----------------------------------------------------------------- #
	async def find_v3_export(self, directory, fileid):
		"""
		The directory an NFSv3 export is over NFSv4. The NFSv4 root is usually not the root
		of the server's filesystem, so the tail of the NFSv3 path is tried: /srv/exports/rw,
		/exports/rw, /rw. The file id tells that the right one was found.
		"""
		parts = [p for p in directory.split('/') if p != '']
		for start in range(len(parts) + 1):
			path = '/' + '/'.join(parts[start:])
			entry, err = await self.nfs.lookup_path(path)
			if err is not None:
				continue
			if entry.type == NF4DIR and (fileid is None or entry.fileid == fileid):
				return path, entry
		return None, None

	async def compare_with_v3(self, v3_exports):
		"""
		v3_exports: export directory -> (file id of its root, result of the access checks over NFSv3)

		The Linux server changes from one export to another only at mount points when it
		walks a path for NFSv4. Exports that are plain directories of one filesystem get the
		options of the export above them, so the same files have other rules in each version.
		"""
		differences = self.parent.report["version_differences"]
		data = [("NFSv3 export", "NFSv4 path", "Check", "NFSv3", "NFSv4")]
		for directory, (fileid, v3_checks) in v3_exports.items():
			path, entry = await self.find_v3_export(directory, fileid)
			if path is None:
				continue
			v4_checks = await self.probe(entry)
			for check in access_differences(v3_checks, v4_checks):
				if check == "writable":
					v3_value = ", ".join(v3_checks[check]["as"]) or "no one"
					v4_value = ", ".join(v4_checks[check]["as"]) or "no one"
				else:
					v3_value = v3_checks[check]["reason"]
					v4_value = v4_checks[check]["reason"]
				differences.append({
					"export": directory, "nfs4_path": path, "check": check,
					"nfs3": v3_value, "nfs4": v4_value,
				})
				data.append((directory, path, check, v3_value, v4_value))

		self._out("")
		if len(data) == 1:
			self._out(self.colors.ok("NFSv3 and NFSv4 give the same access to the exports"))
			return
		self._out(self.colors.error("The same export is treated differently over NFSv3 and NFSv4:"))
		self._out(format_table(data))
