#!/usr/bin/env python3
#
# UniScanner-compatible scanners built on top of the NFS3 security analyzer.
#
# These mirror the interface of anfs.utils.enumerator.NFS3FileScanner: each
# scanner exposes `async def run(self, targetid, target, out_queue)` and pushes
# ScannerData / ScannerError objects onto the out_queue. The result objects
# expose get_header() / to_line() / to_dict() like NFSFileRes so they plug into
# UniScanner.scan_and_process() output handling.
#
# Scanners:
#   - NFS3ExportScanner : exported directories, allowed clients, auth flavors, file handles
#   - NFS3ClientScanner : clients (IP/host) currently mounting exports (mountd DUMP)
#   - NFS3OSScanner     : per-host fingerprint (OS guess, windows fh signing, portmap services)
#   - NFS3VulnScanner   : export escape + /etc/shadow read (+ optional no_root_squash write test)
import asyncio

from asysocks.unicomm.common.scanner.targetgen import UniTargetGen
from asysocks.unicomm.common.scanner.scanner import UniScanner
from asysocks.unicomm.common.scanner.common import *

from anfs.protocol.nfs3.common.factory import NFS3ConnectionFactory
from anfs.utils.analyzer import NFS3Analyzer, Coloring, JSONStatus


def _join(values, sep=","):
	if not values:
		return ""
	return sep.join(str(v) for v in values)


def _format_clients(allowed_clients):
	if not allowed_clients:
		return "(everyone)"
	parts = []
	for c in allowed_clients:
		name = c.get("name", "")
		ctype = c.get("type", "")
		parts.append("%s(%s)" % (name, ctype))
	return ", ".join(parts)


# --------------------------------------------------------------------------- #
# Result objects
# --------------------------------------------------------------------------- #
class NFS3ExportRes:
	def __init__(self, target, directory, allowed_clients, auth_methods, file_handle, mount_result, err=None):
		self.target = target
		self.directory = directory
		self.allowed_clients = allowed_clients or []
		self.auth_methods = auth_methods or []
		self.file_handle = file_handle or ""
		self.mount_result = mount_result
		self.err = err

	def get_header(self):
		return ['otype', 'target', 'export', 'allowed_clients', 'auth_methods', 'mount_result', 'file_handle']

	def to_line(self, separator='\t'):
		if self.err is not None:
			return separator.join(['err', str(self.target), str(self.err)])
		return separator.join([
			'export',
			str(self.target),
			str(self.directory),
			_format_clients(self.allowed_clients),
			_join(self.auth_methods),
			str(self.mount_result),
			self.file_handle,
		])

	def to_dict(self):
		if self.err is not None:
			return {'otype': 'err', 'target': str(self.target), 'err': str(self.err)}
		return {
			'otype': 'export',
			'target': str(self.target),
			'export': self.directory,
			'allowed_clients': self.allowed_clients,
			'auth_methods': self.auth_methods,
			'mount_result': self.mount_result,
			'file_handle': self.file_handle,
		}


class NFS3ClientRes:
	def __init__(self, target, client, directory, client_type, status, err=None):
		self.target = target
		self.client = client
		self.directory = directory
		self.client_type = client_type
		self.status = status
		self.err = err

	def get_header(self):
		return ['otype', 'target', 'client', 'export', 'client_type', 'status']

	def to_line(self, separator='\t'):
		if self.err is not None:
			return separator.join(['err', str(self.target), str(self.err)])
		return separator.join([
			'client',
			str(self.target),
			str(self.client),
			str(self.directory),
			str(self.client_type),
			str(self.status),
		])

	def to_dict(self):
		if self.err is not None:
			return {'otype': 'err', 'target': str(self.target), 'err': str(self.err)}
		return {
			'otype': 'client',
			'target': str(self.target),
			'client': self.client,
			'export': self.directory,
			'client_type': self.client_type,
			'status': self.status,
		}


class NFS3OSRes:
	def __init__(self, target, os_guess, windows_signing, windows_signing_reason, services, err=None):
		self.target = target
		self.os_guess = os_guess
		self.windows_signing = windows_signing
		self.windows_signing_reason = windows_signing_reason
		self.services = services or []
		self.err = err

	def get_header(self):
		return ['otype', 'target', 'os_guess', 'windows_signing', 'windows_signing_reason', 'services']

	def to_line(self, separator='\t'):
		if self.err is not None:
			return separator.join(['err', str(self.target), str(self.err)])
		return separator.join([
			'os',
			str(self.target),
			str(self.os_guess),
			str(self.windows_signing),
			str(self.windows_signing_reason),
			_join(self.services),
		])

	def to_dict(self):
		if self.err is not None:
			return {'otype': 'err', 'target': str(self.target), 'err': str(self.err)}
		return {
			'otype': 'os',
			'target': str(self.target),
			'os_guess': self.os_guess,
			'windows_signing': self.windows_signing,
			'windows_signing_reason': self.windows_signing_reason,
			'services': self.services,
		}


class NFS3VulnRes:
	def __init__(self, target, directory, escape, root_fh, etc_shadow, etc_shadow_reason,
				symlink_escape, no_root_squash, shadow_content=None, err=None):
		self.target = target
		self.directory = directory
		self.escape = escape
		self.root_fh = root_fh
		self.etc_shadow = etc_shadow
		self.etc_shadow_reason = etc_shadow_reason
		self.symlink_escape = symlink_escape
		self.no_root_squash = no_root_squash
		self.shadow_content = shadow_content
		self.err = err

	def get_header(self):
		return ['otype', 'target', 'export', 'escape', 'etc_shadow', 'symlink_escape', 'no_root_squash', 'root_fh']

	def to_line(self, separator='\t'):
		if self.err is not None:
			return separator.join(['err', str(self.target), str(self.err)])
		return separator.join([
			'vuln',
			str(self.target),
			str(self.directory),
			str(self.escape),
			str(self.etc_shadow),
			str(self.symlink_escape),
			str(self.no_root_squash),
			str(self.root_fh or ''),
		])

	def to_dict(self):
		if self.err is not None:
			return {'otype': 'err', 'target': str(self.target), 'err': str(self.err)}
		return {
			'otype': 'vuln',
			'target': str(self.target),
			'export': self.directory,
			'escape': self.escape,
			'etc_shadow': self.etc_shadow,
			'etc_shadow_reason': self.etc_shadow_reason,
			'symlink_escape': self.symlink_escape,
			'no_root_squash': self.no_root_squash,
			'root_fh': self.root_fh,
			'shadow_content': self.shadow_content,
		}


class NFS3FileReadRes:
	"""Result of an arbitrary file read via an NFS export escape."""
	def __init__(self, target, directory, escape, root_fh, filepath, read_status,
				read_reason, size=0, content=None, err=None):
		self.target = target
		self.directory = directory
		self.escape = escape
		self.root_fh = root_fh
		self.filepath = filepath
		self.read_status = read_status
		self.read_reason = read_reason
		self.size = size
		self.content = content
		self.err = err

	def get_header(self):
		return ['otype', 'target', 'export', 'escape', 'filepath', 'read_status', 'read_reason', 'size', 'root_fh']

	def to_line(self, separator='\t'):
		if self.err is not None:
			return separator.join(['err', str(self.target), str(self.err)])
		return separator.join([
			'fileread',
			str(self.target),
			str(self.directory),
			str(self.escape),
			str(self.filepath),
			str(self.read_status),
			str(self.read_reason),
			str(self.size),
			str(self.root_fh or ''),
		])

	def to_dict(self):
		if self.err is not None:
			return {'otype': 'err', 'target': str(self.target), 'err': str(self.err)}
		return {
			'otype': 'fileread',
			'target': str(self.target),
			'export': self.directory,
			'escape': self.escape,
			'filepath': self.filepath,
			'read_status': self.read_status,
			'read_reason': self.read_reason,
			'size': self.size,
			'root_fh': self.root_fh,
			'content': self.content,
		}


# --------------------------------------------------------------------------- #
# Scanners
# --------------------------------------------------------------------------- #
class NFS3ExportScanner:
	"""Enumerate exported directories, allowed clients, auth flavors, file handles."""
	def __init__(self, factory: NFS3ConnectionFactory, do_ping=False):
		self.factory = factory
		self.do_ping = do_ping

	async def run(self, targetid, target, out_queue):
		try:
			newfactory = self.factory.create_factory_newtarget(target)
			analyzer = NFS3Analyzer(newfactory, do_ping=self.do_ping, colors=Coloring(False), quiet=True)
			err = await analyzer.collect_exports()
			if err is not None:
				await out_queue.put(ScannerError(target, err))
				return
			for directory, entry in analyzer.report["exports"]["directories"].items():
				res = NFS3ExportRes(
					target, directory,
					entry["allowed_clients"], entry["auth_methods"],
					entry["file_handle"], entry["mount_result"])
				await out_queue.put(ScannerData(target, res))
		except Exception as e:
			await out_queue.put(ScannerError(target, e))


class NFS3ClientScanner:
	"""List clients (IP/hostname) that currently have exports mounted (mountd DUMP)."""
	def __init__(self, factory: NFS3ConnectionFactory, do_ping=False):
		self.factory = factory
		self.do_ping = do_ping

	async def run(self, targetid, target, out_queue):
		try:
			newfactory = self.factory.create_factory_newtarget(target)
			analyzer = NFS3Analyzer(newfactory, do_ping=self.do_ping, colors=Coloring(False), quiet=True)
			async with newfactory.get_mount() as mount:
				clients, err = await mount.dump()
				if err is not None:
					raise err
				for entry in clients or []:
					info, _label = await analyzer.classify_host(entry.hostname)
					res = NFS3ClientRes(target, entry.hostname, entry.directory,
										info["type"], info["status"])
					await out_queue.put(ScannerData(target, res))
		except Exception as e:
			await out_queue.put(ScannerError(target, e))


class NFS3OSScanner:
	"""Per-host fingerprint: OS guess, Windows file handle signing, portmap services."""
	def __init__(self, factory: NFS3ConnectionFactory):
		self.factory = factory

	async def run(self, targetid, target, out_queue):
		try:
			newfactory = self.factory.create_factory_newtarget(target)
			analyzer = NFS3Analyzer(newfactory, colors=Coloring(False), quiet=True)
			await analyzer.check_portmap()
			await analyzer.collect_exports()
			if analyzer.mount_results:
				analyzer.check_windows_signing()
			analyzer.guess_os()
			services = list(analyzer.report["portmap"]["services"].keys())
			res = NFS3OSRes(
				target,
				analyzer.report["os"]["final_guess"],
				analyzer.report["windows_handle_signing"]["status"],
				analyzer.report["windows_handle_signing"]["reason"],
				services)
			await out_queue.put(ScannerData(target, res))
		except Exception as e:
			await out_queue.put(ScannerError(target, e))


class NFS3VulnScanner:
	"""Active vulnerability checks: export escape + /etc/shadow read (+ optional no_root_squash).

	WARNING: with check_no_root_squash=True this WRITES a test directory to each
	writable export (and removes it again), like the original nfs_analyze tool.
	"""
	def __init__(self, factory: NFS3ConnectionFactory, check_no_root_squash=False, btrfs_subvolumes=16):
		self.factory = factory
		self.check_no_root_squash = check_no_root_squash
		self.btrfs_subvolumes = btrfs_subvolumes

	async def run(self, targetid, target, out_queue):
		try:
			newfactory = self.factory.create_factory_newtarget(target)
			analyzer = NFS3Analyzer(
				newfactory,
				check_no_root_squash=self.check_no_root_squash,
				btrfs_subvolumes=self.btrfs_subvolumes,
				colors=Coloring(False), quiet=True)
			err = await analyzer.collect_exports()
			if err is not None:
				await out_queue.put(ScannerError(target, err))
				return
			if not analyzer.mount_results:
				return

			nfs, err = await analyzer.open_nfs_client()
			if err is not None:
				await out_queue.put(ScannerError(target, err))
				return
			try:
				await analyzer.try_escape(nfs)
				if self.check_no_root_squash:
					await analyzer.check_no_root_squash(nfs)
			finally:
				await nfs.disconnect()

			for directory, entry in analyzer.report["exports"]["directories"].items():
				esc = entry["escape"]
				res = NFS3VulnRes(
					target, directory,
					escape=esc["status"],
					root_fh=esc.get("root_fh"),
					etc_shadow=esc["etc_shadow"]["status"],
					etc_shadow_reason=esc["etc_shadow"]["reason"],
					symlink_escape=esc["symlink_escape"]["status"],
					no_root_squash=entry["no_root_squash"]["status"],
					shadow_content=esc["etc_shadow"].get("content"))
				await out_queue.put(ScannerData(target, res))
		except Exception as e:
			await out_queue.put(ScannerError(target, e))


class NFS3FileReadScanner:
	"""Arbitrary file read via NFS export escape (attack).

	For every export it escapes to the filesystem root (like NFS3VulnScanner)
	and then reads the operator-supplied `filepath` (interpreted from that root),
	leveraging no_root_squash (read as root) or world-readable permissions.
	"""
	def __init__(self, factory: NFS3ConnectionFactory, filepath, btrfs_subvolumes=16, max_size=None):
		self.factory = factory
		self.filepath = filepath
		self.btrfs_subvolumes = btrfs_subvolumes
		self.max_size = max_size

	async def run(self, targetid, target, out_queue):
		try:
			newfactory = self.factory.create_factory_newtarget(target)
			analyzer = NFS3Analyzer(
				newfactory,
				btrfs_subvolumes=self.btrfs_subvolumes,
				read_file_path=self.filepath,
				read_file_max_size=self.max_size,
				colors=Coloring(False), quiet=True)
			err = await analyzer.collect_exports()
			if err is not None:
				await out_queue.put(ScannerError(target, err))
				return
			if not analyzer.mount_results:
				return

			nfs, err = await analyzer.open_nfs_client()
			if err is not None:
				await out_queue.put(ScannerError(target, err))
				return
			try:
				await analyzer.try_escape(nfs)
			finally:
				await nfs.disconnect()

			for directory, entry in analyzer.report["exports"]["directories"].items():
				esc = entry["escape"]
				rf = esc["read_file"]
				res = NFS3FileReadRes(
					target, directory,
					escape=esc["status"],
					root_fh=esc.get("root_fh"),
					filepath=rf.get("path") or self.filepath,
					read_status=rf["status"],
					read_reason=rf["reason"],
					size=rf.get("size", 0),
					content=rf.get("content"))
				await out_queue.put(ScannerData(target, res))
		except Exception as e:
			await out_queue.put(ScannerError(target, e))


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
async def _run_scanner(name, executor, targets, worker_count, show_progress, out_file, include_errors):
	tgen = UniTargetGen.from_list(targets)
	scanner = UniScanner(name, [executor], [tgen], worker_count=worker_count, host_timeout=None)
	await scanner.scan_and_process(progress=show_progress, out_file=out_file, include_errors=include_errors)


async def export_scan(url, targets, worker_count=100, show_progress=True, out_file=None, include_errors=False, do_ping=False):
	factory = NFS3ConnectionFactory.from_url(url)
	await _run_scanner('NFS3ExportScanner', NFS3ExportScanner(factory, do_ping=do_ping),
						targets, worker_count, show_progress, out_file, include_errors)


async def client_scan(url, targets, worker_count=100, show_progress=True, out_file=None, include_errors=False, do_ping=False):
	factory = NFS3ConnectionFactory.from_url(url)
	await _run_scanner('NFS3ClientScanner', NFS3ClientScanner(factory, do_ping=do_ping),
						targets, worker_count, show_progress, out_file, include_errors)


async def os_scan(url, targets, worker_count=100, show_progress=True, out_file=None, include_errors=False):
	factory = NFS3ConnectionFactory.from_url(url)
	await _run_scanner('NFS3OSScanner', NFS3OSScanner(factory),
						targets, worker_count, show_progress, out_file, include_errors)


async def vuln_scan(url, targets, worker_count=100, show_progress=True, out_file=None, include_errors=False,
					check_no_root_squash=False, btrfs_subvolumes=16):
	factory = NFS3ConnectionFactory.from_url(url)
	await _run_scanner('NFS3VulnScanner',
						NFS3VulnScanner(factory, check_no_root_squash=check_no_root_squash, btrfs_subvolumes=btrfs_subvolumes),
						targets, worker_count, show_progress, out_file, include_errors)


def main():
	import argparse

	parser = argparse.ArgumentParser(description='NFSv3 security scanners (UniScanner based)')
	parser.add_argument('-w', '--worker-count', type=int, default=100, help='Parallel worker count')
	parser.add_argument('--no-progress', action='store_false', dest='progress', help='Disable progress bar')
	parser.add_argument('-o', '--out-file', help='Output file path')
	parser.add_argument('-e', '--errors', action='store_true', help='Include errors in output')

	sub = parser.add_subparsers(dest='scanner', required=True)

	def add_common(p):
		p.add_argument('url', help='Connection string in URL format, e.g. nfs://10.0.0.1')
		p.add_argument('targets', nargs='*', help='Hostname/IP or a file with a list of targets')

	p_exp = sub.add_parser('exports', help='Enumerate exports, allowed clients, auth flavors, file handles')
	add_common(p_exp)
	p_exp.add_argument('--ping', action='store_true', help='Ping allowed-client hosts to determine if up')

	p_cli = sub.add_parser('clients', help='List clients currently mounting exports (mountd DUMP)')
	add_common(p_cli)
	p_cli.add_argument('--ping', action='store_true', help='Ping reported clients to determine if up')

	p_os = sub.add_parser('os', help='Per-host fingerprint: OS guess, windows signing, services')
	add_common(p_os)

	p_vuln = sub.add_parser('vuln', help='Export escape + /etc/shadow read (+ optional no_root_squash)')
	add_common(p_vuln)
	p_vuln.add_argument('--check-no-root-squash', action='store_true',
						help='Also test no_root_squash. WARNING: THIS WRITES A TEST DIRECTORY ON THE SERVER')
	p_vuln.add_argument('--btrfs-subvolumes', type=int, default=16,
						help='Number of subvolumes to probe when escaping a BTRFS export')

	args = parser.parse_args()

	if args.scanner == 'exports':
		coro = export_scan(args.url, args.targets, worker_count=args.worker_count,
						show_progress=args.progress, out_file=args.out_file, include_errors=args.errors,
						do_ping=args.ping)
	elif args.scanner == 'clients':
		coro = client_scan(args.url, args.targets, worker_count=args.worker_count,
						show_progress=args.progress, out_file=args.out_file, include_errors=args.errors,
						do_ping=args.ping)
	elif args.scanner == 'os':
		coro = os_scan(args.url, args.targets, worker_count=args.worker_count,
						show_progress=args.progress, out_file=args.out_file, include_errors=args.errors)
	elif args.scanner == 'vuln':
		coro = vuln_scan(args.url, args.targets, worker_count=args.worker_count,
						show_progress=args.progress, out_file=args.out_file, include_errors=args.errors,
						check_no_root_squash=args.check_no_root_squash, btrfs_subvolumes=args.btrfs_subvolumes)
	else:
		parser.error('unknown scanner')

	asyncio.run(coro)


if __name__ == '__main__':
	main()
