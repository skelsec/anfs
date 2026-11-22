#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import os
import sys
import asyncio
import traceback
import logging
import shlex
from tqdm import tqdm

from anfs import logger
from asysocks import logger as sockslogger
from asyauth import logger as authlogger
from anfs.examples.utils import PathCompleter
from anfs.external.aiocmd.aiocmd import aiocmd
from anfs.protocol.nfs3.common.factory import NFS3ConnectionFactory
from anfs.protocol.nfs3.pack import file_mode_to_string
from anfs.protocol.rpc.common.target import RPCTarget
from anfs.protocol.rpc.messages import AUTH_SYS, AUTH_NULL

# the numbers are the same in NFSv3 and NFSv4
FILE_TYPES = {1 : 'file', 2 : 'directory', 3 : 'block device', 4 : 'character device', 5 : 'symlink', 6 : 'socket', 7 : 'fifo'}

class NFSClientConsole(aiocmd.PromptToolkitCmd):
	def __init__(self, url = None):
		aiocmd.PromptToolkitCmd.__init__(self, ignore_sigint=False)
		self.conn_url = url
		if url is not None and isinstance(url, NFS3ConnectionFactory) is False:
			self.conn_url = NFS3ConnectionFactory.from_url(url)
		self.connection = None
		self.mount = None
		self.__current_dir_handle = None
		self.__current_dirs = {}
		self.__current_files = {}
		self.__mounts = {}
		self.__current_mountpoint = None
		self.aliases['use'] = 'mount'
		

	async def do_connect(self, url = None):
		"""Performs connection and login"""
		try:			
			if self.conn_url is None and url is None:
				print('No URL was set, cant do logon')
			if url is not None and isinstance(url, NFS3ConnectionFactory) is False:
				self.conn_url = NFS3ConnectionFactory.from_url(url)

			logger.debug(self.conn_url.get_credential())
			logger.debug(self.conn_url.get_target())

			if self.conn_url.is_v4() is True:
				# no mount protocol in NFSv4, we start at the root of the server
				self.connection = self.conn_url.get_client4()
				_, err = await self.connection.connect()
				if err is not None:
					raise err
				print('Connected! -NFSv4.%s-' % self.connection.minorversion)
				self.__current_mountpoint = ''
				self.__current_dir_handle = 0
				self.prompt = '[/]> '
				await self.do_refreshcurrentdir()
				return True
			
			self.mount = self.conn_url.get_mount()
			_, err = await self.mount.connect()
			if err is not None:
				raise err
			
			logger.debug('Mount connect OK!')
			print('Connected! -mount-')
			
			return True
		except:
			traceback.print_exc()
			return False
		
	async def do_mounts(self):
		"""Lists all mountpoints"""

		if self.conn_url.is_v4() is True:
			print('NFSv4 has no mountpoints, all exports are below the root directory. Use ls and cd!')
			return True
		
		if self.mount is None and await self.do_connect() is False:
			return False

		if len(self.__mounts) == 0:
			mountres, err = await self.mount.export()
			if err is not None:
				raise err
			for mount in mountres:
				self.__mounts[mount.filesys] = mount
		
		for mount in self.__mounts:
			print(mount)
		
		return True

	async def do_mountinfo(self):
		"""Returns info about all mountpoints"""
		
		if len(self.__mounts) == 0:
			print('No mountpoints found! Did you run mounts?')
		
		for mount in self.__mounts:
			print(str(self.__mounts[mount]))
		
		return True
	
	def _mount_completions(self):
		return PathCompleter(get_current_dirs = lambda: list(self.__mounts.keys()))
	
	async def do_mount(self, mountpoint:str):
		"""Changes the current mountpoint"""

		if self.conn_url.is_v4() is True:
			print('NFSv4 has no mountpoints, all exports are below the root directory. Use ls and cd!')
			return True

		if mountpoint == self.__current_mountpoint:
			print('Already using this mountpoint!')
			return True
		
		if self.mount is None and await self.do_connect() is False:
			return False

		mhandle, err = await self.mount.mount(mountpoint)
		if err is not None:
			raise err
		
		self.connection = self.conn_url.get_client(mhandle)
		_, err = await self.connection.connect()
		if err is not None:
			raise err
		logger.debug('Connect OK!')
		print('Connected! -NFS-')
		self.prompt = '[%s]> ' % mountpoint
		self.__current_mountpoint = mountpoint
		self.__current_dir_handle = 0 #root is always 0
		await self.do_refreshcurrentdir()
		return True
		
	async def do_refreshcurrentdir(self):
		"""Refreshes the current directory"""
		if self.__current_dir_handle is None:
			print('Please use a mountpoint first!')
			return False
		
		self.__current_dirs = {}
		self.__current_files = {}
		if self.conn_url.is_v4() is True and self.__current_dir_handle != 0:
			# NFSv4 servers do not list the parent directory
			parent, err = await self.connection.lookup(self.__current_dir_handle, '..')
			if err is None:
				parent.name = '..'
				self.__current_dirs['..'] = parent
		async for fe, err in self.connection.readdirplus(self.__current_dir_handle):
			if err is not None:
				raise err
			if fe.type == 2:
				if fe.name == '.':
					continue
				self.__current_dirs[fe.name] = fe
			elif fe.type == 5:
				# symlink
				symlinkdata, err = await self.connection.readlink(fe.handle)
				if err is not None:
					raise err
				
				fe.symtarget = symlinkdata
				self.__current_files[fe.name] = fe
			else:
				self.__current_files[fe.name] = fe
		return True
	
	async def do_ls(self):
		"""Lists the current directory"""
		if self.__current_dir_handle is None:
			print('Please use a mountpoint first!')
			return False
		
		for d in self.__current_dirs:
			print(self.__current_dirs[d].to_line())
		for f in self.__current_files:
			print(self.__current_files[f].to_line())
		return True
	
	def get_current_dirs(self):
		if self.__current_dirs is None:
			return []
		curdirs = []
		for dirname in self.__current_dirs:
			if dirname.find(' ') != -1:
				dirname = "'%s'" % dirname
			curdirs.append(dirname)
		return curdirs
	
	def get_current_files(self):
		if self.__current_files is None:
			return []
		return list(self.__current_files.keys())
	
	def _cd_completions(self):
		return PathCompleter(get_current_dirs = self.get_current_dirs)
	
	async def do_cd(self, dirname:str):
		"""Changes the current directory"""
		if dirname not in self.__current_dirs:
			print('Directory not found!')
			return False
		
		self.__current_dir_handle = self.__current_dirs[dirname].handle
		self.prompt = '[%s%s]> ' % (self.__current_mountpoint, self.connection.handle_to_path(self.__current_dir_handle) or '/')
		await self.do_refreshcurrentdir()
		return True
	
	def _get_completions(self):
		return PathCompleter(get_current_dirs = self.get_current_files)
	
	async def do_get(self, filename:str):
		"""Downloads a file"""
		if filename not in self.__current_files:
			print('File not found!')
			return False
		
		await self.__getfile_internal(self.__current_files[filename], os.path.basename(filename))
		return True

	def __find(self, name):
		"""The entry of a file or directory in the current directory"""
		if name in self.__current_files:
			return self.__current_files[name]
		if name in self.__current_dirs and name != '..':
			return self.__current_dirs[name]
		return None

	def get_current_names(self):
		return self.get_current_files() + [d for d in self.get_current_dirs() if d != '..']

	def _all_completions(self):
		return PathCompleter(get_current_dirs = self.get_current_names)

	_cat_completions = _get_completions
	_mv_completions = _all_completions
	_stat_completions = _all_completions
	_getacl_completions = _all_completions
	_setacl_completions = _all_completions

	async def do_cat(self, filename:str):
		"""Prints the contents of a file"""
		if filename not in self.__current_files:
			print('File not found!')
			return False

		entry = self.__current_files[filename]
		offset = 0
		while True:
			data, err = await self.connection.read(entry.handle, offset, 1024*1024)
			if err is not None:
				raise err
			if len(data) == 0:
				break
			offset += len(data)
			sys.stdout.write(data.decode(errors = 'replace'))
		sys.stdout.flush()
		return True

	async def do_put(self, localpath:str, remotename:str = None):
		"""Uploads a file to the current directory"""
		if self.__current_dir_handle is None:
			print('Please use a mountpoint first!')
			return False
		if os.path.isfile(localpath) is False:
			print('Local file not found!')
			return False
		if remotename is None:
			remotename = os.path.basename(localpath)
		if remotename in self.__current_dirs:
			print('There is a directory with this name!')
			return False

		await self.__putfile_internal(self.__current_dir_handle, localpath, remotename)
		await self.do_refreshcurrentdir()
		return True

	async def __putfile_internal(self, dir_handle, localpath, remotename):
		pbar = tqdm(total=os.path.getsize(localpath), unit='B', unit_scale=True)
		try:
			# the file is created with the permission bits it has here
			mode = os.stat(localpath).st_mode & 0o777
			_, err = await self.connection.upload_file(dir_handle, remotename, localpath, mode = mode, progress_cb = pbar.update)
			if err is not None:
				raise err
		finally:
			pbar.close()

	async def __putdir_internal(self, dir_handle, localdir, remotename):
		entry, err = await self.connection.lookup(dir_handle, remotename)
		if err is not None:
			entry, err = await self.connection.mkdir(dir_handle, remotename, mode = 0o755)
			if err is not None:
				raise err
		for name in sorted(os.listdir(localdir)):
			localpath = os.path.join(localdir, name)
			if os.path.islink(localpath):
				print('Skipping %s, it is a symlink!' % localpath)
			elif os.path.isdir(localpath):
				await self.__putdir_internal(entry.handle, localpath, name)
			elif os.path.isfile(localpath):
				await self.__putfile_internal(entry.handle, localpath, name)
			else:
				print('Skipping %s for unknown type!' % localpath)

	async def do_putdir(self, localdir:str):
		"""Uploads a directory with everything in it to the current directory"""
		if self.__current_dir_handle is None:
			print('Please use a mountpoint first!')
			return False
		if os.path.isdir(localdir) is False:
			print('Local directory not found!')
			return False
		name = os.path.basename(os.path.normpath(localdir))
		if name in self.__current_files:
			print('There is a file with this name!')
			return False

		await self.__putdir_internal(self.__current_dir_handle, localdir, name)
		await self.do_refreshcurrentdir()
		return True

	async def do_mv(self, name:str, newname:str):
		"""Renames a file or directory. If the new name is a directory here, it is moved into that"""
		if self.__find(name) is None:
			print('File or directory not found!')
			return False

		to_handle = self.__current_dir_handle
		to_name = newname
		if newname in self.__current_dirs:
			to_handle = self.__current_dirs[newname].handle
			to_name = name
		_, err = await self.connection.rename(self.__current_dir_handle, name, to_handle, to_name)
		if err is not None:
			raise err
		await self.do_refreshcurrentdir()
		return True

	async def do_chmod(self, mode:str, name:str):
		"""Changes the permission bits of a file or directory, the mode is octal: chmod 644 file.txt"""
		entry = self.__find(name)
		if entry is None:
			print('File or directory not found!')
			return False
		try:
			mode = int(mode, 8)
		except ValueError:
			print('The mode must be an octal number like 644 or 4755!')
			return False

		_, err = await self.connection.setattr(entry.handle, mode = mode)
		if err is not None:
			raise err
		await self.do_refreshcurrentdir()
		return True

	async def do_chown(self, owner:str, name:str):
		"""Changes the owner and/or group of a file or directory: chown 1000 file, chown 1000:1000 file, chown :1000 file"""
		entry = self.__find(name)
		if entry is None:
			print('File or directory not found!')
			return False

		uid, _, gid = owner.partition(':')
		ids = []
		for value in (uid, gid):
			if value == '':
				value = None
			elif value.isdigit():
				value = int(value)
			elif self.conn_url.is_v4() is False:
				print('NFSv3 knows only numeric ids!')
				return False
			# NFSv4: anything else is sent as it is, servers with id mapping take user@domain
			ids.append(value)

		_, err = await self.connection.setattr(entry.handle, uid = ids[0], gid = ids[1])
		if err is not None:
			raise err
		await self.do_refreshcurrentdir()
		return True

	async def do_stat(self, name:str):
		"""Shows the attributes of a file or directory"""
		entry = self.__find(name)
		if entry is None:
			print('File or directory not found!')
			return False

		attrs, err = await self.connection.getattr(entry.handle)
		if err is not None:
			raise err
		print('Name:    %s' % name)
		print('Type:    %s' % FILE_TYPES.get(attrs.type, attrs.type))
		print('Size:    %s' % attrs.size)
		print('Mode:    %s (%s)' % ('%04o' % (attrs.mode & 0o7777), file_mode_to_string(attrs.type, attrs.mode)))
		print('Owner:   %s' % attrs.uid)
		print('Group:   %s' % attrs.gid)
		print('Links:   %s' % attrs.nlink)
		print('File id: %s' % attrs.fileid)
		print('Access:  %s' % attrs.atime)
		print('Modify:  %s' % attrs.mtime)
		print('Change:  %s' % attrs.ctime)
		if self.conn_url.is_v4() is True:
			acl, err = await self.connection.get_acl(entry.handle)
			if err is None and acl is not None:
				print('ACL:     %s' % ' '.join(str(ace) for ace in acl))
		return True

	async def do_getacl(self, name:str):
		"""Shows the NFSv4 ACL of a file or directory, one entry per line as type:flags:who:permissions"""
		if self.conn_url.is_v4() is False:
			print('ACLs are available only with NFSv4!')
			return False
		entry = self.__find(name)
		if entry is None:
			print('File or directory not found!')
			return False

		acl, err = await self.connection.get_acl(entry.handle)
		if err is not None:
			raise err
		if acl is None:
			print('The server has no ACL for this file!')
			return False
		for ace in acl:
			print(str(ace))
		return True

	async def do_setacl(self, name:str, acl:str):
		"""Replaces the NFSv4 ACL of a file or directory. Entries are separated by commas: setacl file A::OWNER@:rwatTcCy,A::1000:rwa,A::EVERYONE@:rtcy"""
		if self.conn_url.is_v4() is False:
			print('ACLs are available only with NFSv4!')
			return False
		entry = self.__find(name)
		if entry is None:
			print('File or directory not found!')
			return False

		_, err = await self.connection.set_acl(entry.handle, [ace for ace in acl.split(',') if ace != ''])
		if err is not None:
			raise err
		return await self.do_getacl(name)

	async def do_whoami(self):
		"""Shows who we are for the server"""
		cred = self.conn_url.credential
		if isinstance(cred, AUTH_SYS):
			params = cred.get_params()
			print('AUTH_SYS uid=%s gid=%s gids=%s machinename=%s' % (params.uid, params.gid, ','.join(str(g) for g in params.gids), params.machinename))
		elif isinstance(cred, AUTH_NULL):
			print('AUTH_NONE, no credentials are sent')
		else:
			user = getattr(cred, 'credential', None)
			print('Kerberos user %s\\%s, server %s' % (getattr(user, 'domain', '?'), getattr(user, 'username', '?'), cred.get_spn(self.conn_url.target)))
		return True

	async def do_su(self, uid:str, gid:str = None, gids:str = None):
		"""Become another user (AUTH_SYS): su <uid> [gid] [comma separated list of other group ids]. The gid defaults to the uid"""
		cred = self.conn_url.credential
		if isinstance(cred, (AUTH_SYS, AUTH_NULL)) is False:
			print('With kerberos the server knows who we are, there is no way to pick the user!')
			return False
		try:
			uid = int(uid)
			gid = int(gid) if gid is not None else uid
			gids = [int(x) for x in gids.split(',') if x != ''] if gids is not None else None
		except ValueError:
			print('Ids are numbers!')
			return False

		machinename = cred.get_params().machinename if isinstance(cred, AUTH_SYS) else None
		cred = AUTH_SYS(machinename = machinename, uid = uid, gid = gid, gids = gids)
		# connections made later (eg. another mountpoint) use it as well
		self.conn_url.credential = cred
		if self.connection is not None:
			self.connection.set_credential(self.conn_url.get_credential())
		await self.do_whoami()
		if self.__current_dir_handle is not None:
			try:
				await self.do_refreshcurrentdir()
			except Exception as e:
				print('The current directory can not be listed as this user: %s' % e)
		return True
	
	async def do_mkdir(self, dirname:str):
		"""Creates a directory"""
		if dirname in self.__current_dirs:
			print('Directory already exists!')
			return False
		
		entry, err = await self.connection.mkdir(self.__current_dir_handle, dirname)
		if err is not None:
			raise err
		if entry is not None and entry is not False:
			print('Directory created!')
		await self.do_refreshcurrentdir()
		return True
	
	def _rmdir_completions(self):
		return PathCompleter(get_current_dirs = self.get_current_dirs)
	
	async def do_rmdir(self, dirname:str):
		"""Deletes a directory"""
		if dirname not in self.__current_dirs:
			print('Directory not found!')
			return False
		
		entry, err = await self.connection.rmdir(self.__current_dir_handle, dirname)
		if err is not None:
			raise err
		if entry is not None and entry is not False:
			print('Directory deleted!')
		await self.do_refreshcurrentdir()
		return True
	
	def _rm_completions(self):
		return PathCompleter(get_current_dirs = self.get_current_files)
	
	async def do_rm(self, filename:str):
		"""Deletes a file"""
		if filename not in self.__current_files:
			print('File not found!')
			return False
		
		entry, err = await self.connection.remove(self.__current_dir_handle, filename)
		if err is not None:
			raise err
		if entry is not None and entry is not False:
			print('File deleted!')
		await self.do_refreshcurrentdir()
		return True
	
	async def do_touch(self, filename:str):
		"""Creates a file"""
		if filename in self.__current_files:
			print('File already exists!')
			return False
		
		if self.conn_url.is_v4() is True:
			entry, err = await self.connection.create(self.__current_dir_handle, filename)
		else:
			entry, err = await self.connection.create(self.__current_dir_handle, filename, 1, mode = 0o644)
		if err is not None:
			raise err
		if entry is not None and entry is not False:
			print('File created!')
		await self.do_refreshcurrentdir()
		return True
	
	async def do_symlink(self, filename:str, linkname:str):
		"""Creates a symlink"""		
		entry, err = await self.connection.symlink(self.__current_dir_handle, filename, linkname)
		if err is not None:
			raise err
		
		if entry is not None and entry is not False:
			print('Symlink created!')
		await self.do_refreshcurrentdir()
		return True
	
	async def __getfile_internal(self, fileentry, dst_path):
		pbar = tqdm(total=fileentry.size, unit='B', unit_scale=True)
		try:
			_, err = await self.connection.download_file(fileentry.handle, dst_path, chunk_size = 1024*1024, progress_cb = pbar.update)
			if err is not None:
				raise err
		finally:
			pbar.close()
		return True, None
	
	async def __getdir_internal(self, direntry, dst_path):
		if not os.path.exists(dst_path):
			os.makedirs(dst_path)

		async for entry, err in self.connection.readdirplus(direntry.handle):
			if err is not None:
				raise err
			if entry.name in ('.', '..'):
				continue
			if entry.type not in [1,2]:
				print('Skipping %s for unknown type!' % entry.name)
				continue

			target_path = os.path.normpath(os.path.join(dst_path, entry.name))
			if not target_path.startswith(dst_path):
				print(f"Skipping {entry.name} due to path traversal attempt!")
				continue

			if entry.type == 2:
				await self.__getdir_internal(entry, target_path)
			else:
				await self.__getfile_internal(entry, target_path)
		return True, None
	
	def _getdir_completions(self):
		return PathCompleter(get_current_dirs = self.get_current_dirs)

	async def do_getdir(self, dirname):
		"""Downloads a directory with everything in it"""
		try:
			if dirname not in self.__current_dirs:
				print('Directory not found!')
				return False
			# current path
			dstpath = os.path.join(os.getcwd(), dirname)
			await self.__getdir_internal(self.__current_dirs[dirname], dstpath)
			return True
		except Exception as e:
			traceback.print_exc()
			return False

	async def do_services(self):
		"""Lists the RPC services registered at the portmapper of the server"""
		try:
			portmap = self.conn_url.get_portmap()
			_, err = await portmap.connect()
			if err is not None:
				raise err
			programs, err = await portmap.dump()
			if err is not None:
				raise err
			
			for service in programs:
				print(service)
				await asyncio.sleep(0)
			return True
		except Exception as e:
			traceback.print_exc()
			return False

async def amain(args):
	client = NFSClientConsole(args.url)
	
	if len(args.commands) == 0:
		if args.no_interactive is True:
			print('Not starting interactive!')
			return
		res = await client._run_single_command('connect', [])
		if res is False:
			return
		await client.run()
	else:
		for command in args.commands:
			if command == 'i':
				await client.run()
				return
			cmd = shlex.split(command)
			res = await client._run_single_command(cmd[0], cmd[1:])
			if res is False:
				return

def main():
	import argparse
	
	parser = argparse.ArgumentParser(description='NFS console', epilog = NFS3ConnectionFactory.get_help() + RPCTarget.get_help(), formatter_class = argparse.RawDescriptionHelpFormatter)
	parser.add_argument('-v', '--verbose', action='count', default=0, help='Verbosity, can be stacked')
	parser.add_argument('-n', '--no-interactive', action='store_true')
	parser.add_argument('url', help='Connection string in URL format.')
	parser.add_argument('commands', nargs='*', help="Takes a series of commands which will be executed until error encountered. If the command is 'i' is encountered during execution it drops back to interactive shell.")

	args = parser.parse_args()
	
	
	###### VERBOSITY
	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
	else:
		sockslogger.setLevel(logging.DEBUG)
		logger.setLevel(logging.DEBUG)
		authlogger.setLevel(logging.DEBUG)
		logging.basicConfig(level=logging.DEBUG)


	asyncio.run(amain(args))


if __name__ == '__main__':
	main()
