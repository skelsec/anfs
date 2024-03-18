#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import os
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

		if mountpoint == self.__current_mountpoint:
			print('Already using this mountpoint!')
			return True
		
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
		self.prompt = '[%s%s]> ' % (self.__current_mountpoint, self.connection.handle_to_path(self.__current_dir_handle))
		await self.do_refreshcurrentdir()
		return True
	
	def _get_completions(self):
		return PathCompleter(get_current_dirs = self.get_current_files)
	
	async def do_get(self, filename:str):
		"""Downloads a file"""
		if filename not in self.__current_files:
			print('File not found!')
			return False
		
		fh = self.__current_files[filename].handle
		size = 0
		pbar = tqdm(total=self.__current_files[filename].size, unit='B', unit_scale=True)
		with open(filename, 'wb') as f:
			while size < self.__current_files[filename].size:
				data, err = await self.connection.read(fh, size, 10*1024*1024)
				if err is not None:
					raise err
				f.write(data)
				size += len(data)
				pbar.update(len(data))
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
		
		entry, err = await self.connection.create(self.__current_dir_handle, filename, 1)
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
		size = 0
		pbar = tqdm(total=fileentry.size, unit='B', unit_scale=True)
		with open(dst_path, 'wb') as f:
			while size < fileentry.size:
				data, err = await self.connection.read(fileentry.handle, size, 10*1024*1024)
				if err is not None:
					raise err
				f.write(data)
				size += len(data)
				pbar.update(len(data))
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
	
	async def do_getdir(self, dirname):
		try:
			if dirname not in self.__current_dirs:
				print('Directory not found!')
				return False
			# current path
			dstpath = os.path.join(os.getcwd(), dirname)
			return await self.__getdir_internal(self.__current_dirs[dirname], dstpath)
		except Exception as e:
			traceback.print_exc()
			return False

	async def do_services(self):
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
	
	parser = argparse.ArgumentParser(description='NFSv3 console')
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
