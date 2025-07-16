
# https://raw.githubusercontent.com/CharmingYang0/NfsClient/master/pyNfsClient/nfs3.py

import logging
from functools import wraps
from pathlib import Path
from anfs.protocol.rpc import RPC

from anfs.protocol.nfs3.pack import nfs_pro_v3Packer, nfs_pro_v3Unpacker, nextiter, NFSFileEntry
from anfs.protocol.nfs3.rtypes import (nfs_fh3, set_uint32, set_uint64, sattr3, set_time, diropargs3, setattr3args, create3args,
					 mkdir3args, symlink3args, commit3args, sattrguard3, access3args, readdir3args, readdirplus3args,
					 read3args, write3args, createhow3, symlinkdata3, mknod3args, mknoddata3, devicedata3, specdata3,
					 link3args, rename3args, nfstime3)
from anfs.protocol.nfs3.messages import (NFS3_PROCEDURE_NULL, NFS3_PROCEDURE_GETATTR, NFS3_PROCEDURE_SETATTR, NFS3_PROCEDURE_LOOKUP,
					NFS3_PROCEDURE_ACCESS, NFS3_PROCEDURE_READLINK, NFS3_PROCEDURE_READ, NFS3_PROCEDURE_WRITE,
					NFS3_PROCEDURE_CREATE, NFS3_PROCEDURE_MKDIR, NFS3_PROCEDURE_SYMLINK, NFS3_PROCEDURE_MKNOD,
					NFS3_PROCEDURE_REMOVE, NFS3_PROCEDURE_RMDIR, NFS3_PROCEDURE_RENAME, NFS3_PROCEDURE_LINK,
					NFS3_PROCEDURE_READDIR, NFS3_PROCEDURE_READDIRPLUS, NFS3_PROCEDURE_FSSTAT, NFS3_PROCEDURE_FSINFO,
					NFS3_PROCEDURE_PATHCONF, NFS3_PROCEDURE_COMMIT, NFS_PROGRAM, NFS_V3, NF3BLK, NF3CHR, NF3FIFO,
					NF3SOCK, time_how, DONT_CHANGE, SET_TO_CLIENT_TIME, SET_TO_SERVER_TIME)

from anfs.protocol.nfs3 import logger
from anfs.protocol.rpc.messages import AUTH_SYS

class NFSAccessError(Exception):
	pass


class NFSv3Client:
	def __init__(self, root_handle, target, credential=None, encoding='utf-8'):
		self.root_handle = root_handle
		self.target = target
		self.credential = credential
		self.rpc:RPC = None
		self.host = ''
		self.encoding = encoding
		self.__handle_id = 1
		self.__handles = {
			0: root_handle
		}
		# NFSv3 doesn't support getting full path from handle, so we need to keep a map of handles to names
		self.__handle_name_map = {
			root_handle: '/'
		}
		self.__parent_handles = {}
		self.__handle_reverse_map = {
			root_handle : 0
		}

	async def __aenter__(self):
		_, err = await self.connect()
		if err is not None:
			raise err
		return self
	
	async def __aexit__(self, exc_type, exc, tb):
		await self.disconnect()

	def handle_to_path(self, handle, parts=None):
		if isinstance(handle, int):
			handle = self.__handles[handle]
		if handle not in self.__handle_name_map:
			return ''
		if parts is None:
			parts = []
		if self.__handle_name_map[handle] in parts:
			# We have a loop!!! This is bad
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
	
	async def connect(self):
		try:
			self.rpc = RPC(self.target, self.credential)
			return await self.rpc.connect(NFS_PROGRAM, NFS_V3)
		except Exception as e:
			return False, e
		
	async def disconnect(self):
		if self.rpc is not None:
			return await self.rpc.disconnect()

	async def nfs_request(self, procedure, args, credential = None):
		return await self.rpc.call(NFS_PROGRAM, NFS_V3, procedure, args, credential)
		

	async def null(self):
		try:
			_, err = await self.rpc.call(NFS_PROGRAM, NFS_V3, NFS3_PROCEDURE_NULL, b'')
			if err is not None:
				raise err
			return True, None
		except Exception as e:
			return False, e

	@classmethod
	async def get_sattr3(cls, mode=None, uid=None, gid=None, size=None, atime_flag=None, atime_s=0, atime_ns=0,
				   mtime_flag=None, mtime_s=0, mtime_ns=0):
		if atime_flag not in time_how:
			raise ValueError("atime flag must be one of %s" % time_how.keys())

		if mtime_flag not in time_how:
			raise ValueError("mtime flag must be one of %s" % time_how.keys())

		attrs = sattr3(mode=set_uint32(True, int(mode)) if mode is not None else set_uint32(False),
					   uid=set_uint32(True, int(uid)) if uid is not None else set_uint32(False),
					   gid=set_uint32(True, int(gid)) if gid is not None else set_uint32(False),
					   size=set_uint64(True, int(size)) if size is not None else set_uint64(False),
					   atime=set_time(SET_TO_CLIENT_TIME, nfstime3(int(atime_s), int(atime_ns)))
							 if atime_flag == SET_TO_CLIENT_TIME else set_time(atime_flag),
					   mtime=set_time(SET_TO_CLIENT_TIME, nfstime3(int(mtime_s), int(mtime_ns)))
							 if mtime_flag == SET_TO_CLIENT_TIME else set_time(mtime_flag))
		return attrs

	async def getattr(self, file_handle):
		try:
			ofh = file_handle
			file_handle = self.__handles[file_handle]
			packer = nfs_pro_v3Packer()
			packer.pack_fhandle3(file_handle)

			logger.debug("NFSv3 procedure %d: GETATTR on %s" % (NFS3_PROCEDURE_GETATTR, self.host))
			data, err = await self.nfs_request(NFS3_PROCEDURE_GETATTR, packer.get_buffer())
			if err is not None:
				raise err
			
			unpacker = nfs_pro_v3Unpacker(data)
			response = unpacker.unpack_getattr3res()
			
			if response['status'] != 0:
				raise NFSAccessError(response['status'])

			fe = NFSFileEntry.from_attrs(response['attributes'])
			fe.handle = ofh
			
			return fe, None
		except Exception as e:
			return False, e

	# TODO: Implement setattr
	async def setattr(self, file_handle, mode=None, uid=None, gid=None, size=None,
				atime_flag=SET_TO_SERVER_TIME, atime_s=None, atime_us=None,
				mtime_flag=SET_TO_SERVER_TIME, mtime_s=None, mtime_us=None,
				check=False, obj_ctime=None):
		try:
			file_handle = self.__handles[file_handle]
			packer = nfs_pro_v3Packer()
			attrs = await self.get_sattr3(mode, uid, gid, size, atime_flag, atime_s, atime_us, mtime_flag, mtime_s, mtime_us)
			packer.pack_setattr3args(setattr3args(object=nfs_fh3(file_handle),
												new_attributes=attrs,
												guard=sattrguard3(check=check, ctime=obj_ctime)))

			logger.debug("NFSv3 procedure %d: GETATTR on %s" % (NFS3_PROCEDURE_SETATTR, self.host))
			data, err = await self.nfs_request(NFS3_PROCEDURE_SETATTR, packer.get_buffer())
			if err is not None:
				raise err

			unpacker = nfs_pro_v3Unpacker(data)
			return unpacker.unpack_setattr3res(), None
		except Exception as e:
			return False, e


	async def lookup(self, dir_handle, file_folder):
		try:
			dir_handle = self.__handles[dir_handle]

			packer = nfs_pro_v3Packer()
			packer.pack_diropargs3(diropargs3(dir=nfs_fh3(dir_handle), name=file_folder.encode()))

			logger.debug("NFSv3 procedure %d: LOOKUP on %s" % (NFS3_PROCEDURE_LOOKUP, self.host))
			data, err = await self.nfs_request(NFS3_PROCEDURE_LOOKUP, packer.get_buffer())
			if err is not None:
				raise err
			
			unpacker = nfs_pro_v3Unpacker(data)
			response = unpacker.unpack_lookup3res(data_format='json')
			
			if response['status'] != 0:
				return False, None
			
			entry = NFSFileEntry.from_attrs(response['resok']['obj_attributes']['attributes'])
			entry.name = file_folder
			entry.handle = self.register_handle(response['resok']['object']['data'], file_folder, dir_handle)
			return entry, None
		
		except Exception as e:
			return False, e

	async def access(self, file_handle, access_option):
		try:
			file_handle = self.__handles[file_handle]
			packer = nfs_pro_v3Packer()
			packer.pack_access3args(access3args(object=nfs_fh3(file_handle), access=access_option))

			logger.debug("NFSv3 procedure %d: ACCESS on %s" % (NFS3_PROCEDURE_ACCESS, self.host))
			data, err = await self.nfs_request(NFS3_PROCEDURE_ACCESS, packer.get_buffer())
			if err is not None:
				raise err
			unpacker = nfs_pro_v3Unpacker(data)
			response = unpacker.unpack_access3res()

			if response['status'] != 0:
				raise NFSAccessError(response['status'])

			return response['resok']['access'], None
		except Exception as e:
			return False, e

	async def readlink(self, file_handle):
		try:
			file_handle = self.__handles[file_handle]
			packer = nfs_pro_v3Packer()
			packer.pack_fhandle3(file_handle)

			logger.debug("NFSv3 procedure %d: READLINK on %s" % (NFS3_PROCEDURE_READLINK, self.host))
			data, err = await self.nfs_request(NFS3_PROCEDURE_READLINK, packer.get_buffer())
			if err is not None:
				raise err
			
			unpacker = nfs_pro_v3Unpacker(data)
			result = unpacker.unpack_readlink3res()
			if result['status'] != 0:
				raise NFSAccessError(result.status)
			return result['resok']['data'].decode(self.encoding), None
		except Exception as e:
			return False, e

	async def read(self, file_handle, offset=0, chunk_count=1024 * 1024, auth=None):
		try:
			file_handle = self.__handles[file_handle]
			packer = nfs_pro_v3Packer()
			packer.pack_read3args(read3args(file=nfs_fh3(file_handle), offset=offset, count=chunk_count))

			logger.debug("NFSv3 procedure %d: READ on %s" % (NFS3_PROCEDURE_READ, self.host))
			data, err = await self.nfs_request(NFS3_PROCEDURE_READ, packer.get_buffer(), auth)
			if err is not None:
				raise err
			
			unpacker = nfs_pro_v3Unpacker(data)
			response = unpacker.unpack_read3res()
			if response['status'] != 0:
				raise NFSAccessError(response['status'])
			
			return response['resok']['data'], None

		except Exception as e:
			return False, e

	async def write(self, file_handle, offset, count, content, stable_how, auth=None):
		try:
			file_handle = self.__handles[file_handle]
			packer = nfs_pro_v3Packer()
			packer.pack_write3args(write3args(file=nfs_fh3(file_handle),
											offset=offset,
											count=count,
											stable=stable_how,
											data=content))

			logger.debug("NFSv3 procedure %d: WRITE on %s" % (NFS3_PROCEDURE_WRITE, self.host))
			res, err = await self.nfs_request(NFS3_PROCEDURE_WRITE, packer.get_buffer())
			if err is not None:
				raise err
			
			unpacker = nfs_pro_v3Unpacker(res)
			return unpacker.unpack_write3res(), None
		except Exception as e:
			return False, e

	async def create(self, dir_handle, file_name, create_mode, mode=None, uid=None, gid=None, size=None,
			   atime_flag=SET_TO_SERVER_TIME, atime_s=None, atime_us=None,
				mtime_flag=SET_TO_SERVER_TIME, mtime_s=None, mtime_us=None,
			   verf='0', auth=None):
		try:
			dir_handle = self.__handles[dir_handle]	
			packer = nfs_pro_v3Packer()
			attrs = await self.get_sattr3(mode, uid, gid, size, atime_flag, atime_s, atime_us, mtime_flag, mtime_s, mtime_us)
			packer.pack_create3args(create3args(where=diropargs3(dir=nfs_fh3(dir_handle), name=file_name.encode()),
												how=createhow3(mode=create_mode, obj_attributes=attrs, verf=verf)))

			logger.debug("NFSv3 procedure %d: CREATE on %s" % (NFS3_PROCEDURE_CREATE, self.host))
			data, err = await self.nfs_request(NFS3_PROCEDURE_CREATE, packer.get_buffer())
			if err is not None:
				raise err
			
			unpacker = nfs_pro_v3Unpacker(data)
			response = unpacker.unpack_create3res()
			if response['status'] != 0:
				raise NFSAccessError(response['status'])
			
			entry = NFSFileEntry.from_attrs(response['resok']['obj_attributes']['attributes'])
			entry.name = file_name
			entry.handle = self.register_handle(response['resok']['obj']['handle']['data'], file_name, dir_handle)
			return entry, None
		except Exception as e:
			return False, e

	async def mkdir(self, dir_handle, dir_name, mode=None, uid=None, gid=None,
			  atime_flag=SET_TO_SERVER_TIME, atime_s=None, atime_us=None,
			  mtime_flag=SET_TO_SERVER_TIME, mtime_s=None, mtime_us=None):

		try:
			dir_handle = self.__handles[dir_handle]
			packer = nfs_pro_v3Packer()
			attrs = await self.get_sattr3(mode, uid, gid, None, atime_flag, atime_s, atime_us, mtime_flag, mtime_s, mtime_us)
			packer.pack_mkdir3args(mkdir3args(where=diropargs3(dir=nfs_fh3(dir_handle), name=dir_name.encode()),
											attributes=attrs))

			logger.debug("NFSv3 procedure %d: MKDIR on %s" % (NFS3_PROCEDURE_MKDIR, self.host))
			res, err = await self.nfs_request(NFS3_PROCEDURE_MKDIR, packer.get_buffer())
			if err is not None:
				raise err
			unpacker = nfs_pro_v3Unpacker(res)
			response = unpacker.unpack_mkdir3res()
			if response['status'] != 0:
				raise NFSAccessError(response['status'])
			
			entry = NFSFileEntry.from_attrs(response['resok']['obj_attributes']['attributes'])
			entry.name = dir_name
			entry.handle = self.register_handle(response['resok']['obj']['handle']['data'], dir_name, dir_handle)
			return entry, None
		except Exception as e:
			import traceback
			traceback.print_exc()
			return False, e

	async def symlink(self, dir_handle, link_name, link_to_path, auth=None):
		try:
			dir_handle = self.__handles[dir_handle]
			packer = nfs_pro_v3Packer()
			attrs = await self.get_sattr3(mode=None, size=None, uid=None, gid=None, atime_flag=DONT_CHANGE, mtime_flag=DONT_CHANGE)
			packer.pack_symlink3args(symlink3args(where=diropargs3(dir=nfs_fh3(dir_handle),
																name=link_name.encode()),
												symlink=symlinkdata3(symlink_attributes=attrs,
																	symlink_data=link_to_path.encode())))

			logger.debug("NFSv3 procedure %d: SYMLINK on %s" % (NFS3_PROCEDURE_SYMLINK, self.host))
			res, err = await self.nfs_request(NFS3_PROCEDURE_SYMLINK, packer.get_buffer())
			if err is not None:
				raise err

			unpacker = nfs_pro_v3Unpacker(res)
			result = unpacker.unpack_symlink3res()
			if result['status'] != 0:
				raise NFSAccessError(result.status)
			return True, None
		
		except Exception as e:
			return False, e

	async def mknod(self, dir_handle, file_name, ftype,
			  mode=None, uid=None, gid=None,
			  atime_flag=SET_TO_SERVER_TIME, atime_s=None, atime_us=None,
			  mtime_flag=SET_TO_SERVER_TIME, mtime_s=None, mtime_us=None,
			  spec_major=0, spec_minor=0, auth=None):
		
		try:
			dir_handle = self.__handles[dir_handle]
			packer = nfs_pro_v3Packer()
			attrs = await self.get_sattr3(mode, uid, gid, None, atime_flag, atime_s, atime_us, mtime_flag, mtime_s, mtime_us)
			if ftype in (NF3CHR, NF3BLK):
				spec = specdata3(major=spec_major, minor=spec_minor)
				what = mknoddata3(type=ftype, device=devicedata3(dev_attributes=attrs, spec=spec))
			elif ftype in (NF3SOCK, NF3FIFO):
				what = mknoddata3(type=ftype, pipe_attributes=attrs)
			else:
				raise ValueError("ftype must be one of [%d, %d, %d, %d]" % (NF3CHR, NF3BLK, NF3SOCK, NF3FIFO))
			packer.pack_mknod3args(mknod3args(where=diropargs3(dir=nfs_fh3(dir_handle),
															name=file_name.encode()),
											what=what))

			logger.debug("NFSv3 procedure %d: MKNOD on %s" % (NFS3_PROCEDURE_MKNOD, self.host))
			res = self.nfs_request(NFS3_PROCEDURE_MKNOD, packer.get_buffer())

			unpacker = nfs_pro_v3Unpacker(res)
			return unpacker.unpack_mknod3res(), None
		except Exception as e:
			return False, e


	async def remove(self, dir_handle, file_name):
		try:
			dir_handle = self.__handles[dir_handle]
			packer = nfs_pro_v3Packer()
			packer.pack_diropargs3(diropargs3(dir=nfs_fh3(dir_handle), name=file_name.encode()))

			logger.debug("NFSv3 procedure %d: REMOVE on %s" % (NFS3_PROCEDURE_REMOVE, self.host))
			res, err = await self.nfs_request(NFS3_PROCEDURE_REMOVE, packer.get_buffer())
			if err is not None:
				raise err

			unpacker = nfs_pro_v3Unpacker(res)
			response = unpacker.unpack_remove3res()
			if response['status'] != 0:
				raise NFSAccessError(response['status'])
			return True, None
		except Exception as e:
			return False, e

	async def rmdir(self, dir_handle, dir_name):
		try:
			dir_handle = self.__handles[dir_handle]
			packer = nfs_pro_v3Packer()
			packer.pack_diropargs3(diropargs3(dir=nfs_fh3(dir_handle), name=dir_name.encode()))

			logger.debug("NFSv3 procedure %d: RMDIR on %s" % (NFS3_PROCEDURE_RMDIR, self.host))
			res, err = await self.nfs_request(NFS3_PROCEDURE_RMDIR, packer.get_buffer())
			if err is not None:
				raise err

			unpacker = nfs_pro_v3Unpacker(res)
			response = unpacker.unpack_rmdir3res()
			if response['status'] != 0:
				raise NFSAccessError(response['status'])

			return True, None
		except Exception as e:
			return False, e

	async def rename(self, dir_handle_from, from_name, dir_handle_to, to_name, auth=None):
		try:
			dir_handle_from = self.__handles[dir_handle_from]
			dir_handle_to = self.__handles[dir_handle_to]

			packer = nfs_pro_v3Packer()
			packer.pack_rename3args(rename3args(from_v=diropargs3(dir=nfs_fh3(dir_handle_from),
																name=from_name.encode()),
												to=diropargs3(dir=nfs_fh3(dir_handle_to),
															name=to_name.encode())))

			logger.debug("NFSv3 procedure %d: RENAME on %s" % (NFS3_PROCEDURE_RENAME, self.host))
			res, err = await self.nfs_request(NFS3_PROCEDURE_RENAME, packer.get_buffer())

			unpacker = nfs_pro_v3Unpacker(res)
			return unpacker.unpack_rename3res(), None
		except Exception as e:
			return False, e

	
	async def link(self, file_handle, link_to_dir_handle, link_name, auth=None):
		try:
			file_handle = self.__handles[file_handle]
			link_to_dir_handle = self.__handles[link_to_dir_handle]
			packer = nfs_pro_v3Packer()
			packer.pack_link3args(link3args(file=nfs_fh3(file_handle),
											link=diropargs3(dir=nfs_fh3(link_to_dir_handle), name=link_name.encode())))

			logger.debug("NFSv3 procedure %d: LINK on %s" % (NFS3_PROCEDURE_LINK, self.host))
			res, err = await self.nfs_request(NFS3_PROCEDURE_LINK, packer.get_buffer())
			if err is not None:
				raise err
			
			unpacker = nfs_pro_v3Unpacker(res)
			return unpacker.unpack_link3res(), None
		except Exception as e:
			return False, e

	async def readdir(self, dir_handle, cookie=0, cookie_verf='0', count=4096):
		try:
			dir_handle = self.__handles[dir_handle]
			packer = nfs_pro_v3Packer()
			packer.pack_readdir3args(readdir3args(dir=nfs_fh3(dir_handle),
												cookie=cookie,
												cookieverf=cookie_verf.encode(),
												count=count))

			logger.debug("NFSv3 procedure %d: READDIR on %s" % (NFS3_PROCEDURE_READDIR, self.host))
			res, err =  await self.nfs_request(NFS3_PROCEDURE_READDIR, packer.get_buffer())
			if err is not None:
				raise err
			
			unpacker = nfs_pro_v3Unpacker(res)
			fl = unpacker.unpack_readdir3res(data_format='')
			if fl.status != 0:
				raise NFSAccessError(fl.status)
			
			last_cookie = 0
			for entry in nextiter(fl.resok.reply.entries):
				last_cookie = entry['cookie']
				entry, realhandle = NFSFileEntry.from_dict(entry, encoding=self.encoding)
				entry.handle = self.register_handle(realhandle, entry.name, dir_handle)

				yield entry, None
			
			if fl.resok.reply.eof is False:
				async for entry, err in self.readdirplus(dir_handle, last_cookie, cookie_verf, count):
					entry, realhandle = NFSFileEntry.from_dict(entry, encoding=self.encoding)
					entry.handle = self.register_handle(realhandle, entry.name, dir_handle)
					yield entry, err

		except Exception as e:
			yield False, e
	
	# This version was provided by PTG
	# The original version was not working properly
	async def readdirplus(self, dir_handle, cookie=0, cookie_verf=b'\x00', dircount=4096, maxcount=32768, auth=None):
		try:
			real_dir_handle = self.__handles[dir_handle]
			packer = nfs_pro_v3Packer()
			packer.pack_readdirplus3args(readdirplus3args(dir=nfs_fh3(real_dir_handle),
				cookie=cookie,
				cookieverf=cookie_verf,
				dircount=dircount,
				maxcount=maxcount)
			)
			
			logger.debug("NFSv3 procedure %d: READDIRPLUS on %s" % (NFS3_PROCEDURE_READDIRPLUS, self.host))
			res, err = await self.nfs_request(NFS3_PROCEDURE_READDIRPLUS, packer.get_buffer(), auth)
			if err is not None:
				raise err
			unpacker = nfs_pro_v3Unpacker(res)
			fl = unpacker.unpack_readdirplus3res(data_format='')
			if fl.status != 0:
				raise NFSAccessError(fl.status)
			
			last_cookie = 0
			last_cookie_verf = fl.resok.cookieverf
			for entry in nextiter(fl.resok.reply.entries):
				last_cookie = entry['cookie']
				entry, realhandle = NFSFileEntry.from_dict(entry, encoding=self.encoding)
				entry.handle = self.register_handle(realhandle, entry.name, real_dir_handle)
				yield entry, None
						   
			if fl.resok.reply.eof is False:
				async for entry, err in self.readdirplus(dir_handle, last_cookie, last_cookie_verf, dircount, maxcount, auth):
					yield entry, err

		except Exception as e:
			yield False, e

	async def enumall(self, dir_handle = 0, depth = 3, filter_cb = None, auth = None):
		try:
			curpath = self.handle_to_path(dir_handle)
			if depth == 0:
				return
			
			if auth == None:
				attrs, err = await self.getattr(dir_handle)
				if err == None:
					auth = AUTH_SYS(uid = attrs.uid, gid = attrs.gid)
				else:
					auth = AUTH_SYS(uid = 0, gid = 0)
			
			async for entry, err in self.readdirplus(dir_handle, auth = auth):
				if err is not None:
					raise err
				#print(str(entry))
				entrypath = curpath + '/' + entry.name
				if entry.type == 5:
					# TODO: Implement symlink handling
					yield entrypath, 'symlink', entry, None
				elif entry.type == 1:
					yield entrypath, 'file', entry, None

				elif entry.type == 2:
					if entry.name == '.' or entry.name == '..':
						continue
					yield entrypath, 'dir', entry, None
					if filter_cb is not None:
						tograb = await filter_cb(entrypath, entry)
						if tograb is False:
							continue
					
					async for epath, etype, ee, err in self.enumall(dir_handle = entry.handle, depth=depth - 1, filter_cb=filter_cb, auth=AUTH_SYS(uid=entry.uid, gid=entry.gid)):
						yield epath, etype, ee, err
				else:
					# currently not supported types
					#Type 1: Regular File
					#Type 2: Directory
					#Type 3: Block Special Device
					#Type 4: Character Special Device
					#Type 5: Symbolic Link
					#Type 6: Socket
					#Type 7: Named Pipe (FIFO)
					#Type 8: Unknown Type (usually for files with unknown types)
					continue
		except Exception as e:
			yield None, None, None, e
				
				
	async def download_file(self, file_handle, local_path, chunk_size = 4096, max_size = None, uid = 0, gid = 0):
		try:
			done = False
			bytes_read = 0

			local_path = Path(local_path)
			if local_path.is_dir():
				local_path = local_path.joinpath(self.__handle_name_map[self.__handles[file_handle]])
			
			with open(local_path, 'wb') as f:
				while not done:
					data, err = await self.read(file_handle, bytes_read, chunk_size, auth = AUTH_SYS(uid = uid, gid = gid))

					if err is not None:
						raise err
					
					f.write(data)

					bytes_read += len(data)
					
					if len(data) <= chunk_size or (max_size is not None and bytes_read >= max_size):
						done = True
			
			return local_path, None

		except Exception as e:
			return False, e


	#async def readdirplus(self, dir_handle, cookie=0, cookie_verf='0', dircount=4096, maxcount=32768):
	#	try:
	#		dir_handle = self.__handles[dir_handle]
	#		packer = nfs_pro_v3Packer()
	#		packer.pack_readdirplus3args(readdirplus3args(dir=nfs_fh3(dir_handle),
	#													cookie=cookie,
	#													cookieverf=cookie_verf.encode(),
	#													dircount=dircount,
	#													maxcount=maxcount))
	#
	#		logger.debug("NFSv3 procedure %d: READDIRPLUS on %s" % (NFS3_PROCEDURE_READDIRPLUS, self.host))
	#		res, err = await self.nfs_request(NFS3_PROCEDURE_READDIRPLUS, packer.get_buffer())
	#		if err is not None:
	#			raise err
	#
	#		
	#		unpacker = nfs_pro_v3Unpacker(res)
	#		fl = unpacker.unpack_readdirplus3res(data_format='')
	#		if fl.status != 0:
	#			raise NFSAccessError(fl.status)
	#		
	#		last_cookie = 0
	#		for entry in nextiter(fl.resok.reply.entries):
	#			last_cookie = entry['cookie']
	#			entry, realhandle = NFSFileEntry.from_dict(entry, encoding=self.encoding)
	#			entry.handle = self.register_handle(realhandle, entry.name, dir_handle)
	#
	#			yield entry, None
	#		
	#		if fl.resok.reply.eof is False:
	#			async for entry, err in self.readdirplus(dir_handle, last_cookie, cookie_verf, dircount, maxcount):
	#				entry, realhandle = NFSFileEntry.from_dict(entry, encoding=self.encoding)
	#				entry.handle = self.register_handle(realhandle, entry.name, dir_handle)
	#				yield entry, err
	#
	#	except Exception as e:
	#		yield False, e
	#
	
	async def fsstat(self, file_handle, auth=None):
		try:
			file_handle = self.__handles[file_handle]
			packer = nfs_pro_v3Packer()
			packer.pack_fhandle3(file_handle)

			logger.debug("NFSv3 procedure %d: FSSTAT on %s" % (NFS3_PROCEDURE_FSSTAT, self.host))
			data = self.nfs_request(NFS3_PROCEDURE_FSSTAT, packer.get_buffer())

			unpacker = nfs_pro_v3Unpacker(data)
			return unpacker.unpack_fsstat3res(), None
		except Exception as e:
			return False, e

	
	async def fsinfo(self, file_handle, auth=None):
		try:
			file_handle = self.__handles[file_handle]
			packer = nfs_pro_v3Packer()
			packer.pack_fhandle3(file_handle)

			logger.debug("NFSv3 procedure %d: FSINFO on %s" % (NFS3_PROCEDURE_FSINFO, self.host))
			data, err = await self.nfs_request(NFS3_PROCEDURE_FSINFO, packer.get_buffer())
			if err is not None:
				raise err

			unpacker = nfs_pro_v3Unpacker(data)
			return unpacker.unpack_fsinfo3res(), None
		except Exception as e:
			return False, e

	async def pathconf(self, file_handle, auth=None):
		try:
			file_handle = self.__handles[file_handle]
			packer = nfs_pro_v3Packer()
			packer.pack_fhandle3(file_handle)

			logger.debug("NFSv3 procedure %d: PATHCONF on %s" % (NFS3_PROCEDURE_PATHCONF, self.host))
			data, err = await self.nfs_request(NFS3_PROCEDURE_PATHCONF, packer.get_buffer())
			if err is not None:
				raise err

			unpacker = nfs_pro_v3Unpacker(data)
			return unpacker.unpack_pathconf3res(), None
		except Exception as e:
			return False, e


	async def commit(self, file_handle, count=0, offset=0, auth=None):
		try:
			file_handle = self.__handles[file_handle]
			packer = nfs_pro_v3Packer()
			packer.pack_commit3args(commit3args(file=nfs_fh3(file_handle), offset=offset, count=count))

			logger.debug("NFSv3 procedure %d: COMMIT on %s" % (NFS3_PROCEDURE_COMMIT, self.host))
			res = self.nfs_request(NFS3_PROCEDURE_COMMIT, packer.get_buffer())

			unpacker = nfs_pro_v3Unpacker(res)
			return unpacker.unpack_commit3res(), None
		except Exception as e:
			return False, e

async def amain():
	from anfs.protocol.rpc.common.target import RPCTarget
	from anfs.protocol.rpc.messages import AUTH_SYS
	from anfs.protocol.mount import Mount
	import pprint

	ip = '192.168.30.10'
	target = RPCTarget(ip)
	cred = AUTH_SYS(machinename='192.168.30.195') #192.168.30.195
	mount = Mount(target, cred)
	_, err = await mount.connect()
	if err is not None:
		raise err
	
	fhandle, err = await mount.mount('/volume1/NFSTEST')
	if err is not None:
		raise err
	print(fhandle)
	
	nfs = NFSv3Client(fhandle, target, cred)
	_, err = await nfs.connect()
	if err is not None:
		raise err
	
	async for epath, etype, ee, err in nfs.enumall():
		if err is not None:
			print(err)
		print(epath)
	
	
	return
	nfs = NFSv3(fhandle, target, cred)
	_, err = await nfs.connect()
	if err is not None:
		raise err
	res, err = await nfs.fsinfo(0)
	if err is not None:
		raise err
	print(res)

	res, err = await nfs.pathconf(0)
	if err is not None:
		raise err
	print(res)

	#_, err = await nfs.null()
	#if err is not None:
	#	raise err
	res, err = await nfs.access(0, 0x1f)
	async for entry, err in nfs.readdirplus(0):
		if err is not None:
			raise err
		print(str(entry))
	

	res, err = await nfs.getattr(0)
	print(res)

	res, err = await nfs.lookup(0, 'test')
	print(res)

	th = None
	async for entry, err in nfs.readdirplus(res.handle):
		if err is not None:
			raise err
		print(str(entry))
		if entry.name.startswith(b'Terasz-20180919-212510-1537385110.mp4'):
			th = entry.handle
			break
	
	print(th)
	res, err = await nfs.read(th, 0, 10)
	print(res)

def main():
	import asyncio
	asyncio.run(amain())
if __name__ == '__main__':
	main()