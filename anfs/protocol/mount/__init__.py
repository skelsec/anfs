from anfs.protocol.rpc import RPC
import traceback
import io
from anfs.protocol.mount.messages import export, fhstatus, mountpoint, pack_str

# https://datatracker.ietf.org/doc/html/rfc1094#appendix-A

class Mount:
	def __init__(self, target, credential = None):
		self.target = target
		self.credential = credential
		self.rpc = None
	
	async def __aenter__(self):
		_, err = await self.connect()
		if err is not None:
			raise err
		return self
	
	async def __aexit__(self, exc_type, exc, tb):
		await self.disconnect()
	
	async def connect(self):
		self.rpc = RPC(self.target, self.credential)
		return await self.rpc.connect(100005, 1)
	
	async def disconnect(self):
		if self.rpc is not None:
			await self.umountall()
			return await self.rpc.disconnect()
	
	async def null(self):
		"""Null call"""
		data = b''
		return await self.rpc.call(100005, 1, 0, data)
	
	async def mount(self, path):
		"""Mount a directory"""
		try:
			data = pack_str(path)
			res, err = await self.rpc.call(100005, 3, 1, data)
			if err is not None:
				raise err
			
			res = fhstatus.from_bytes(res)
			return res.fhandle, None
		except Exception as e:
			return None, e

	async def dump(self):
		"""Fetches all the mount entries from the server"""
		try:
			entries = []
			entries_buff, err = await self.rpc.call(100005, 1, 2, b'')
			if err is not None:
				raise err
			
			if len(entries_buff) < 4:
				return entries
		
			entries_buff = io.BytesIO(entries_buff)
			while entries_buff.read(4) == b'\x00\x00\x00\x01':
				entries.append(mountpoint.from_buffer(entries_buff))
			return entries, None
		except Exception as e:
			return None, e
	
	async def umount(self, path):
		"""Unmount a directory"""
		data = pack_str(path)
		res, err = await self.rpc.call(100005, 1, 3, data)
		if err is not None:
			raise err
		
		return res
	
	async def umountall(self):
		"""Unmount all directories"""
		res, err = await self.rpc.call(100005, 1, 4, b'')
		if err is not None:
			raise err
		
		return res
	
	async def export(self):
		"""Export a directory"""
		res, err = await self.rpc.call(100005, 1, 5, b'')
		if err is not None:
			return None, err
		
		results = []
		res = io.BytesIO(res)
		while res.read(4) == b'\x00\x00\x00\x01':
			results.append(export.from_buffer(res))
		return results, None

async def amain():
	from anfs.protocol.rpc.common.target import RPCTarget
	from anfs.protocol.rpc.messages import AUTH_SYS

	ip = '192.168.30.10'
	target = RPCTarget(ip)
	cred = None #AUTH_SYS(machinename='192.168.30.195') #192.168.30.195
	mount = Mount(target, cred)
	try:
		_, err = await mount.connect()
		if err is not None:
			raise err
		pm, err = await mount.export()
		for p in pm:
			print(str(p))
		
		entries, err = await mount.dump()
		if err is not None:
			raise err
		for e in entries:
			print(str(e))
		await mount.mount('/volume1/NFSTEST')
		#port = await portmap.getport(100000, 2, 6)
		#print(port)
		#curtime = await mount.export()
		#print(curtime)
	except Exception as e:
		traceback.print_exc()
def main():
	import asyncio
	asyncio.run(amain())

if __name__ == '__main__':
	main()