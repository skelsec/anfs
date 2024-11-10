from asysocks.unicomm.common.scanner.targetgen import UniTargetGen, UniCredentialGen
from asysocks.unicomm.common.scanner.scanner import UniScanner
from anfs.protocol.nfs3.common.factory import NFS3ConnectionFactory
from asysocks.unicomm.common.scanner.common import *

class NFSFileRes:
	def __init__(self, obj, otype, err):
		self.obj = obj
		self.otype = otype
		self.err = err

	# https://stackoverflow.com/questions/1094841/get-human-readable-version-of-file-size
	@staticmethod
	def sizeof_fmt(num, suffix='B'):
		if num is None:
			return ''
		for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
			if abs(num) < 1024.0:
				return "%3.1f%s%s" % (num, unit, suffix)
			num /= 1024.0
		return "%.1f%s%s" % (num, 'Yi', suffix)

	def get_header(self):
		return ['otype', 'path', 'creationtime', 'size', 'sizefmt']

	def to_line(self, separator = '\t'):
		if self.err is not None:
			unc_path = ''
			try:
				unc_path = str(self.obj.unc_path)
			except:
				pass
			return separator.join([
				'err',
				unc_path,
				str(self.err)
			])

		unc_path = ''
		creationtime = ''
		size = ''
		sizefmt = ''
		if self.otype in ['dir', 'file', 'mount']:
			unc_path = str(self.obj.unc_path)
			if self.otype == 'dir' or self.otype == 'file' or self.otype == 'mount':
				if self.otype == 'dir' or self.otype == 'file':
					if self.obj.creation_time is not None:
						creationtime = self.obj.creation_time.isoformat()
			
			if self.otype == 'file':
				size = self.obj.size
				sizefmt = NFSFileRes.sizeof_fmt(size)

		if self.otype == 'file':
			return separator.join([
				'file',
				unc_path,
				creationtime,
				str(size), 
				sizefmt,
			])
		if self.otype == 'dir' or self.otype == 'symlink':
			return separator.join([
				self.otype,
				unc_path, 
				creationtime, 
			])
		if self.otype == 'mount':
			return separator.join([
				'mount',
				unc_path,
			])
		else:
			return separator.join([
				self.otype,
				unc_path,
				creationtime,
			])

class NFS3FileScanner:
	def __init__(self, 
			factory:NFS3ConnectionFactory, 
			depth = 3,
			max_items = None,
			):
		
		self.factory = factory
		self.depth = depth 
		self.maxentries = max_items

	async def run(self, targetid, target, out_queue):
		try:
			newfactory = self.factory.create_factory_newtarget(target)
			mount = newfactory.get_mount()
			_, err = await mount.connect()
			if err is not None:
				raise err
			
			mountpoints, err = await mount.dump()
			if err is not None:
				raise err
			
			mounts = {}
			for mountpoint in mountpoints:
				mounts[mountpoint.directory] = mountpoint

			for mountpoint in mounts:
				await out_queue.put(ScannerData(target, NFSFileRes(mounts[mountpoint].to_smbshare(target), 'mount', None)))

				mhandle, err = await mount.mount(mountpoint)
				if err is not None:
					raise err

				nfs = newfactory.get_client(mhandle)
				_, err = await nfs.connect()
				if err is not None:
					raise err
				
				async for epath, etype, entry, err in nfs.enumall(0, depth=self.depth):
					await out_queue.put(ScannerData(target, NFSFileRes(entry.to_smbfile(mountpoint, epath), etype, err)))

		except Exception as e:
			await out_queue.put(ScannerError(target, e))


async def nfsenum(url, targets, worker_count:int = 10, no_progress:bool = False, out_file:str=None, include_errors:bool=False, depth:int= 3):
	connectionfactory = NFS3ConnectionFactory.from_url(url)
	executor = NFS3FileScanner(connectionfactory, depth=depth)
	tgen = UniTargetGen.from_list(targets)
	scanner = UniScanner('NFS3FileScanner', [executor], [tgen], worker_count=worker_count, host_timeout=None)
	await scanner.scan_and_process(progress=no_progress, out_file=out_file, include_errors=include_errors)
	
def main():
	import asyncio
	import argparse

	parser = argparse.ArgumentParser(description='Enumerate NFS mounts and files')
	parser.add_argument('url', help='Connection string in URL format')
	parser.add_argument('-d', '--depth', type=int, default=3, help='Depth of the enumeration')
	parser.add_argument('-w', '--worker-count', type=int, default=100, help='Parallell count')
	parser.add_argument('--no-progress', action='store_false', help='Disable progress bar')
	parser.add_argument('-o', '--out-file', help='Output file path.')
	parser.add_argument('-e', '--errors', action='store_true', help='Includes errors in output.')
	parser.add_argument('targets', nargs='*', help = 'Hostname or IP address or file with a list of targets')

	args = parser.parse_args()

	asyncio.run(
		nfsenum(
			args.url,
			args.targets,
			worker_count = args.worker_count,
			no_progress = args.no_progress,
			out_file = args.out_file,
			include_errors = args.errors,
			depth = args.depth
		)
	)

if __name__ == '__main__':
	main()