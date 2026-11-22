
#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import enum
import copy
from urllib.parse import urlparse, parse_qs

from anfs.protocol.rpc import RPC
from anfs.protocol.portmap import Portmap
from anfs.protocol.mount import Mount
from anfs.protocol.rpc.common.target import RPCTarget
from anfs.protocol.rpc.messages import AUTH_SYS, AUTH_NULL
from anfs.protocol.nfs3.client import NFSv3Client
from anfs.protocol.nfs4.client import NFSv4Client
from asyauth.common.credentials import UniCredential

class NFS3ConnectionFactory:	
	def __init__(self, credential:UniCredential = None, target:RPCTarget = None, version = '3'):
		self.credential = credential
		self.target = target
		# NFS protocol version asked for in the URL: 3, 4.1 or 4.2
		self.version = NFS3ConnectionFactory.parse_version(version)

	@staticmethod
	def from_url(connection_url):
		target = RPCTarget.from_url(connection_url)
		credential = NFS3ConnectionFactory.authsys_from_url(connection_url)
		#credential = UniCredential.from_url(connection_url)
		query = parse_qs(urlparse(connection_url).query)
		version = query['version'][0] if 'version' in query else '3'
		return NFS3ConnectionFactory(credential, target, version)

	@staticmethod
	def parse_version(version):
		"""Returns the (major, minor) version tuple for the version string"""
		version = str(version).lower().lstrip('v')
		if version == '3':
			return (3, 0)
		if version in ('4', '4.1'):
			return (4, 1)
		if version == '4.2':
			return (4, 2)
		if version == '4.0':
			raise Exception('NFSv4.0 is not supported yet, use 4.1 or 4.2')
		raise Exception('Unknown NFS version "%s", must be one of 3, 4, 4.1, 4.2' % version)

	def is_v4(self):
		return self.version[0] == 4

	@staticmethod
	def authsys_from_url(connection_url):
		"""
		Creates an AUTH_SYS credential from the uid, gid, gids and machinename query parameters
		"""
		query = parse_qs(urlparse(connection_url).query)
		uid = int(query['uid'][0]) if 'uid' in query else None
		gid = int(query['gid'][0]) if 'gid' in query else None
		gids = None
		if 'gids' in query:
			gids = [int(x) for x in ','.join(query['gids']).split(',') if x != '']
		machinename = query['machinename'][0] if 'machinename' in query else None
		return AUTH_SYS(machinename = machinename, uid = uid, gid = gid, gids = gids)

	@staticmethod
	def get_help(helptype:str = 'url'):
		if helptype == 'url':
			return 'Protocol version -query params-:\n' + \
				'\tversion - str - 3 (default), 4 or 4.1, 4.2\n' + \
				'Authentication (AUTH_SYS) related parameters -query params-:\n' + \
				'\tuid - int - user id to present to the server (default: 0)\n' + \
				'\tgid - int - group id to present to the server (default: 0)\n' + \
				'\tgids - str - comma separated list of auxiliary group ids\n' + \
				'\tmachinename - str - client machine name to present to the server (default: anfs)\n'
		return ''

	def get_credential(self) -> UniCredential:
		"""
		Creates a credential object
		
		:return: Credential object
		:rtype: :class:`UniCredential`
		"""
		return copy.deepcopy(self.credential)

	def get_target(self) -> RPCTarget:
		"""
		Creates a target object
		
		:return: Target object
		:rtype: :class:`RPCTarget`
		"""
		return copy.deepcopy(self.target)
	
	def get_portmap(self) -> Portmap:
		"""
		Creates a portmap object
		"""

		target = self.get_target().get_portmap_target()
		# The PORTMAP protocol is queried with AUTH_NULL - it carries no
		# meaningful AUTH_SYS authorization and many implementations silently
		# drop AUTH_SYS requests. NFS file operations use their own credential.
		return Portmap(target, AUTH_NULL())
	
	def get_mount(self):
		"""
		Creates a mount object
		
		:return: Mount object
		:rtype: :class:`Mount`
		"""
		
		target = self.get_target().get_mount_target()
		# mountd is queried with AUTH_NULL for the same reason as portmap above:
		# AUTH_SYS is meant for NFS file ops, and several mountd implementations
		# only answer AUTH_NULL (silently dropping AUTH_SYS, which manifests as a
		# timeout). The actual NFS operations still use the factory credential.
		return Mount(target, AUTH_NULL())

	def get_client(self, root_handle) -> NFSv3Client:
		"""
		Creates a client that can be used to interface with the server
		
		:return: NFSv3 client
		:rtype: :class:`NFSv3Client`
		"""
		cred = self.get_credential()
		target = self.get_target().get_nfs_target()
		return NFSv3Client(root_handle, target, cred)

	def get_client4(self) -> NFSv4Client:
		"""
		Creates an NFSv4 client. There is no mount protocol in NFSv4, the
		client starts at the root of the server's namespace.

		:return: NFSv4 client
		:rtype: :class:`NFSv4Client`
		"""
		cred = self.get_credential()
		target = self.get_target().get_nfs_target()
		if target.port == 0:
			# NFSv4 servers are not required to register with the portmapper (or to have one)
			target.port = 2049
		minorversion = self.version[1] if self.is_v4() else 1
		return NFSv4Client(target, cred, minorversion = minorversion)


	def get_connection(self) -> RPC:
		"""
		Creates a connection that can be used to interface with the server
		
		:return: RPC connection
		:rtype: :class:`RPC`
		"""
		cred = self.get_credential()
		target = self.get_target()
		return RPC(target, cred)
	
	def create_factory_newtarget(self, ip_or_hostname):
		"""
		Creates a connection that can be used to interface with the server
		
		:return: A new factory object
		:rtype: :class:`NFS3ConnectionFactory`
		"""
		target = self.target.get_newtarget(ip_or_hostname, 0)
		cred = self.get_credential()
		res = NFS3ConnectionFactory(credential = cred, target = target)
		res.version = self.version
		return res
		
	def __str__(self):
		t = '==== NFSConnectionFactory ====\r\n'
		for k in self.__dict__:
			val = self.__dict__[k]
			if isinstance(val, enum.IntFlag):
				val = val
			elif isinstance(val, enum.Enum):
				val = val.name
			
			t += '%s: %s\r\n' % (k, str(val))
			
		return t


