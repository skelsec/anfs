
#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import enum
import copy

from anfs.protocol.rpc import RPC
from anfs.protocol.portmap import Portmap
from anfs.protocol.mount import Mount
from anfs.protocol.rpc.common.target import RPCTarget
from anfs.protocol.rpc.messages import AUTH_SYS
from anfs.protocol.nfs3.client import NFSv3Client
from asyauth.common.credentials import UniCredential

class NFS3ConnectionFactory:	
	def __init__(self, credential:UniCredential = None, target:RPCTarget = None ):
		self.credential = credential
		self.target = target

	@staticmethod
	def from_url(connection_url):
		target = RPCTarget.from_url(connection_url)
		credential = AUTH_SYS()
		#credential = UniCredential.from_url(connection_url)
		return NFS3ConnectionFactory(credential, target)

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

		target = self.get_target()
		target.port = 111
		cred = self.get_credential()
		return Portmap(target, cred)
	
	def get_mount(self):
		"""
		Creates a mount object
		
		:return: Mount object
		:rtype: :class:`Mount`
		"""
		
		target = self.get_target()
		cred = self.get_credential()
		return Mount(target, cred)

	def get_client(self, root_handle) -> NFSv3Client:
		"""
		Creates a client that can be used to interface with the server
		
		:return: NFSv3 client
		:rtype: :class:`NFSv3Client`
		"""
		cred = self.get_credential()
		target = self.get_target()
		return NFSv3Client(root_handle, target, cred)


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
		return NFS3ConnectionFactory(credential = cred, target = target)
		
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


