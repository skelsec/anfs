import copy
from asysocks.unicomm.common.target import UniTarget, UniProto
from anfs.protocol.portmap.messages import ipproto
from urllib.parse import urlparse, parse_qs
from asysocks.unicomm.utils.paramprocessor import str_one, int_one, bool_one

rpctarget_url_params = {
	'fragsize': int_one,
	'transport': str_one,
	'portmapport': int_one,
	'mountport': int_one,
	'nfsport': int_one,
}

class RPCTarget(UniTarget):
	def __init__(self, ip, port = 0, protocol = UniProto.CLIENT_TCP, proxies = None, timeout = 10, dns:str=None, dc_ip:str = None, domain:str = None, hostname:str = None, ssl_ctx = None, use_privileged_source_port:bool=False, fragsize = 1048576, portmap_port:int = 111, mount_port:int = 0, nfs_port:int = 0):
		UniTarget.__init__(self, ip, port, protocol, timeout, hostname = hostname, ssl_ctx= ssl_ctx, proxies = proxies, domain = domain, dc_ip = dc_ip, dns=dns, use_privileged_source_port=use_privileged_source_port)
		self.fragsize = fragsize
		# port is the port of the service this target points to, 0 means the portmapper will be asked for it
		# The ports below are the ones the individual services are reached on, 0 means ask the portmapper
		self.portmap_port = portmap_port
		self.mount_port = mount_port
		self.nfs_port = nfs_port
	
	def get_rpcprotocol(self):
		if self.protocol in [UniProto.CLIENT_TCP, UniProto.SERVER_TCP, UniProto.CLIENT_SSL_TCP, UniProto.SERVER_SSL_TCP]:
			return ipproto.IPPROTO_TCP.value
		if self.protocol in [UniProto.CLIENT_UDP, UniProto.SERVER_UDP]:
			return ipproto.IPPROTO_UDP.value
		raise Exception('Unknown protocol')

	def is_udp(self):
		return self.protocol in [UniProto.CLIENT_UDP, UniProto.SERVER_UDP]

	def get_newtarget(self, ip, port, hostname = None):
		t = copy.deepcopy(self)
		t.ip = ip
		t.port = port
		t.hostname = hostname
		return t

	def get_portmap_target(self):
		return self.get_newtarget(self.ip, self.portmap_port, self.hostname)

	def get_mount_target(self):
		return self.get_newtarget(self.ip, self.mount_port, self.hostname)

	def get_nfs_target(self):
		return self.get_newtarget(self.ip, self.nfs_port, self.hostname)

	@staticmethod
	def get_help(helptype:str = 'url'):
		if helptype == 'url':
			return 'NFS related parameters -query params-:\n' + \
				'\tThe port in the URL is the port of the NFS service, same as "nfsport"\n' + \
				'\ttransport - str - "tcp" (default) or "udp"\n' + \
				'\tportmapport - int - port of the portmapper (default: 111)\n' + \
				'\tmountport - int - port of the mount service (default: ask the portmapper)\n' + \
				'\tnfsport - int - port of the NFS service (default: ask the portmapper)\n' + \
				'\tprivport - bool - use a source port below 1024, needs privileges\n' + \
				'\tfragsize - int - RPC fragment size in bytes\n'
		return ''

	@staticmethod
	def from_url(connection_url:str):
		url_e = urlparse(connection_url)
		unitarget, extraparams = UniTarget.from_url(connection_url, UniProto.CLIENT_TCP, 0, rpctarget_url_params)
		fragsize = extraparams['fragsize'] if extraparams['fragsize'] is not None else 1048576

		protocol = UniProto.CLIENT_TCP
		if extraparams['transport'] is not None:
			transport = extraparams['transport'].lower()
			if transport == 'udp':
				protocol = UniProto.CLIENT_UDP
			elif transport != 'tcp':
				raise Exception('Unknown transport "%s", must be "tcp" or "udp"' % extraparams['transport'])

		nfs_port = 0
		if url_e.port:
			nfs_port = url_e.port
		if extraparams['nfsport'] is not None:
			nfs_port = extraparams['nfsport']

		target = RPCTarget(
			unitarget.ip, 
			port = 0, 
			protocol = protocol, 
			proxies = unitarget.proxies, 
			timeout = unitarget.timeout, 
			dns = unitarget.dns, 
			dc_ip = unitarget.dc_ip, 
			domain = unitarget.domain, 
			hostname = unitarget.hostname,
			ssl_ctx = unitarget.ssl_ctx,
			fragsize = fragsize,
			use_privileged_source_port = unitarget.use_privileged_source_port,
			portmap_port = extraparams['portmapport'] if extraparams['portmapport'] is not None else 111,
			mount_port = extraparams['mountport'] if extraparams['mountport'] is not None else 0,
			nfs_port = nfs_port,
		)
		return target
