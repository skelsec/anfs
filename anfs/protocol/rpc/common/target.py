import copy
from asysocks.unicomm.common.target import UniTarget, UniProto
from anfs.protocol.portmap.messages import ipproto
from urllib.parse import urlparse, parse_qs
from asysocks.unicomm.utils.paramprocessor import str_one, int_one, bool_one

rpctarget_url_params = {
	'fragsize': int_one,
}

class RPCTarget(UniTarget):
	def __init__(self, ip, port = 0, protocol = UniProto.CLIENT_TCP, proxies = None, timeout = 10, dns:str=None, dc_ip:str = None, domain:str = None, hostname:str = None, ssl_ctx = None, use_privileged_source_port:bool=False, fragsize = 1048576):
		UniTarget.__init__(self, ip, port, protocol, timeout, hostname = hostname, ssl_ctx= ssl_ctx, proxies = proxies, domain = domain, dc_ip = dc_ip, dns=dns, use_privileged_source_port=use_privileged_source_port)
		self.fragsize = fragsize
	
	def get_rpcprotocol(self):
		if self.protocol in [UniProto.CLIENT_TCP, UniProto.SERVER_TCP, UniProto.CLIENT_SSL_TCP, UniProto.SERVER_SSL_TCP]:
			return ipproto.IPPROTO_TCP.value
		if self.protocol in [UniProto.CLIENT_UDP, UniProto.SERVER_UDP]:
			return ipproto.IPPROTO_UDP.value
		raise Exception('Unknown protocol')

	def get_newtarget(self, ip, port, hostname = None):
		t = copy.deepcopy(self)
		t.ip = ip
		t.port = port
		t.hostname = hostname
		return t

	@staticmethod
	def from_url(connection_url:str):
		url_e = urlparse(connection_url)
		schemes = []
		for item in url_e.scheme.upper().split('+'):
			schemes.append(item.replace('-','_'))

		port = 0
		if url_e.port:
			port = url_e.port
		if port is None:
			raise Exception('Port must be provided!')
		
		path = None
		if url_e.path not in ['/', '', None]:
			path = url_e.path
		
		protocol = UniProto.CLIENT_TCP
		unitarget, extraparams = UniTarget.from_url(connection_url, protocol, port, rpctarget_url_params)
		fragsize = extraparams['fragsize'] if extraparams['fragsize'] is not None else 10*1024

		target = RPCTarget(
			unitarget.ip, 
			port = unitarget.port, 
			protocol = unitarget.protocol, 
			proxies = unitarget.proxies, 
			timeout = unitarget.timeout, 
			dns = unitarget.dns, 
			dc_ip = unitarget.dc_ip, 
			domain = unitarget.domain, 
			hostname = unitarget.hostname,
			ssl_ctx = unitarget.ssl_ctx,
			fragsize = fragsize,
			use_privileged_source_port = unitarget.use_privileged_source_port
		)
		return target