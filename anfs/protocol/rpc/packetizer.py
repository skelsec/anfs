import struct

from asysocks.unicomm.common.packetizers import Packetizer

# https://datatracker.ietf.org/doc/html/rfc1831

class RPCPacketizer(Packetizer):
	def __init__(self):
		Packetizer.__init__(self, 65535)
		self.in_buffer = b''
		self.__in_fragment = False
		self.fragments = []
	
	def process_buffer(self):
		preread = 4
		remaining_length = -1
		while True:
			if len(self.in_buffer) < preread:
				break
			lb = self.in_buffer[:preread]
			remaining_length = struct.unpack('!L', lb)[0]
			self.__in_fragment = not bool(remaining_length & 0x80000000)
			remaining_length &= 0x7fffffff
			if len(self.in_buffer) >= remaining_length+preread:
				data = self.in_buffer[4:remaining_length+preread]
				self.fragments.append(data)
				self.in_buffer = self.in_buffer[remaining_length+preread:]
				if not self.__in_fragment:
					yield b''.join(self.fragments)
					self.fragments = []
				continue
			break
		

	async def data_out(self, data):
		yield data

	async def data_in(self, data):
		if data is None:
			yield data
		self.in_buffer += data
		for packet in self.process_buffer():
			yield packet