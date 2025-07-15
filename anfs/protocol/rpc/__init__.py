import asyncio
import io
from typing import cast
from asysocks.unicomm.client import UniClient
from anfs.protocol.rpc.packetizer import RPCPacketizer
from anfs.protocol.rpc.common.exceptions import *
from anfs.protocol.rpc.messages import rpc_msg, msg_type, call_body, reply_body,\
	AUTH_NULL, reply_stat, accepted_reply, accept_stat
import traceback

# https://datatracker.ietf.org/doc/html/rfc5531
# https://github.com/CharmingYang0/NfsClient/

class RPC:
	def __init__(self, target, credential = AUTH_NULL()):
		self.target = target
		self.credential = credential
		self.connection = None
		self.__portmap = None
		self.__read_task = None
		self.__current_xid = 10
		self.__xid_table = {}
		if self.credential is None:
			self.credential = AUTH_NULL()

	async def __handle_incoming(self):
		try:
			async for message_data in self.connection.read():		
				message = rpc_msg.from_bytes(message_data)
				if message.msg_type == msg_type.REPLY:
					if message.xid in self.__xid_table:
						x = message.body
						await self.__xid_table[message.xid].put(message.body)
					else:
						print('Received a REPLY message, but no matching xid found. XID: %s' % message.xid)
				else:
					raise Exception('Received a CALL message, expected a REPLY message')
		except Exception as e:
			await self.disconnect()

	def next_xid(self):
		t = self.__current_xid
		self.__current_xid += 1
		if self.__current_xid >= 0xffffffff:
			self.__current_xid = 10
		return t
	
	async def register_xid(self, xid):
		self.__xid_table[xid] = asyncio.Queue()
		return xid, self.__xid_table[xid]
	
	
	async def connect(self, program, version):
		try:
			if self.target.port == 0:
				protocol = self.target.get_rpcprotocol()
				# at this point we don't know the port, we need to query the portmapper
				if program is None or version is None or protocol is None:
					raise Exception('Program or port must be set!')
				from anfs.protocol.portmap import Portmap
				nt = self.target.get_newtarget(self.target.ip, 111)
				self.__portmap = Portmap(nt, self.credential)
				_, err = await self.__portmap.connect()
				if err is not None:
					return False, err
				port, err = await self.__portmap.getport(program, version, protocol)
				await self.__portmap.disconnect()
				if err is not None:
					return False, err
				self.target = self.target.get_newtarget(self.target.ip, port)


			packetizer = RPCPacketizer()
			client = UniClient(self.target, packetizer)
			self.connection = await asyncio.wait_for(client.connect(), timeout=self.target.timeout)
			self.__read_task = asyncio.create_task(self.__handle_incoming())
			return True, None
		except Exception as e:
			return False, e

	async def disconnect(self):
		if self.__read_task is not None:
			self.__read_task.cancel()
			self.__read_task = None
		if self.connection is not None:
			await self.connection.close()
			self.connection = None
	
	async def __send(self, data):
		dsize = len(data)
		total_sent = 0
		data = io.BytesIO(data)
		while total_sent < dsize:
			fragment = data.read(self.target.fragsize)
			rpc_fragment_header = len(fragment)
			if rpc_fragment_header == 0:
				break
			if (rpc_fragment_header + total_sent) == dsize:
				rpc_fragment_header += 0x80000000
			total_sent += rpc_fragment_header
			
			fragment = rpc_fragment_header.to_bytes(4, byteorder='big', signed=False) + fragment
			await self.connection.write(fragment)
	
	async def call(self, program, version, procedure, data, credential = None):
		xid, xid_queue = await self.register_xid(self.next_xid())
		try:
			call = rpc_msg()
			call.xid = xid
			call.msg_type = msg_type.CALL
			call.body = call_body()
			call.body.rpcvers = 2
			call.body.prog = program
			call.body.vers = version
			call.body.proc = procedure
			call.body.cred = self.credential if credential is None else credential
			call.body.verf = AUTH_NULL() # for both auth null and auth sys, the verifier is null
			call.body.data = data
			
			await self.__send(call.to_bytes())
			reply = await xid_queue.get()
			reply = cast(reply_body, reply)
			if reply.reply_stat != reply_stat.MSG_ACCEPTED:
				raise RPCReplyDeniedException()
			
			areply = cast(accepted_reply, reply.reply)

			if areply.stat != accept_stat.SUCCESS:
				raise RPCCallRejectedException(areply.stat.value)
			
			return areply.results, None
		except Exception as e:
			traceback.print_exc()
			return None, e
		finally:
			del self.__xid_table[xid]