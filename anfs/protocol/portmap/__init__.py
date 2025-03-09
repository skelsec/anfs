from anfs.protocol.rpc import RPC
from anfs.protocol.portmap.messages import mapping, call_args, call_result
import traceback
import struct
import io
import datetime


# https://www.rfc-editor.org/rfc/rfc1833.html
# TODO: Implement the rest of the portmap protocol, as many functions missing

class Portmap:
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
        return await self.rpc.connect(100000, 4)
    
    async def disconnect(self):
        if self.rpc is not None:
            return await self.rpc.disconnect()
    
    async def dump(self):
        """Fetches all the portmap entries from the server"""
        try:
            data = struct.pack('!LL', 2, 4)
            pm_entries = []
            pm_entries_buff, err = await self.rpc.call(100000, 2, 4, data)
            if err is not None:
                raise err
            if len(pm_entries_buff) < 4:
                return pm_entries
            
            pm_entries_buff = io.BytesIO(pm_entries_buff)
            while pm_entries_buff.read(4) == b'\x00\x00\x00\x01':
                pm_entries.append(mapping.from_buffer(pm_entries_buff))
            return pm_entries, None
        except Exception as e:
            return None, e

    async def getport(self, program, version, protocol):
        """Fetches the port for a specific program and version"""
        try:
            data = mapping()
            data.program = program
            data.version = version
            data.protocol = protocol
            data.port = 0
            data = data.to_bytes()
            
            port_buff, err = await self.rpc.call(100000, 2, 3, data)
            if err is not None:
                raise err
            if len(port_buff) < 4:
                return None
            return int.from_bytes(port_buff, byteorder='big', signed=False), None
        except Exception as e:
            return None, e
    
    async def null(self):
        """Null call"""
        return await self.rpc.call(100000, 2, 0, b'')
    
    async def callit(self, program, version, procedure, data):
        """Call a specific procedure on a program"""
        try:
            req = call_args()
            req.program = program
            req.version = version
            req.procedure = procedure
            req.data = data
            req = req.to_bytes()
            
            rep, err =  await self.rpc.call(100000, 2, 5, req)
            if err is not None:
                raise err
            return call_result.from_bytes(rep), None
        except Exception as e:
            return None, e
    
    async def gettime(self):
        """Get the server time"""
        try:
            tdata, err = await self.rpc.call(100000, 4, 6, b'')
            if err is not None:
                raise err
            curtime = datetime.datetime.fromtimestamp(int.from_bytes(tdata, byteorder='big', signed=False))
            return curtime, None
        except Exception as e:
            return None, e
        
    async def get_target_for_porgram(self, basetarget, program, version, protocol):
        try:
            port = await self.getport(program, version, protocol)
            return basetarget.get_newport(port), None
        except Exception as e:
            return None, e

        

async def amain():
    from anfs.protocol.rpc.common.target import RPCTarget

    ip = '192.168.30.10'
    target = RPCTarget(ip, port = 111)
    portmap = Portmap(target)
    try:
        _, err = await portmap.connect()
        if err is not None:
            raise err
        pm, err = await portmap.dump()
        for p in pm:
            print(str(p))
        #port = await portmap.getport(100000, 2, 6)
        #print(port)
        #curtime = await portmap.gettime()
        #print(curtime)
    except Exception as e:
        traceback.print_exc()
def main():
    import asyncio
    asyncio.run(amain())

if __name__ == '__main__':
    main()