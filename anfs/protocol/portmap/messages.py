import io
import enum
from anfs.protocol.portmap.wellknown import wellknown_programs

class ipproto(enum.Enum):
    IPPROTO_TCP = 6
    IPPROTO_UDP = 17

class mapping:
    def __init__(self):
        self.program = None
        self.version = None
        self.protocol = None
        self.port = None
        self.name = None
    
    @staticmethod
    def from_bytes(data: bytes):
        return mapping.from_buffer(io.BytesIO(data))
    
    @staticmethod
    def from_buffer(buff: io.BytesIO):
        result = mapping()
        result.program = int.from_bytes(buff.read(4), byteorder='big', signed=False)
        result.version = int.from_bytes(buff.read(4), byteorder='big', signed=False)
        result.protocol = int.from_bytes(buff.read(4), byteorder='big', signed=False)
        result.port = int.from_bytes(buff.read(4), byteorder='big', signed=False)
        if result.program in wellknown_programs:
            result.name = wellknown_programs[result.program]
        return result
    
    def to_bytes(self):
        result = self.program.to_bytes(4, byteorder='big', signed=False)
        result += self.version.to_bytes(4, byteorder='big', signed=False)
        result += self.protocol.to_bytes(4, byteorder='big', signed=False)
        result += self.port.to_bytes(4, byteorder='big', signed=False)
        return result
    
    def __str__(self):
        return 'Program: %s, Version: %s, Protocol: %s, Port: %s, Name: %s' % (self.program, self.version, ipproto(self.protocol).name, self.port, self.name)

class call_args:
    def __init__(self):
        self.program = None
        self.version = None
        self.procedure = None
        self.data = None
    
    @staticmethod
    def from_bytes(data: bytes):
        return call_args.from_buffer(io.BytesIO(data))
    
    @staticmethod
    def from_buffer(buff: io.BytesIO):
        result = call_args()
        result.program = int.from_bytes(buff.read(4), byteorder='big', signed=False)
        result.version = int.from_bytes(buff.read(4), byteorder='big', signed=False)
        result.procedure = int.from_bytes(buff.read(4), byteorder='big', signed=False)
        
        result.data = buff.read()
        return result
    
    def to_bytes(self):
        result = self.program.to_bytes(4, byteorder='big', signed=False)
        result += self.version.to_bytes(4, byteorder='big', signed=False)
        result += self.procedure.to_bytes(4, byteorder='big', signed=False)
        result += self.data
        return result

class call_result:
    def __init__(self):
        self.port = None
        self.data = None
    
    @staticmethod
    def from_bytes(data: bytes):
        return call_result.from_buffer(io.BytesIO(data))
    
    @staticmethod
    def from_buffer(buff: io.BytesIO):
        result = call_result()
        result.port = int.from_bytes(buff.read(4), byteorder='big', signed=False)
        result.data = buff.read()
        return result
    
    def to_bytes(self):
        result = self.port.to_bytes(4, byteorder='big', signed=False)
        result += self.data
        return result