import io
import os

MNTPATHLEN = 1024
MNTNAMLEN = 255
FHSIZE = 32

def read_str(buf):
    sl = int.from_bytes(buf.read(4), byteorder='big', signed=False)
    return buf.read(sl).decode('utf-8')

class export:
    def __init__(self):
        self.filesys = None
        self.groups = []
    
    @staticmethod
    def from_bytes(data: bytes):
        return export.from_buffer(io.BytesIO(data))

    @staticmethod
    def from_buffer(buff: io.BytesIO):
        result = export()
        result.filesys = read_str(buff)
        while buff.read(4) != b'\x00\x00\x00\x00':
            groupname = read_str(buff)
            result.groups.append(groupname)
            
        return result
    
    def __str__(self):
        return 'Filesystem: %s, Groups: %s' % (self.filesys, self.groups)
    
class fhstatus:
    def __init__(self):
        self.status = None
        self.fhandle = None
    
    @staticmethod
    def from_bytes(data: bytes):
        return fhstatus.from_buffer(io.BytesIO(data))

    @staticmethod
    def from_buffer(buff: io.BytesIO):
        result = fhstatus()
        result.status = int.from_bytes(buff.read(4), byteorder='big', signed=False)
        if result.status == 0:
            hszie = int.from_bytes(buff.read(4), byteorder='big', signed=False)
            result.fhandle = buff.read(hszie)
        else:
            raise Exception('fhstatus error: %s' % os.strerror(result.status))
        return result
    
    def __str__(self):
        return 'Status: %s' % self.status

class mountpoint:
    def __init__(self):
        self.hostname = None
        self.directory = None
    
    @staticmethod
    def from_bytes(data: bytes):
        return mountpoint.from_buffer(io.BytesIO(data))

    @staticmethod
    def from_buffer(buff: io.BytesIO):
        result = mountpoint()
        result.hostname = read_str(buff)
        result.directory = read_str(buff)
        return result
    
    def __str__(self):
        return 'Hostname: %s, Directory: %s' % (self.hostname, self.directory)