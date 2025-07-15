import io
import os

MNTPATHLEN = 1024
MNTNAMLEN = 255
FHSIZE = 32

def read_str(buf:io.BytesIO, encoding:str='utf-8'):
    sl = int.from_bytes(buf.read(4), byteorder='big', signed=False)
    data = buf.read(sl).decode(encoding)
    if sl%4 != 0:
        buf.read(4 - sl%4)
    return data

def pack_str(data:str, encoding:str='utf-8'):
    data = data.encode(encoding)
    padding =  b'' if len(data) % 4 == 0 else b'\x00' * (4 - len(data)%4)
    return len(data).to_bytes(4, byteorder='big', signed=False) + data + padding

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
    
    def to_smbshare(self, hostname_or_ip):
        fullpath = '%s%s' % (hostname_or_ip, self.filesys)
        return NFSSMBShare(name=self.filesys, stype='mount', remark=None, fullpath=fullpath)
    
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
    
    def to_smbshare(self, hostname_or_ip):
        fullpath = '%s%s' % (hostname_or_ip, self.directory)
        return NFSSMBShare(name=self.directory, stype='mount', remark=None, fullpath=fullpath)
    
class NFSSMBShare:
    # only used for scanner results output, do not use for anything else
	def __init__(self, name = None, stype = None, remark = None, fullpath = None):
		self.fullpath = fullpath
		self.unc_path = fullpath
		self.name = name
		self.type = stype
		self.remark = remark
		self.flags = None
		self.capabilities = None
		self.maximal_access = None
		self.tree_id = None
		self.security_descriptor = None
		
		self.files = {}
		self.subdirs = {}