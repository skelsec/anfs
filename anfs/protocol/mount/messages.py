import io
import os

MNTPATHLEN = 1024
MNTNAMLEN = 255
FHSIZE = 32

# mountstat3 (RFC1813)
MNT3_OK = 0
MNT3ERR_PERM = 1
MNT3ERR_NOENT = 2
MNT3ERR_IO = 5
MNT3ERR_ACCES = 13
MNT3ERR_NOTDIR = 20
MNT3ERR_INVAL = 22
MNT3ERR_NAMETOOLONG = 63
MNT3ERR_NOTSUPP = 10004
MNT3ERR_SERVERFAULT = 10006

MOUNTSTAT3 = {
    0: 'MNT3_OK',
    1: 'MNT3ERR_PERM',
    2: 'MNT3ERR_NOENT',
    5: 'MNT3ERR_IO',
    13: 'MNT3ERR_ACCES',
    20: 'MNT3ERR_NOTDIR',
    22: 'MNT3ERR_INVAL',
    63: 'MNT3ERR_NAMETOOLONG',
    10004: 'MNT3ERR_NOTSUPP',
    10006: 'MNT3ERR_SERVERFAULT',
}

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

class mountres3:
    # XDR definition (RFC1813):
    # union mountres3 switch (mountstat3 fhs_status) {
    #     case MNT3_OK:
    #         mountres3_ok mountinfo;  // fhandle3 fhandle; int auth_flavors<>;
    #     default:
    #         void;
    # };
    def __init__(self):
        self.status = None
        self.fhandle = None
        self.auth_flavors = []

    @staticmethod
    def from_bytes(data: bytes):
        return mountres3.from_buffer(io.BytesIO(data))

    @staticmethod
    def from_buffer(buff: io.BytesIO):
        result = mountres3()
        result.status = int.from_bytes(buff.read(4), byteorder='big', signed=False)
        if result.status == MNT3_OK:
            fhlen = int.from_bytes(buff.read(4), byteorder='big', signed=False)
            result.fhandle = buff.read(fhlen)
            count = int.from_bytes(buff.read(4), byteorder='big', signed=False)
            for _ in range(count):
                result.auth_flavors.append(int.from_bytes(buff.read(4), byteorder='big', signed=False))
        return result

    def __str__(self):
        return 'mountres3(status=%s, fhandle=%s, auth_flavors=%s)' % (
            MOUNTSTAT3.get(self.status, self.status), self.fhandle, self.auth_flavors)

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