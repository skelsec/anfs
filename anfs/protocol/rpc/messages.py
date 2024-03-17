import io
import enum
import time

# https://datatracker.ietf.org/doc/html/rfc4506

class auth_flavor(enum.Enum):
    AUTH_NONE       = 0
    AUTH_SYS        = 1
    AUTH_SHORT      = 2
    AUTH_DH         = 3
    AUTH_KERB       = 4 #/* kerberos auth, see RFC 2695 */
    AUTH_RSA        = 5 #/* RSA authentication */
    RPCSEC_GSS      = 6 #/* GSS-based RPC security for auth, integrity and privacy, RPC 5403 */

    AUTH_NW         = 30001           #NETWARE
    AUTH_SEC        = 200000          #TSIG NFS subcommittee
    AUTH_ESV        = 200004          #SVr4 ES

    AUTH_NQNFS      = 300000          #Univ. of Guelph - Not Quite NFS
    AUTH_GSSAPI     = 300001          #OpenVision <john.linn@ov.com>
    AUTH_ILU_UGEN   = 300002          #Xerox <janssen@parc.xerox.com> ILU Unsecured Generic Identity
    AUTH_SPNEGO     = 390000
                   #390000 - 390255 NFS 'pseudo' flavors for RPCSEC_GSS
                   #390003 - kerberos_v5 authentication, RFC 2623
                   #390004 - kerberos_v5 with data integrity, RFC 2623
                   #390005 - kerberos_v5 with data privacy, RFC 2623

    Reserved        = 200000000
    NEXT_INC        = 200100000

class opaque_auth:
    def __init__(self):
        self.flavor = None
        self.body = None
    
    @staticmethod
    def from_bytes(data: bytes):
        return opaque_auth.from_buffer(io.BytesIO(data))

    @staticmethod
    def from_buffer(buff: io.BytesIO):
        result = opaque_auth()
        result.flavor = auth_flavor(int.from_bytes(buff.read(4), byteorder='big', signed=False))
        bodylen = int.from_bytes(buff.read(4), byteorder='big', signed=False)
        result.body = buff.read(bodylen)
        return result
    
    def to_bytes(self):
        result = self.flavor.value.to_bytes(4, byteorder='big', signed=False)
        result += len(self.body).to_bytes(4, byteorder='big', signed=False)
        result += self.body
        return result
    

class msg_type(enum.Enum):
    CALL  = 0
    REPLY = 1

class reply_stat(enum.Enum):
    MSG_ACCEPTED = 0
    MSG_DENIED   = 1

class accept_stat(enum.Enum):
    SUCCESS      = 0
    PROG_UNAVAIL = 1
    PROG_MISMATCH= 2
    PROC_UNAVAIL = 3
    GARBAGE_ARGS = 4
    SYSTEM_ERR   = 5

class reject_stat(enum.Enum):
    RPC_MISMATCH = 0
    AUTH_ERROR   = 1

class auth_stat(enum.Enum):
    AUTH_OK      = 0
    AUTH_BADCRED      = 1,  #/* bad credential (seal broken)   */
    AUTH_REJECTEDCRED = 2,  #/* client must begin new session  */
    AUTH_BADVERF      = 3,  #/* bad verifier (seal broken)     */
    AUTH_REJECTEDVERF = 4,  #/* verifier expired or replayed   */
    AUTH_TOOWEAK      = 5,  #/* rejected for security reasons  */
    #* failed locally*/
    AUTH_INVALIDRESP  = 6,  #/* bogus response verifier        */
    AUTH_FAILED       = 7,  #/* reason unknown                 */
    #/* AUTH_KERB errors; deprecated.  See [RFC2695] */
    AUTH_KERB_GENERIC = 8,  #/* kerberos generic error */
    AUTH_TIMEEXPIRE = 9,    #/* time of credential expired */
    AUTH_TKT_FILE = 10,     #/* problem with ticket file */
    AUTH_DECODE = 11,       #/* can't decode authenticator */
    AUTH_NET_ADDR = 12,     #/* wrong net address in ticket */
    #/* RPCSEC_GSS GSS related errors*/
    RPCSEC_GSS_CREDPROBLEM = 13, #/* no credentials for user */
    RPCSEC_GSS_CTXPROBLEM = 14   #/* problem with context */

class rpc_msg:
    def __init__(self):
        self.xid = None
        self.msg_type = None
        self.body = None
    
    @staticmethod
    def from_bytes(data: bytes):
        return rpc_msg.from_buffer(io.BytesIO(data))

    @staticmethod
    def from_buffer(buff: io.BytesIO):
        result = rpc_msg()
        result.xid = int.from_bytes(buff.read(4), byteorder='big', signed=False)
        result.msg_type = msg_type(int.from_bytes(buff.read(4), byteorder='big', signed=False))
        if result.msg_type == msg_type.CALL:
            result.body = call_body.from_buffer(buff)
        else:
            result.body = reply_body.from_buffer(buff)
        return result
    
    def to_bytes(self):
        result = self.xid.to_bytes(4, byteorder='big', signed=False)
        result += self.msg_type.value.to_bytes(4, byteorder='big', signed=False)
        result += self.body.to_bytes()
        return result

class call_body:
    def __init__(self):
        self.rpcvers = 2
        self.prog = None
        self.vers = None
        self.proc = None
        self.cred = None
        self.verf = None
        self.data = None
    
    @staticmethod
    def from_bytes(data: bytes):
        return call_body.from_buffer(io.BytesIO(data))

    @staticmethod
    def from_buffer(buff: io.BytesIO):
        result = call_body()
        result.rpcvers = int.from_bytes(buff.read(4), byteorder='big', signed=False)
        result.prog = int.from_bytes(buff.read(4), byteorder='big', signed=False)
        result.vers = int.from_bytes(buff.read(4), byteorder='big', signed=False)
        result.proc = int.from_bytes(buff.read(4), byteorder='big', signed=False)
        result.cred = opaque_auth.from_buffer(buff)
        result.verf = opaque_auth.from_buffer(buff)
        result.data = buff.read()
        return result
    
    def to_bytes(self):
        result = self.rpcvers.to_bytes(4, byteorder='big', signed=False)
        result += self.prog.to_bytes(4, byteorder='big', signed=False)
        result += self.vers.to_bytes(4, byteorder='big', signed=False)
        result += self.proc.to_bytes(4, byteorder='big', signed=False)
        result += self.cred.to_bytes()
        result += self.verf.to_bytes()
        result += self.data
        return result

class reply_body:
    def __init__(self):
        self.reply_stat = None
        self.reply = None
    
    @staticmethod
    def from_bytes(data: bytes):
        return reply_body.from_buffer(io.BytesIO(data))

    @staticmethod
    def from_buffer(buff: io.BytesIO):
        result = reply_body()
        result.reply_stat = reply_stat(int.from_bytes(buff.read(4), byteorder='big', signed=False))
        if result.reply_stat == reply_stat.MSG_ACCEPTED:
            result.reply = accepted_reply.from_buffer(buff)
        else:
            result.reply = rejected_reply.from_buffer(buff)
        return result
    
    def to_bytes(self):
        result = self.reply_stat.to_bytes(4, byteorder='big', signed=False)
        result += self.reply.to_bytes()
        return result

class accepted_reply:
    def __init__(self):
        self.verf = None
        self.stat = None
        self.mismatch_info = None
        self.results = None

    @staticmethod
    def from_bytes(data: bytes):
        return accepted_reply.from_buffer(io.BytesIO(data))

    @staticmethod
    def from_buffer(buff: io.BytesIO):
        result = accepted_reply()
        result.verf = opaque_auth.from_buffer(buff)
        result.stat = accept_stat(int.from_bytes(buff.read(4), byteorder='big', signed=False))
        if result.stat == accept_stat.SUCCESS:
            result.results = buff.read()
        elif result.stat == accept_stat.PROG_MISMATCH:
            result.mismatch_info = mismatch_info.from_buffer(buff)
        return result
    
    def to_bytes(self):
        result = self.verf.to_bytes()
        result += self.stat.to_bytes(4, byteorder='big', signed=False)
        if self.stat == accept_stat.SUCCESS:
            result += self.results
        elif self.stat == accept_stat.PROG_MISMATCH:
            result += self.mismatch_info.to_bytes()
        return result

class rejected_reply:
    def __init__(self):
        self.stat = None
        self.mismatch_info = None
    
    @staticmethod
    def from_bytes(data: bytes):
        return rejected_reply.from_buffer(io.BytesIO(data))

    @staticmethod
    def from_buffer(buff: io.BytesIO):
        result = rejected_reply()
        result.stat = reject_stat(int.from_bytes(buff.read(4), byteorder='big', signed=False))
        if result.stat == reject_stat.RPC_MISMATCH:
            result.mismatch_info = mismatch_info.from_buffer(buff)
        return result
    
    def to_bytes(self):
        result = self.stat.to_bytes(4, byteorder='big', signed=False)
        if self.stat == reject_stat.RPC_MISMATCH:
            result += self.mismatch_info.to_bytes()
        return result

class mismatch_info:
    def __init__(self):
        self.low = None
        self.high = None
    
    @staticmethod
    def from_bytes(data: bytes):
        return mismatch_info.from_buffer(io.BytesIO(data))

    @staticmethod
    def from_buffer(buff: io.BytesIO):
        result = mismatch_info()
        result.low = int.from_bytes(buff.read(4), byteorder='big', signed=False)
        result.high = int.from_bytes(buff.read(4), byteorder='big', signed=False)
        return result
    
    def to_bytes(self):
        result = self.low.to_bytes(4, byteorder='big', signed=False)
        result += self.high.to_bytes(4, byteorder='big', signed=False)
        return result

class authsys_params:
    def __init__(self, stamp = None, machinename = None, uid = None, gid = None, gids = None):
        self.stamp = stamp
        self.machinename = machinename
        self.uid = uid
        self.gid = gid
        self.gids = gids

        if self.stamp is None:
            self.stamp = int(time.time()) & 0xffff
        if self.machinename is None:
            self.machinename = 'anfs'
        if self.uid is None:
            self.uid = 0
        if self.gid is None:
            self.gid = 0
        if self.gids is None:
            self.gids = [0]
    
    @staticmethod
    def from_bytes(data: bytes):
        return authsys_params.from_buffer(io.BytesIO(data))

    @staticmethod
    def from_buffer(buff: io.BytesIO):
        result = authsys_params()
        result.stamp = int.from_bytes(buff.read(4), byteorder='big', signed=False)
        result.machinename = buff.read(255)
        result.uid = int.from_bytes(buff.read(4), byteorder='big', signed=False)
        result.gid = int.from_bytes(buff.read(4), byteorder='big', signed=False)
        result.gids = buff.read(16*4)
        return result
    
    def to_bytes(self):
        result = self.stamp.to_bytes(4, byteorder='big', signed=False)
        mn = self.machinename.encode('utf-8')
        result += len(mn).to_bytes(4, byteorder='big', signed=False)
        result += mn
        result += b'\x00'*((4-len(mn) % 4) % 4)
        result += self.uid.to_bytes(4, byteorder='big', signed=False)
        result += self.gid.to_bytes(4, byteorder='big', signed=False)
        if len(self.gids) == 1 and self.gids[0] == 0:
            result += b'\x00\x00\x00\x00'
        else:
            result += len(self.gids).to_bytes(4, byteorder='big', signed=False)
            for gid in self.gids:
                result += gid.to_bytes(4, byteorder='big', signed=False)
        return result
    
class AUTH_NULL(opaque_auth):
    def __init__(self):
        super().__init__()
        self.flavor = auth_flavor.AUTH_NONE
        self.body = b''

class AUTH_SYS(opaque_auth):
    def __init__(self, stamp = None, machinename = None, uid = None, gid = None, gids = None):
        super().__init__()
        params = authsys_params(stamp = stamp, machinename = machinename, uid = uid, gid = gid, gids = gids)
        self.flavor = auth_flavor.AUTH_SYS
        self.body = params.to_bytes()