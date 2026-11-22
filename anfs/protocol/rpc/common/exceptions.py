

class RPCException(Exception):
    pass

class RPCReplyException(RPCException):
    pass

class RPCConnectionClosedException(RPCException):
    def __init__(self, msg='RPC connection closed before a reply was received.'):
        super().__init__(msg)

class RPCTimeoutException(RPCException):
    def __init__(self, msg='Timed out waiting for an RPC reply.'):
        super().__init__(msg)

class RPCProgramNotRegisteredException(RPCException):
    def __init__(self, program, version):
        self.program = program
        self.version = version
        super().__init__('Program %s version %s is not registered with the portmapper for this transport.' % (program, version))

class RPCReplyDeniedException(RPCReplyException):
    def __init__(self, reply = None):
        # reply is the rejected_reply sent by the server
        self.reply = reply
        self.reject_stat = None
        self.auth_stat = None
        self.mismatch_info = None
        msg = 'RPC reply denied without reason provided.'
        if reply is not None:
            self.reject_stat = reply.stat
            self.auth_stat = reply.auth_stat
            self.mismatch_info = reply.mismatch_info
            if reply.auth_stat is not None:
                msg = 'RPC reply denied. Authentication error: %s' % reply.auth_stat.name
            elif reply.mismatch_info is not None:
                msg = 'RPC reply denied. RPC version mismatch, server supports versions %s - %s' % (reply.mismatch_info.low, reply.mismatch_info.high)
        super().__init__(msg)

class RPCCallException(RPCException):
    pass


class RPCCallRejectedException(RPCCallException):
    def __init__(self, reject_code, mismatch_info = None):
        self.code = reject_code
        self.mismatch_info = mismatch_info
        self.msg = ''
        if(self.code == 1):
            self.msg = 'Remote procedure not exported by server'
        elif(self.code == 2):
            self.msg = 'Remote procedure version mismatch'
            if mismatch_info is not None:
                self.msg += ', server supports versions %s - %s' % (mismatch_info.low, mismatch_info.high)
        elif(self.code == 3):
            self.msg = 'Remote procedure is not available'
        elif(self.code == 4):
            self.msg = 'Incorrect parameters'
        elif(self.code == 5):
            self.msg = 'System error. (remote)'
        super().__init__('RPC Call rejected. Code: %s, Message: %s' % (reject_code, self.msg))

