

class RPCException(Exception):
    pass

class RPCReplyException(RPCException):
    pass

class RPCReplyDeniedException(RPCReplyException):
    def __init__(self):
        super().__init__('RPC reply denied without reason provided.')

class RPCCallException(RPCException):
    pass


class RPCCallRejectedException(RPCCallException):
    def __init__(self, reject_code):
        self.code = reject_code
        self.msg = ''
        if(self.code == 1):
            self.msg = 'Remote procedure not exported by server'
        elif(self.code == 2):
            self.msg = 'Remote procedure version mismatch'
        elif(self.code == 3):
            self.msg = 'Remote procedure is not available'
        elif(self.code == 4):
            self.msg = 'Incorrect parameters'
        elif(self.code == 5):
            self.msg = 'System error. (remote)'
        super().__init__('RPC Call rejected. Code: %s, Message: %s' % (reject_code, self.msg))

