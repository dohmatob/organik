from SIPutils.packet import makeRequest, parsePkt, SIP_PKT_PATTERNS
# from SIPutils.helper import getRange as getPortRange, ip4range, scanlist as getTargets
import socket
import sys
import select

class SipLet:
    def __init__(self, 
                 sockettimeout=3,
                 selecttimeout=0.03,
                 bindingip='0.0.0.0',
                 xternalip=None,
                 pcallback=None):
        self._sockettimeout = sockettimeout
        self._selecttimeout = selecttimeout 
        self._bindingip = bindingip
        self._xternalip = xternalip
        self._pcallback = pcallback
        self._localport = 5060
        self._bound = False
        self._nomoretoscan = False
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.settimeout(self._sockettimeout)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    def logDebug(self, msg):
        if self._pcallback is not None:
            self._pcallback.logDebug(msg)
        else:
            print '-DEBUG- %s' %msg

    def logInfo(self, msg):
        if self._pcallback is not None:
            self._pcallback.logInfo(msg)
        else:
            print '-INFO- %s' %msg

    def logWarning(self, msg):
        if self._pcallback is not None:
            self._pcallback.logWarning(msg)
        else:
            print '-WARNING- %s' %msg

    def bind(self):
        if self._bound:
            return
        while self._localport < 65535:
            try:
                self._sock.bind(('', self._localport))
                break
            except socket.error:
                self.logWarning("couldn't bind to local address: %s:%s" %(self._bindingip, self._localport))
                self._localport += 1
        assert self._localport < 65535, "couldn't bind to any any local address" 
        self._bound = True
        self.logDebug("bound to local address:%s: %s" %(self._bindingip, self._localport))
        if self._xternalip is None:
            if self._bindingip != '0.0.0.0':
                self._xternalip = self._bindingip
            else:
                self._xternalip = '127.0.0.1'
        self.logDebug("using xternal ip: %s" %(self._xternalip))
        
    def getNextScanItem(self):
        return self._scaniter.next()

    def getResponse(self):
        pkt, srcaddr = self._sock.recvfrom(8192)
        match = SIP_PKT_PATTERNS['reqfirstline'].search(pkt)
        if match is not None:
            if srcaddr == (self._xternalip,self._localport):
                self.logDebug("recv'd our own pkt ..")
            else:
                self.logDebug("recv'd SIP request '%s' from %s:%s" %(match.group(),srcaddr[0],srcaddr[1]))
            return 
        self.pktCallback(srcaddr, pkt)

    def mustDie(self):
        return False

    def mayGenerateNextRequest(self):
        return True

    def mainLoop(self):
        self.bind()
        while True:
            if self.mustDie():
                break
            try:
                r, w, x = select.select([self._sock], [], [], self._selecttimeout)
                if r:
                    if self.mustDie():
                        break
                    try:
                        self.getResponse()
                    except socket.timeout:
                        continue
                else:
                    if self.mustDie():
                        break
                    if self._nomoretoscan or not self.mayGenerateNextRequest():
                        self.logDebug("making sure no pkts are lost ..")
                        try:
                            while True:
                                if self.mustDie():
                                    break
                                self.getResponse()
                        except socket.error:
                            break
                    if self.mayGenerateNextRequest():
                        try:
                            dstaddr, reqpkt = self.genNextRequest()
                        except StopIteration:
                            self._nomoretoscan = True
                            continue
                        self._sock.sendto(reqpkt, dstaddr)
            except select.error:
                break
            except KeyboardInterrupt:
                self.logDebug("caught your ^C; quitting ..")
                sys.exit(1)

        

# if __name__ == "__main__":
#     m = SipLet()
#     m.execute([sys.argv[1]], sys.argv[2])
