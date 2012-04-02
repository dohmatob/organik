from SIPutils.packet import makeRequest, parsePkt, SIP_PKT_PATTERNS
import socket
import sys
import select

class SipLet:
    """
    Abstract class: implements a fundamental UA for a SIP scanner. 
    Concrete scanners 
            - MUST implement the following methods:
              - self.genNextRequest(), which yields  pair ((dst_ip,dst_port),pkt), of remote address and payload pkt.
              - self.pktCallback((src_ip,src_port),pkt), a callback which is invoked by the self.getResponse() 
                method to process an incoming response packet
                
            - MAY (optionally) override the following methods:
              - mustDie(), which should return true iff the present scan must end. For example, for a password cracker, 
                this method should return true in any of the following cases:
                - the sought-for password has been cracked 
                - the (target) extension does not exist
                - the REGISTRAR has answered with an unknown response
                - etc.
              - mayGenerateNextRequest(), which should returns true iff we may generate the next request yet. Typically, 
                this method should return false if a we haven't yet placed a verdict on a test packet or the target is down

            N.B.:- The above methods can't be generic as they strongly depend on the kind of business the specific 
                   scanner is into (UAS discovery, extension enumeration, credentials cracking, etc.)

            Examples of concrete scanners: see the plugin_SIP_mapper/warrior/cracker plugins

    """
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
        """
        Sets local end-point
        """
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
        
    def getResponse(self):
        pkt, srcaddr = self._sock.recvfrom(8192)
        match = SIP_PKT_PATTERNS['reqfirstline'].search(pkt) # scrape first line of pkt
        if match is not None: # strange; somebody is requesting from us !
            if srcaddr == (self._xternalip,self._localport): # we sent this, didn't we ?
                self.logDebug("recv'd our own pkt ..")
            else: # strange !
                self.logDebug("recv'd SIP request '%s' from %s:%s" %(match.group(),srcaddr[0],srcaddr[1]))
            return 
        self.pktCallback(srcaddr, pkt) # invoke appropriate handle

    def mustDie(self):
        """
        End this scan immediately!?
        """
        return False # by default, nothx is redhibitory!

    def mayGenerateNextRequest(self):
        """
        Generate next request alread?
        """
        return True # by default, generate pkts as opportunity presents

    def mainLoop(self):
        """
        Main siplet logic be implemented here
        """
        self.bind() # set local end-point
        while True:
            if self.mustDie():
                break 
            try:
                r, w, x = select.select([self._sock], # readfds
                                        [], # writefds
                                        [], # exceptfds
                                        self._selecttimeout,
                                        )
                if r: # we got stuff to read
                    if self.mustDie():
                        break 
                    try:
                        self.getResponse()
                    except socket.timeout:
                        continue
                else: # tell'em!
                    if self.mustDie():
                        break
                    if self._nomoretoscan or not self.mayGenerateNextRequest(): # pack your backs!
                        self.logDebug("making sure no pkts are lost ..")
                        # UDP is asynchronous; there may be delaied pkts, etc.
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
                        self._sock.sendto(reqpkt, dstaddr) # send pkt to remote end-point
            except select.error:
                break
            except KeyboardInterrupt:
                self.logDebug("caught your ^C; quitting ..")
                sys.exit(1)

        

# if __name__ == "__main__":
#     m = SipLet()
#     m.execute([sys.argv[1]], sys.argv[2])
