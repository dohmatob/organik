
import socket
import select
import sys

class BreakMainLoopException(Exception):
    pass
    
class UdpPacketFactory:
    '''
    Abstract class: Implements a fundamental UDP. 
    Concrete clients 
            - MUST implement the following methods:
              - self.genNextRequest(), which yields  pair ((dst_ip,dst_port),pkt), of remote address and payload pkt, or
                None to signify that there're no more requests to generate
              - self.pktCallback((src_ip,src_port),pkt), a callback which is invoked by the self.getResponse() 
                method to process an incoming response packet
              - handlePkt(srcaddr, pkt), which is called to dispatch and incoming pkt
              - logInfo(msg), logDebug(msg), logWarning(msg)
                
            - MAY (optionally) override the following methods:
              - mustDie(), which should return true iff a special event has been experienced and we must break out of the 
                mainLoop(..).
              - mayGenerateNextRequest(), which should returns true iff we may generate the next request yet. Typically, 
                this method should return false if a we haven't yet placed a verdict on a test packet or the target is 
                down
    '''

    def __init__(self, 
                 sockettimeout=3,
                 selecttimeout=0.003,
                 bindingip='0.0.0.0', # XXX ip to bind-to
                 xternalip=None, # ip to use in requests
                 localport=1,    # local port to bind-to
                 ):
        self._sockettimeout = sockettimeout
        self._selecttimeout = selecttimeout 
        self._bindingip = bindingip
        self._xternalip = xternalip
        self._localport = localport
        self._bound = False
        self._nomorepktstosend = False
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # we do UDP
        self._sock.settimeout(self._sockettimeout)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self._stats = {"nb_sent_pkts":0,"nb_received_pkts":0}

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

    def mustDie(self):
        return False

    def mayGenerateNextRequest(self):
        return True

    def getResponse(self):
        pkt, srcaddr = self._sock.recvfrom(8192) # XXX catch exceptions here!!!
        self._stats["nb_received_pkts"] += 1
        self.handlePkt(srcaddr, pkt)
        
    def sendto(self, pkt, dstaddr):
        try:
            self._sock.sendto(pkt, dstaddr)
            self._stats["nb_sent_pkts"] += 1
        except socket.error:
            self.breakMainLoop()
        
    def breakMainLoop(self, reason=None):
        raise BreakMainLoopException

    def mainLoop(self):
        """
        Main siplet logic be implemented here
        """
        self.bind() # bind to local end-point
        while True:
            try:
                r, w, x = select.select([self._sock], # readfds
                                        [], # writefds
                                        [], # exceptfds
                                        self._selecttimeout,
                                        )
                if r: # we got stuff to read
                    try:
                        self.getResponse()
                    except socket.timeout:
                        continue
                else: # tell'em!
                    if self._nomorepktstosend or not self.mayGenerateNextRequest(): # pack your bags!
                        self.logDebug("making sure no pkts are lost ..")
                        # UDP is --inherently-- asynchronous; there may be delayed pkts on their way, etc.
                        try:
                            while True:
                                self.getResponse()
                        except socket.error:
                            break
                    if self.mayGenerateNextRequest():
                        req = self.genNextRequest()
                        if req is None:
                            self._nomorepktstosend = True
                            continue 
                        dstaddr,reqpkt = req 
                        self.sendto(reqpkt, dstaddr) # send pkt to remote end-point
            except select.error:
                break
            except BreakMainLoopException:
                break
            except KeyboardInterrupt:
                self.logDebug("caught your ^C; quitting ..")
                self.logInfo("PKTS SENT: %d, PKTS RECEIVED: %d"%(self._stats["nb_sent_pkts"],
                                                                 self._stats["nb_received_pkts"]))
                sys.exit(1)
