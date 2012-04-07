from SIPutils.packet import SIP_PKT_PATTERNS
from packets.udp_packet_factory import UdpPacketFactory

class SipLet(UdpPacketFactory):
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
                 localport=5060,
                 pcallback=None):
        UdpPacketFactory.__init__(self, 
                                  sockettimeout=sockettimeout, 
                                  selecttimeout=selecttimeout, 
                                  bindingip=bindingip, 
                                  xternalip=xternalip, 
                                  localport=localport,
                                  )
        self._pcallback = pcallback

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
        
    def handlePkt(self, srcaddr, pkt):
        match = SIP_PKT_PATTERNS['reqfirstline'].search(pkt) # scrape first line of pkt
        if match is not None: # strange; somebody is requesting from us !
            if srcaddr == (self._xternalip,self._localport): # we sent this, didn't we ?
                self.logDebug("recv'd our own pkt ..")
            else: # strange !
                self.logDebug("recv'd SIP request '%s' from %s:%s" %(match.group(),srcaddr[0],srcaddr[1]))
            return 
        self.pktCallback(srcaddr, pkt) # invoke appropriate handle

# if __name__ == "__main__":
#     m = SipLet()
#     m.execute([sys.argv[1]], sys.argv[2])
