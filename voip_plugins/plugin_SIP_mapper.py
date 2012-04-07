
#!/usr/bin/env python
from argparse import ArgumentParser
from SIPutils.packet import makeRequest, parsePkt
from SIPutils.siplet import SipLet
from SIPutils.helper import getRange as getPortRange, ip4range, scanlist as getTargetList
from coreutils import targets

def targetrule(target):
    return target.getCategory() == "TARGET_IPRANGE"


class SipMapper(SipLet):
    def treated(self, addr):
        return addr in self._donesrcaddrs

    def pktCallback(self, srcaddr, pkt):
        """
        FOOD IS SERVED \L/
        """
        if self.treated(srcaddr):
            return
        self._donesrcaddrs.append(srcaddr)
        
        metadata = parsePkt(pkt)
        if metadata is None:
            return
        
        self.logInfo("SIP (UDP) server '%s' at %s:%s" %(metadata['headers']['User-Agent'],srcaddr[0],srcaddr[1]))
        if self._pcallback:
            self._pcallback.announceNewTarget(targets.TARGET_SIP_SERVICE(ip=srcaddr[0], 
                                                                         port=srcaddr[1], 
                                                                         ua=metadata['headers']['User-Agent'],))
            if not srcaddr[0] in [target[0] for target in self._donesrcaddrs]:
                self._pcallback.announceNewTarget(targets.TARGET_IP(ip=srcaddr[0],))
        
    def genNextRequest(self):
        try:
            ip, port, method = self._scaniter.next()
        except StopIteration:
            return None
        reqpkt = makeRequest(method,
                             ip,
                             port,
                             self._xternalip,
                             self._localport,
                             )
        return (ip,port), reqpkt
        
    def execute(self, target, portrange="5060-5070",):
        """
        Scan
        """
        if type(target) is str:
            target = target.split(',')
        self._scaniter = getTargetList(ip4range(*target), getPortRange(portrange), ["OPTIONS",])
        self._donesrcaddrs = []
        self.mainLoop()
        if not self._donesrcaddrs:
            self.logDebug("Nothing found")
  
def run(target, pcallback):
    sipmapper = SipMapper(pcallback=pcallback)
    sipmapper.execute(target.get('iprange'))


if __name__ == '__main__':
    parser = ArgumentParser(version='w0rkz 0f d0hm4t06 3. d0p91m4')
    parser.add_argument('--target', '-t',
                   action='store',
                   dest='target',
                   default="",
                   help="""specify a target ip/iprange (you may specify a comma-seperated list like localhost,scanme.org,trixbox)""",
                   )
    parser.add_argument('--portrange', '-p',
                   action='store',
                   dest='portrange',
                   default='5060',
                   help="""specify target port/portrange (you may specify a comma-seperated list like 5060,5070-5090""",
                   )
    options = parser.parse_args()
    sip = SipMapper()
    sip.execute(options.target, options.portrange)
