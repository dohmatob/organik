#!/usr/bin/env python
from argparse import ArgumentParser
from libsip.siplet import SipLet
from libsip.helper import getRange as getPortRange, ip4range, scanlist as getTargetList
from core import targets

def targetrule(target):
    return target.getCategory() == "TARGET_IPRANGE"


class SipMapper(SipLet):
    def treated(self, addr):
        return addr in self._donetargets

    def callback(self, srcaddr, meta):
        self.logInfo("SIP (UDP) server '%s' at %s:%s" %(meta['headers']['User-Agent'],srcaddr[0],srcaddr[1]))
        if self._pcallback:
            self._pcallback.announceNewTarget(targets.TARGET_SIP_SERVICE(ip=srcaddr[0], 
                                                                         port=srcaddr[1], 
                                                                         useragent=meta['headers']['User-Agent'],))
            if not srcaddr[0] in [target[0] for target in self._donetargets]:
                self._pcallback.announceNewTarget(targets.TARGET_IP(ip=srcaddr[0],))
        
    def genNewRequest(self):
        next = self.getNextScanItem()
        if not next is None:
            ip,port,method = next
            return (ip,port), self.makeRequest((ip,port), method=method)
        
    def execute(self, target, portrange="5060-5070", methods=["OPTIONS"]):
        """
        Scan
        """
        self._scaniter = getTargetList(ip4range(*target), getPortRange(portrange), methods)
        self.mainLoop()

        
def run(target, pcallback):
    sipmapper = SipMapper(pcallback=pcallback)
    raw_target = target.get('iprange')
    if not type(raw_target) is list:
        raw_target = [raw_target]
    sipmapper.execute(raw_target)


if __name__ == '__main__':
    parser = ArgumentParser(version='w0rkz 0f d0hm4t06 3. d0p91m4')
    parser.add_argument('--target', '-t',
                   action='append',
                   dest='target',
                   default=list(),
                   help="""specify a target ip/iprange""",
                   )
    parser.add_argument('--portrange', '-p',
                   action='append',
                   dest='portrange',
                   default=list(),
                   help="""specify target port/portrange""",
                   )
    options = parser.parse_args()
    sip = SipMapper()
    sip.execute(options.target, ",".join(options.portrange))
