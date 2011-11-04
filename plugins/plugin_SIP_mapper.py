import socket
import sys
import select
import time
import random
import traceback
import re
from sipcontrib.helper import makeRequest, scanlist, ip4range, getRange as getPortRange, createTag, mysendto
import errno
from core import targets

DESCRIPTION="""Plugin for SIP (UDP) discovery"""
AUTHOR="""d0hm4t06 3. d0p91m4"""
AUTHOR_EMAIL="""gmdopp@gmail.com"""

def targetrule(target):
    """
    Run this plugin on targets in the "TARGET_IPRANGE" category
    """
    return target.getCategory() == "TARGET_IPRANGE"


class SIPProbe:
    """
    Scan SIP (UDP) -enabled devices
    """
    _CHUNK_SIZE = 8192
    # SIP pkt regexp black-magik \L/
    """
    A SIP pkt looks as follows:
    SIP/2.0 404 Not found
    Via: SIP/2.0/UDP 512472208890754321164178:5060;branch=z9hG4bK-2486524293;received=192.168.46.1;rport=5061
    From: sip:ping@1.1.1.1
    To: sip:pong@1.1.1.1;tag=as66e097b0
    Call-ID: 127.0.0.1
    CSeq: 1 REGISTER
    User-Agent: Asterisk PBX 1.6.0.26-FONCORE-r78
    Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO
    Supported: replaces, timer
    Content-Length: 0
    """
    _PKT_FIELD_PATTERNS = dict({"via":re.compile("^via: (?P<via>.*)", re.MULTILINE),
                          "to":re.compile("^To: (?P<to>.*)", re.MULTILINE),
                          "from":re.compile("^From: (?P<from>.*)", re.MULTILINE),
                          "callid":re.compile("^Call-ID: (?P<callid>.*)", re.MULTILINE),
                          "contentlength":re.compile("^Content-Length: (?P<contentlength>.*)", re.MULTILINE),
                          "cseq":re.compile("^CSeq: (?P<cseq>\d*)", re.MULTILINE),
                          "maxforwards":re.compile("^Max-Forwards: (?P<maxorwards>.*)", re.MULTILINE),
                          "accept":re.compile("^Accept: (?P<accept>.*)", re.MULTILINE),
                          "contact":re.compile("^Contact: (?P<contact>.*)", re.MULTILINE),
                          "useragent":re.compile("(?:Server|User-Agent): (?P<useragent>.*)", re.MULTILINE),
                          "allow":re.compile("^Allow: (?P<allow>.*)", re.MULTILINE),
                          "supported":re.compile("^Supported: (?P<supported>.*)", re.MULTILINE)})
                         
    def __init__(self, bindingip="0.0.0.0", localport=5060, selecttime=0.005, sockettimeout=3, pcallback=None):
        self._sockettimeout = sockettimeout
        self._localport = localport
        self._bindingip = bindingip
        self._selecttime = selecttime
        self._pcallback = pcallback
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # we do UDP
        self._sock.settimeout(self._sockettimeout)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) # so we can send broadcasts
        self._donetargets = list() # list of servers on which we've confirmed SIP

    def logDebug(self, msg):
        if self._pcallback:
            self._pcallback.logDebug(msg)
        else:
            print "-DEBUG- %s" %(msg)        

    def logInfo(self, msg):
        if self._pcallback:
            self._pcallback.logInfo(msg)
        else:
            print "-INFO- %s" %(msg)

    def logWarning(self, msg):
        if self._pcallback:
            self._pcallback.logWarning(msg)
        else:
            print "-WARNING- %s" %(msg)
        
    def bind(self):
        """
        Bind to local address = (externalip, localport)
        """
        while self._localport < 65536:
            try:
                self._sock.bind((self._bindingip,self._localport))
                break
            except socket.error:
                self.logWarning("couldn't bind to localport %s" %(self._localport))
                self._localport += 1
        self._externalip = "127.0.0.1"
        if self._localport == 65535:
            self.logWarning("couldn't bind to any local port")
            return -1
        self.logDebug("bound to %s:%s" %(self._bindingip, self._localport))
        try:
            self._externalip = socket.gethostbyname(socket.gethostname())
        except socket.error:
            pass
          
    def handleDiscovery(self, ip, port, useragent):
        self.logInfo("SIP (UDP) server '%s' at %s:%s" %(useragent, ip, port)) 
        if self._pcallback:
            self._pcallback.announceNewTarget(targets.TARGET_SIP_SERVICE(ip=ip, port=port, useragent=useragent,))
            self._pcallback.announceNewTarget(targets.TARGET_IP(ip=ip,))
            self._donetargets.append((ip,port))

    def getResponse(self):
        """
        Read incoming response from socket
        """
        buf, srcaddr = self._sock.recvfrom(self._CHUNK_SIZE)
        if srcaddr in self._donetargets:
            return
        if re.search("^(?:OPTIONS|INVITE|REGISTER)", buf, re.MULTILINE):
            if srcaddr == (self._externalip, self._localport):
                self.logDebug("our own pkt ..")
            else:
                self.logDebug("SIP req from %s:%s" %(srcaddr))
            return
        else:
            match = self._PKT_FIELD_PATTERNS["useragent"].search(buf)
            if match:
                useragent = match.group("useragent").rstrip("\r\n")
            else:
                useragent = "UNKNOWN"
            self.logDebug("Received SIP reponse pkt\n%s" %(buf))
            self.handleDiscovery(srcaddr[0], srcaddr[1], useragent)
                
    def execute(self, target, portrange="4569, 5060-5070", methods=["OPTIONS"]):
        """
        Scan
        """
        scaniter = scanlist(ip4range(*target), getPortRange(portrange), methods)
        if self.bind() == -1:
          return
        fromname = "quatre-vingt-quinze"
        fromaddr = toaddr = '"%s"<sip:%s@1.1.1.1>' %(fromname, random.choice(xrange(100, 1000)))
        nomoretoscan = False
        while True:
            try:
                r, w, x = select.select([self._sock], list(), list(), self._selecttime)
                if r: # somebody talking; let's see what they saying ..
                    try:
                        self.getResponse()
                    except socket.error:
                        continue
                else: # nobody talking; let's rule ..
                    if nomoretoscan:
                        try:
                            while True:
                                self.getResponse()
                        except socket.error:
                            break
                    try:
                        ip, port, method = scaniter.next()
                        dsthost = (ip, port)
                    except StopIteration:
                        nomoretoscan = True # targets exhausted: send no more probes ..
                        continue      
                    branchunique = '%s' % (random.getrandbits(80))
                    localtag = createTag('%s%s' % (''.join(map(lambda x: '%02x' % int(x), dsthost[0].split('.'))),'%04x' % dsthost[1]))
                    callid = '%s' %(random.getrandbits(80))
                    contact = None
                    if method != 'REGISTER':
                        contact = 'sip:%s@%s:%s' % (random.choice(xrange(100, 1000)), self._externalip, self._localport)
                    req = makeRequest(method,
                                      fromaddr,
                                      toaddr,
                                      dsthost[0],
                                      dsthost[1],
                                      callid,
                                      self._externalip,
                                      branchunique,
                                      localtag=localtag,
                                      contact=contact,
                                      localport=self._localport,)
                    try:
                        bytes = mysendto(self._sock, req, dsthost)
                    except socket.error:
                        self.logWarning("socket error while sending SIP pkt to %s:%s (see traceback below)\n%s" %(dst,traceback.format_exc()))
        
            except:
                self.logWarning("error in select.select (see traceback below)\n%s" %(traceback.format_exc()))

        
def run(target, pcallback):
    sipprobe = SIPProbe(pcallback=pcallback)
    raw_target = target.get('iprange')
    if not type(raw_target) is list:
        raw_target = [raw_target]
    sipprobe.execute(raw_target)

if __name__ == '__main__':
    sip = SIPProbe()
    sip.execute(sys.argv[1], portrange=sys.argv[2])
