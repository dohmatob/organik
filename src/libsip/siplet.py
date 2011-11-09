import socket
import sys
import os
import select
import time
import random
import traceback
import re
import unittest
from helper import mysendto, getRange as getPortRange, ip4range, scanlist as getTargetList
import errno
from core import targets

SIP_PKT_PATTERNS = {'reqfirstline':re.compile("^(?P<method>(?:REGISTER|OPTIONS|ACK|BYE|CANCEL|NOTIFY|PRACK|INVITE|UPDATE|PUBLISH|MESSAGE|INFO)) sip:(?P<username>.*?)@(?P<domain>.*?) SIP/2.0\r\n"),
                    'respfirstline':re.compile("^SIP/2.0 (?P<code>[1-6][0-9]{2}) "),
                    'Via':re.compile("(?:Via|v): SIP/2.0/UDP (?P<provider>\S+?);branch=(?P<branch>z9hG4bK\S*?).*?\r\n"),
                    'To':re.compile("(?:To|t): (?P<username>\S+?) *?<(?P<uri>sip:\S+?@.+?)>(?:; *?tag=(?P<tag>.*?))\r\n"),
                    'From':re.compile("(?:From|f): (?P<username>\S+?) <(?P<uri>sip:\S+?@\S+?)>; *?tag=(?P<tag>.+?)\r\n"),
                    'CSeq':re.compile("CSeq: (?P<secnum>[0-9]+?) (?P<method>(?:REGISTER|OPTIONS|ACK|BYE|CANCEL|NOTIFY|PRACK|INVITE|UPDATE|PUBLISH|MESSAGE|INFO))\r\n"),
                    'Call-ID':re.compile("(?:Call-ID|i): (?P<callid>\S*?)\r\n"),
                    'Max-Forwards':re.compile("Max-Forwards: (?P<maxforwars>[0-9]+?)\r\n"),
                    'User-Agent':re.compile("(?:User-Agent|Server): (?P<useragent>.+?\r\n)"),
                    'Content-Length':re.compile("(?:Content-Length): (?P<contentlength>[0-9]+?)\r\n"),
                    }


class SipLet:
    """
    Scan SIP (UDP) -enabled devices
    """

    _CHUNK_SIZE = 8192
    def __init__(self, bindingip="0.0.0.0", localport=5060, selecttime=0.005, sockettimeout=3, pcallback=None):
        self._sockettimeout = sockettimeout
        self._localport = localport
        self._bindingip = bindingip
        self._selecttime = selecttime
        self._nomoretoscan = False
        self._pcallback = pcallback
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # we do UDP
        self._sock.settimeout(self._sockettimeout)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) # so we can send broadcasts
        self._donetargets = list() # list of servers on which we've confirmed SIP
        self._bound = False

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
        
    def makeRequest(self, dsthost, srchost=None, method="OPTIONS", username="sipuser", ToUri=None, FromUri=None, maxforwards=70, contact=None, content="", cseqnum=None, callid=None, auth=None):
        self._useragent = 'CRON' # XXX rm
        self._accept = 'application/sdp' # XXX rm
        if not srchost:
            srchost = (self._externalip, self._localport)
        req = ""
        firstline = "%s sip:%s@%s SIP/2.0\r\n" %(method,username,dsthost[0])
        superheaders = dict()
        headers = dict()
        finalheaders = dict()
        superheaders['Via'] = "SIP/2.0/UDP %s:%s;branch=z9hG4bK-%s;rport" %(srchost[0],srchost[1],random.getrandbits(80))
        if ToUri is None: 
            ToUri = "sip:%s@1.1.1.1" %(random.choice(xrange(100,1000)))
        headers['To'] = '"%s" <%s>' %(username,ToUri)
        if FromUri is None:
            FromUri = "sip:%s@1.1.1.1" %(random.choice(xrange(100,1000)))
        if contact is None:
            contact = 'sip:%s@%s:%s' %(random.choice(xrange(100,1000)),srchost[0],srchost[1])
        headers['Contact'] = contact
        headers['From'] = '"%s" <%s>;tag=%s' %(random.choice(xrange(100,1000)),FromUri,random.getrandbits(80))
        if cseqnum is None:
            cseqnum = random.choice(xrange(1,1000))
        headers['CSeq'] = '%s %s' %(cseqnum,method)
        if callid is None:
            callid = random.getrandbits(80)
        headers['Call-ID'] = callid 
        if not maxforwards is None:
            headers['Max-Forwards'] = '%s' %(maxforwards)
        else:
            headers['Max-Forwards'] = '%s' %(random.choice(xrange(50,70)))
        headers['User-Agent'] = '%s' %(self._useragent)
        headers['Accept'] = self._accept        
        finalheaders['Content-Length'] = len(content)
        if auth is not None:
            response = challengeResponse(auth['username'],
                                         auth['realm'],
                                         auth['password'],
                                         method,
                                         uri,
                                         auth['nonce'])        
            if auth['proxy']:
                finalheaders['Proxy-Authorization'] = \
                    'Digest username="%s",realm="%s",nonce="%s",uri="%s",response="%s",algorithm=MD5' % (auth['username'],
                                                                                                         auth['realm'],
                                                                                                         auth['nonce'],
                                                                                                         uri,
                                                                                                         response)
            else:
                finalheaders['Authorization'] = \
                    'Digest username="%s",realm="%s",nonce="%s",uri="%s",response="%s",algorithm=MD5' % (auth['username'],
                                                                                                         auth['realm'],
                                                                                                         auth['nonce'],
                                                                                                         uri,
                                                                                                         response)

        req += firstline
        for param, value in superheaders.iteritems():
            req += '%s: %s\r\n' %(param,value)
        for param,value in headers.iteritems():
            req += '%s: %s\r\n' %(param,value)
        for param,value in finalheaders.iteritems():
            req += '%s: %s\r\n' %(param,value)
        req += '\r\n'
        req += content
        return req

    def bind(self):
        """
        Bind to local address = (externalip, localport)
        """
        if self._bound:
            return
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
            return
        self.logDebug("bound to %s:%s" %(self._bindingip, self._localport))
        try:
            self._externalip = socket.gethostbyname(socket.gethostname())
        except socket.error:
            pass
        self._bound = True
          
    def parsePkt(self, pkt):
        result = dict()
        headers = dict()
        for h,pattern in SIP_PKT_PATTERNS.iteritems():
            if h in ['reqfirstline', 'respfirstline']:
                continue
            headers[h] = None
            match = pattern.search(pkt)
            if match:
                headers[h] = re.sub(h + ': ', '', match.group()).rstrip('\r\n')
            if h == 'User-Agent' and headers[h]:
                headers[h] = re.sub("Server: ", "", headers[h])
        result['headers'] = headers
        match = SIP_PKT_PATTERNS['respfirstline'].search(pkt)
        if match:
            result['respfirstline'] = match.group().rstrip(' ')
            result['code'] = int(match.group('code'))
        else:
            result['code'] = None
        return result
  
    def treated(self, addr):
        return False

    def getResponse(self):
        """
        Read incoming response from socket
        """
        buf, srcaddr = self._sock.recvfrom(self._CHUNK_SIZE)
        if self.treated(srcaddr):
            return
        meta = self.parsePkt(buf)
        if meta['code'] is None:
            if srcaddr == (self._externalip, self._localport):
                self.logDebug("our own pkt ..")
            # else:
            #     self.logDebug("SIP req from %s:%s" %(srcaddr[0],srcaddr[1]))
            return
        else:
            if meta['headers']['User-Agent'] is None:
                meta['headers']['User-Agent'] = 'UNKNOWN'  
            self.callback(srcaddr, meta)
            self._donetargets.append(srcaddr)

    def noMoreToScan(self):
        """
        This boolean method determines whether scan items have been exhausted
        """
        return self._nomoretoscan

    def getNextScanItem(self):
        """
        This method fetches next scan item
        """
        try:
            return self._scaniter.next()
        except StopIteration:
            self._nomoretoscan = True

    def noNeedToContinue(self):
        """
        This boolean method is called to check whether some global goal 
        has been achieved which makes the rest of the scan useless. 
        """
        return False

    def mainLoop(self):
        """
        ARGANIC CHEMISTRY
        """
        self.bind()
        if not self._bound:
            return
        while True:
            try:
                r, w, x = select.select([self._sock], list(), list(), self._selecttime)
                if r: # somebody talking; let's see what they saying ..
                    if self.noNeedToContinue():
                        break
                    try:
                        self.getResponse()
                    except socket.error:
                        continue
                else: # nobody talking; let's rule ..
                    if self.noMoreToScan():
                        try:
                            while True:
                                self.getResponse()
                        except socket.error:
                            break
                    req = self.genNewRequest()
                    if req is None:
                        continue
                    dstaddr,pkt = req
                    try:
                        bytes = mysendto(self._sock, pkt, dstaddr)
                    except socket.error:
                        self.logWarning("socket error while sending SIP pkt to %s:%s (see traceback below)\n%s" %(dstaddr[0],dstaddr[1],traceback.format_exc()))        
            except:
                self.logWarning("error in select.select (see traceback below)\n%s" %(traceback.format_exc()))


class TestSIPlet(unittest.TestCase):
    def test_genRequest(self):
        s = SipLet()
        s.bind()
        req = s.makeRequest(('localhost',5060))
        print req
        for key in SIP_PKT_PATTERNS.keys():
            print key
            self.assertTrue(SIP_PKT_PATTERNS[key].search(req))
        print s.parsePkt(req)


if __name__ == '__main__':
    unittest.main()
