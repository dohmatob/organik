import socket
import sys
import os
import select
import time
import random
import traceback
import re
import unittest
import errno

__author__ = 'd0hm4t06 E. d0p91m4'

class SipLet:
    _CHUNK_SIZE = 8192
    def __init__(self, bindingip="0.0.0.0", localport=5060, selecttime=0.005, sockettimeout=3, pcallback=None):
        self._sockettimeout = sockettimeout
        self._localport = localport
        self._bindingip = bindingip
        self._selecttime = selecttime
        self._nomoretoscan = False
        self._noneedtocontinue = False
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
  
    def sendto(self, pkt, addr):
        while pkt:
            bytes = self._sock.sendto(pkt[:self._CHUNK_SIZE], addr)
            pkt = pkt[bytes:]
        
    def treated(self, addr):
        return False

    def getResponse(self):
        """
        Read incoming response from socket
        """
        buf, srcaddr = self._sock.recvfrom(self._CHUNK_SIZE)
        if self.treated(srcaddr):
            return
        if re.search("^SIP/2.0 [1-6][0-9]{2} ", buf):  # is response pkt
            self._donetargets.append(srcaddr)
            self.callback(srcaddr, buf)
        elif re.search('^(REGISTER|OPTIONS|ACK|BYE|CANCEL|NOTIFY|PRACK|INVITE|UPDATE|PUBLISH|MESSAGE|INFO) sip:\S*', buf):
            if srcaddr == (self._externalip, self._localport):
                self.logDebug("our own pkt ..")
            # else:
            #     self.logDebug("SIP req from %s:%s:\n%s" %(srcaddr[0],srcaddr[1],buf))
        else:
            self.logWarning("got gabbage pkt: %s" %(buf))

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
        return self._noneedtocontinue

    def mainLoop(self):
        """
        ARGANIC CHEMISTRY
        """
        self.bind()
        if not self._bound:
            return
        while not self.noNeedToContinue():
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
                            self.logDebug('making sure no packets are lost ..')
                            while not self.noNeedToContinue():
                                self.getResponse()
                        except socket.error:
                            break
                    if self.noNeedToContinue():
                        break
                    req = self.genNewRequest()
                    if req is None:
                        continue
                    dstaddr,pkt = req
                    try:
                        bytes = self.sendto(pkt, dstaddr)
                    except socket.error:
                        self.logWarning("socket error while sending SIP pkt to %s:%s (see traceback below)\n%s" %(dstaddr[0],dstaddr[1],traceback.format_exc()))        
            except KeyboardInterrupt:
                self.logDebug('caught your KBI; quiting ..')
                sys.exit(1)
            except:
                self.logWarning("error in select.select (see traceback below)\n%s" %(traceback.format_exc()))


class TestSIPlet(unittest.TestCase):
    pass


if __name__ == '__main__':
    unittest.main()
