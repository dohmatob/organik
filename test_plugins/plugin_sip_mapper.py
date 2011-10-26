import socket
import sys
import select
import time
import random
import traceback
import re
import helper

DESCRIPTION="""Plugin for SIP (UDP) discovery"""
AUTHOR="""d0hm4t06 3. d0p91m4"""
AUTHOR_EMAIL="""gmdopp@gmail.com"""

def targetrule(target):
    return target.getCategory() == "TARGET_IP"

class SIPProbe:
    _CHUNK_SIZE = 8192

    def __init__(self, bindingip="0.0.0.0", localport=5060, selecttime=0.005, sockettimeout=3, pcallback=None):
        self._sockettimeout = sockettimeout
        self._localport = localport
        self._bindingip = bindingip
        self._selecttime = selecttime
        self._pcallback = pcallback
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.settimeout(self._sockettimeout)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    def log(self, msg, debug=False):
        if self._pcallback:
            self._pcallback.log(msg, debug=debug)
        else:
            print msg        
        
    def getResponse(self):
        buf, srcaddr = self._sock.recvfrom(self._CHUNK_SIZE)
        if re.search("^(?:OPTIONS|INVITE|REGISTER)", buf, re.MULTILINE):
            if srcaddr == (self._externalip, self._localport):
                self.log("our own pkt ..")
            else:
                self.log("SIP req from %s:%s" %(srcaddr))
            return
        else:
            server_name = helper.fingerPrintPacket(buf)["name"][0]
            self.log("SIP (UDP) server '%s' at %s:5060" %(server_name, srcaddr[0])) 
            return True

    def execute(self, target_ip):
        self._localport, self._sock = helper.bindto(self._bindingip, self._localport, self._sock)
        self._externalip = "127.0.0.1"
        try:
            self._externalip = socket.gethostbyname(socket.gethostname())
        except socket.error:
            pass
        fromname = "sipvicious"
        fromaddr = "sip:100@1.1.1.1"
        while True:
            try:
                r, w, x = select.select([self._sock], list(), list(), self._selecttime)
                if r:
                    try:
                        if self.getResponse():
                            break
                    except socket.error:
                        print traceback.format_exc()
                        continue
                else:
                    dsthost = (target_ip, 5060)
                    branchunique = random.getrandbits(80)
                    localtag = random.getrandbits(80)
                    callid = '%s' % (random.getrandbits(80))
                    contact = None
                    toaddr = fromaddr
                    req = helper.makeRequest("REGISTER",
                                      fromaddr,
                                      toaddr,
                                      dsthost[0],
                                      dsthost[1],
                                      self._externalip,
                                      branchunique)
                    try:
                        bytes = helper.mysendto(self._sock, req, dsthost)
                    except socket.error:
                        self.log("error while sending SIP packet", debug=True)
                        pass
            except:
                print traceback.format_exc()
                pass # XXX dirty !!!

        
def run(target, pcallback):
    sipprobe = SIPProbe(pcallback=pcallback)
    sipprobe.execute(target.get("ip"))

if __name__ == '__main__':
    sip = SIPProbe()
    sip.execute(sys.argv[1])
