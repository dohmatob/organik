#!/usr/bin/env python
import re
import random
import socket
import traceback
from argparse import ArgumentParser
from SIPutils.siplet import SipLet
from SIPutils.packet import makeRequest, parsePkt
from SIPutils.iterators import fileLineIterator
from SIPutils.response_codes import *
from coreutils import targets

AUTHOR="""d0hm4t06 3. d0p91m4 (h4lf-jiffie)"""
AUTHOR_EMAIL="""gmdopp@gmail.com"""
DESCRIPTION="""Plugin to enumerate remote SIP usernames/extensions"""

ROOTDIR='.'

def targetrule(target):
    """
    Run plugin on targets in the TARGET_SIP_SERVICE category
    """
    return target.getCategory() == "TARGET_SIP_SERVICE"


class SipWarrior(SipLet):    
    def pktCallback(self, srcaddr, pkt):
        """
        Food is served
        """
        metadata = parsePkt(pkt)
        if metadata['headers']['To'] is None:
            # self.logInfo("received failure response: %s" %(metadata['respfirstline']))
            return
        if self._BADUSERCODE is None:
            """
            Perform a test 1st .. to find out what error code is returned for unknown users
            Quit if weird codes are returned (the SIP UAS must be sick or somethx \L/)
            """
            self._targetisalive = True
            if metadata['code'] == TRYING \
                    or metadata['code'] == RINGING \
                    or metadata['code'] == UNAVAILABLE:
                pass
            elif metadata['code'] == NOTALLOWED \
                    or metadata['code'] == NOTIMPLEMENTED \
                    or metadata['code'] == INEXISTENTTRANSACTION \
                    or metadata['code'] == NOTACCEPTABLE \
                    or metadata['code'] == BADREQUEST: # yes, protocol imcopatibility is fatal !
                self.logWarning("received fatal failure response '%s'" %(metadata['respfirstline']))
                try:
                    self._currentmethod = self._methods.pop()
                    self._testpktgenerated = False
                except IndexError:
                    self.logWarning("all test pkts failed")
                    self._failed = True
            elif metadata['code'] == PROXYAUTHREQ \
                    or metadata['code'] == INVALIDPASS \
                    or metadata['code'] == AUTHREQ \
                    or metadata['code'] == TEMPORARILYUNAVAILABLE:
                self.logWarning("SIP server replied with an authentication request '%s' for an random extension; there can't be any hope!" %(metadata['respfirstline']))
                self._failed = True
            else:
                self._BADUSERCODE = metadata['code']
                self.logDebug("BADUSERCODE = %s" % self._BADUSERCODE)
            return
        match = re.search("^(?P<username>.+?) *?<", metadata['headers']['To'])
        username = match.group('username').replace('"', '').replace("'", "")
        if metadata['code'] != self._BADUSERCODE:
            if username in self._doneusernames:
                return
            if (200 <= metadata['code'] < 300) and self._ackenabled: # ACKnowledge all 2XX (success!) responses
                if metadata['headers']['CSeq'] is None:
                    # self.logDebug("received failure response: %s" %(metadata['firstline']))
                    return
                match = re.search("^(?P<cseqnum>[0-9]+?) .+?", metadata['headers']['CSeq'])
                assert match is not None # XXX dirty
                cseqnum = match.group('cseqnum')
                ackpkt = makeRequest('ACK',
                                     srcaddr[0],
                                     srcaddr[1],
                                     self._xternalip,
                                     self._localport,
                                     extension=username,
                                     callid=metadata['headers']['Call-ID'],
                                     cseqnum=cseqnum)
                self.logInfo("received (success) response '%s' for username '%s'" %(metadata['respfirstline'], username))
                self.logDebug("sending ACK ..")
                self._sock.sendto(ackpkt, srcaddr)
            if metadata['code'] == OKAY \
                    or metadata['code'] == AUTHREQ \
                    or metadata['code'] == PROXYAUTHREQ \
                    or metadata['code'] == INVALIDPASS \
                    or metadata['code'] == TEMPORARILYUNAVAILABLE:
                self._doneusernames.append(username)
                authentication = 'reqauth'
                if metadata['code'] == OKAY:
                    authentication = 'noauth'
                self.logInfo("cracked username: %s (SIP response to '%s' request was '%s')" %(username,self._currentmethod,metadata['respfirstline']))
                if self._pcallback:
                    self._pcallback.announceNewTarget(targets.TARGET_SIP_USER(ip=srcaddr[0], 
                                                                              port=srcaddr[1],
                                                                              useragent=metadata['headers']['User-Agent'],
                                                                              username=username,
                                                                              authentication=authentication))
            else:
                self.logInfo("received '%s' for username '%s'" %(metadata['respfirstline'], username))
        else:
            self.logInfo("received failure response '%s' for username '%s'" %(metadata['respfirstline'], username))
            pass

    def mustDie(self):
        return self._failed

    def mayGenerateNextRequest(self):
        if not self._testpktgenerated:
            return True
        else:
            return self._targetisalive

    def genNextRequest(self):
        """
        Generate next request to fire on target SIP UAS
        """
        if not self._testpktgenerated:
            self.logDebug("generating '%s' test .." %self._currentmethod)
            self._testpktgenerated = True
            nextusername = random.getrandbits(9)
        else:
            nextusername = self._scaniter.next()
        toaddr = fromaddr = '"%s"<sip:%s@%s>' %(nextusername,nextusername,self._targetip)
        contact = 'sip:%s@%s' %(nextusername,self._targetip)
        reqpkt = makeRequest(self._currentmethod,
                             self._targetip,
                             self._targetport,
                             self._xternalip, 
                             self._localport,
                             toaddr,
                             fromaddr,
                             contact=contact,
                             extension=nextusername)
        return (self._targetip,self._targetport), reqpkt        

    def execute(self, targethost, targetport, dictionary, methods=["PING","REGISTER","OPTIONS",], ackenabled=True):
        self._methods = methods
        self._currentmethod = self._methods.pop()
        self._targetip = socket.gethostbyname(targethost)
        self._targetport = targetport
        self._testpktgenerated = False
        self._targetisalive = False
        self._ackenabled = ackenabled
        self._BADUSERCODE = None
        self._doneusernames = []
        self._failed = False
        try:
            self._scaniter = fileLineIterator(open(dictionary, 'r'))
        except:
            self.logDebug("caught exception while opening dictionary '%s' (see traceback below):\n%s" %(dictionary,traceback.format_exc()))
            return        
        self.mainLoop()
        if not self._targetisalive:
            self.logWarning("No server response")
        elif self._doneusernames:
            self.logInfo('cracked usernames: %s' %(', '.join(self._doneusernames))) # XXX reportVuln here !!!
        
def run(target, pcallback):
    sipwarrior = SipWarrior(pcallback=pcallback)
    sipwarrior.execute(target.get('ip'), target.get('port'), '%s/etc/SIP/wordlists/dummy_usernames.txt' % ROOTDIR)


if __name__ == '__main__':
    parser = ArgumentParser(version='w0rkz 0f d0hm4t06 3. d0p91m4')
    parser.add_argument('--target', '-t',
                        action='store',
                        dest='target',
                        default='localhost',
                        help="""specify a target ip (default is localhost)""",
                        )
    parser.add_argument('--port', '-p',
                        action='store',
                        dest='port',
                        default=5060,
                        help="""specify target port (default is 5060)""",
                   )
    parser.add_argument('--dictionary', '-d',
                        action='store',
                        dest='dictionary',
                        default=None,
                        help="""specify dictionary file of SIP usernames to use""",
                        )
    parser.add_argument('--methods', '-m',
                        action='store',
                        dest='methods',
                        default="PING",
                        help="""specify request method to use (default are PING)""",
                        )
    options = parser.parse_args()
    sip = SipWarrior()
    sip.execute(options.target, int(options.port), options.dictionary, methods=options.methods.split(","))
