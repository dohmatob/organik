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

ROOTDIR='.' # XXX what is this ?

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
        self._targetisalive = True
        metadata = parsePkt(pkt)
        if metadata['headers']['To'] is None:
            # self.logInfo("received failure response: %s" %(metadata['respfirstline']))
            return
        if self._BADUSERCODE is None:
            """
            Perform a test 1st .. to find out what error code is returned for unknown users
            Quit if weird codes are returned (the SIP UAS must be sick or somethx \L/)
            """
            if metadata['code'] == TRYING \
                    or metadata['code'] == RINGING \
                    or metadata['code'] == UNAVAILABLE:
                pass
            elif metadata['code'] == OKAY \
                    or metadata['code'] == NOTALLOWED \
                    or metadata['code'] == UNSUPPORTED \
                    or metadata['code'] == NOTIMPLEMENTED \
                    or metadata['code'] == INEXISTENTTRANSACTION \
                    or metadata['code'] == NOTACCEPTABLE \
                    or metadata['code'] == BADREQUEST \
                    or metadata['code'] == PROXYAUTHREQ \
                    or metadata['code'] == INVALIDPASS \
                    or metadata['code'] == AUTHREQ \
                    or metadata['code'] == TEMPORARILYUNAVAILABLE:
                self.logWarning("SIP server (fatally) replied test packet with '%s'" %(metadata['respfirstline']))
                self.set_currentmethod()
            else:
                self.logDebug("ok. server replied test packet with '%s'"%(metadata['respfirstline']))
                self._BADUSERCODE = metadata['code']
                self.logDebug("setting BADUSERCODE = %s" % self._BADUSERCODE)
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
                self.sendto(ackpkt, srcaddr)
            if metadata['code'] == OKAY \
                    or metadata['code'] == AUTHREQ \
                    or metadata['code'] == PROXYAUTHREQ \
                    or metadata['code'] == INVALIDPASS \
                    or metadata['code'] == TEMPORARILYUNAVAILABLE:
                self._doneusernames.append(username)
                authentication = 'reqauth'
                if metadata['code'] == OKAY:
                    authentication = 'noauth'
                self.logInfo("cracked username: %s (response to '%s' request was '%s')" %(username,self._currentmethod,metadata['respfirstline']))
                if self._pcallback:
                    self._pcallback.announceNewTarget(targets.TARGET_SIP_USER(ip=srcaddr[0], 
                                                                              port=srcaddr[1],
                                                                              ua=metadata['headers']['User-Agent'],
                                                                              user=username,
                                                                              auth=authentication))
            else:
                self.logInfo("received '%s' for username '%s'" %(metadata['respfirstline'], username))
        else:
            self.logInfo("received failure response '%s' for username '%s'" %(metadata['respfirstline'], username))
            pass

    def mayGenerateNextRequest(self):
        if self._BADUSERCODE is None:
            if self._nb_test_pkts_generated >= self._max_test_pkts_per_method:
                self.logWarning("no server response for method '%s'"%self._currentmethod)                
                self.set_currentmethod()
        return True

    def set_currentmethod(self):
        self._nb_test_pkts_generated = 0
        self._BADUSERCODE = None
        try:
            self._currentmethod = self._methods.pop()
            self.logDebug("using request method '%s'"%self._currentmethod)
        except IndexError:
            self.logWarning("all methods failed!")
            self.breakMainLoop()
        
    def genNextRequest(self):
        """
        Generate next request to fire on target SIP UAS
        """
        if self._BADUSERCODE is None:
            self._nb_test_pkts_generated += 1
            self.logDebug("generating test packet #%d for method '%s' .." %(self._nb_test_pkts_generated,
                                                                            self._currentmethod))
            nextusername = random.getrandbits(50)
        else:
            try:
                nextusername = self._scaniter.next()
            except StopIteration:
                return None
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

    def execute(self, targethost, targetport, dictionary, methods=None, max_test_pkts_per_method=20, ackenabled=False):
        if methods is None:
            methods = ["PING","REGISTER","OPTIONS",]
    
        self._methods = methods
        self._max_test_pkts_per_method = max_test_pkts_per_method
        self._targetip = socket.gethostbyname(targethost)
        self._targetport = targetport
        self._ackenabled = ackenabled
        self._doneusernames = []
        try:
            self._scaniter = fileLineIterator(open(dictionary, 'r'))
        except:
            self.logDebug("caught exception while opening dictionary '%s' (see traceback below):\n%s" %(dictionary,traceback.format_exc()))
            return        
        self.set_currentmethod()
        self.mainLoop()
        if self._doneusernames:
            self.logInfo('cracked usernames: %s' %(', '.join(self._doneusernames))) # XXX reportVuln here !!!
        else:
            self.logInfo('nothing found')
        
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
                        default=None,
                        help="""specify comma-separated list of request methods to use""",
                        )
    options = parser.parse_args()
    methods = None
    if not options.methods is None:
        methods = options.methods.split(",")
    sip = SipWarrior()
    sip.execute(options.target, int(options.port), options.dictionary, methods=methods)
