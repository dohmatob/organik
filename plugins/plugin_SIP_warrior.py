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
from core import targets

AUTHOR="""d0hm4t06 3. d0p91m4"""
AUTHOR_EMAIL="""gmdopp@gmail.com"""
DESCRIPTION="""Plugin to enumerate remote SIP usernames/extensions"""

ROOTDIR='.'

def targetrule(target):
    """
    Run plugin on targets in the TARGET_SIP_SERVICE category
    """
    return target.getCategory() == "TARGET_SIP_SERVICE"


class SipWarrior(SipLet):    
    def callback(self, srcaddr, pkt):
        """
        Food is served
        """
        metadata = parsePkt(pkt)
        if metadata['headers']['To'] is None:
            # self.logInfo("received failure response: %s" %(metadata['respfirstline']))
            return
        match = re.search("^(?P<username>.+?) *?<", metadata['headers']['To'])
        username = match.group('username').replace('"', '').replace("'", "")
        if metadata['code'] != self._BADUSER:
            if username in self._doneusernames:
                return
            if 200 <= metadata['code'] < 300: # ACKnowledge all 2XX (success!) responses
                if metadata['headers']['CSeq'] is None:
                    # self.logDebug("received failure response: %s" %(metadata['firstline']))
                    return
                match = re.search("^(?P<cseqnum>[0-9]+?) .+?", metadata['headers']['CSeq'])
                cseqnum = match.group('cseqnum')
                ToUri = FromUri = 'sip:%s@%s' %(username, srcaddr[0])
                req = self.makeRequest(srcaddr,
                                       method='ACK',
                                       username=username,
                                       callid=metadata['headers']['Call-ID'],
                                       cseqnum=cseqnum,
                                       ToUri=ToUri,
                                       FromUri=FromUri,
                                       )
                self.sendto(req, srcaddr)
            if metadata['code'] == OKAY \
                    or metadata['code'] == TEMPORARILYUNAVAILABLE \
                    or metadata['code'] == AUTHREQ \
                    or metadata['code'] == PROXYAUTHREQ \
                    or metadata['code'] == INVALIDPASS: # username exists!
                self._doneusernames.append(username)
                authentication = 'reqauth'
                if metadata['code'] == OKAY:
                    authentication = 'noauth'
                self.logInfo("cracked username: %s (SIP response to '%s' request was '%s')" %(username,self._method,metadata['respfirstline']))
                if self._pcallback:
                    self._pcallback.announceNewTarget(targets.TARGET_SIP_USER(ip=srcaddr[0], 
                                                                              port=srcaddr[1],
                                                                              useragent=metadata['headers']['User-Agent'],
                                                                              username=username,
                                                                              authentication=authentication))
        else:
            self.logInfo("received '%s' for username '%s'" %(metadata['respfirstline'], username))
            pass

    def genNewRequest(self):
        """
        Generate next request to fire on target SIP UAS
        """
        nextusername = self.getNextScanItem()
        if not nextusername is None:
            toaddr = fromaddr = '"%s" <sip:%s@%s>' %(nextusername,nextusername,self._targetip)
            reqpkt = makeRequest(self._method,
                                 self._targetip,
                                 self._targetport,
                                 self._externalip, 
                                 self._localport,
                                      toaddr,
                                      fromaddr)
            return (self._targetip,self._targetport), reqpkt        

    def getBADUSER(self):
        """
        Perform a test 1st .. to find out what error code is returned for unknown users
        Quit if weird codes are returned (the SIP UAS must be sick or somethx \L/)
        """
        self.bind()
        if not self._bound:
            return
        randomusername = random.getrandbits(32)
        toaddr = fromaddr = '"%s" <sip:%s@%s>' %(randomusername,randomusername,self._targetip)
        data = makeRequest(self._method,
                           self._targetip,
                           self._targetport,
                           self._externalip,
                           self._localport,
                           toaddr,
                            fromaddr)
        try:
            self.sendto(data,(self._targetip,self._targetport))
        except socket.error,err:
            self.logWarning("socket error while sending SIP requset: %s" % err)
            return
        # first we identify the assumed reply for an unknown extension 
        gotbadresponse=False
        try:
            while 1:
                try:
                    buff,srcaddr = self._sock.recvfrom(8192)
                except socket.error,err:
                    self.logWarning("socket error while receiving from remote peer: %s" % err)
                    return
                metadata = parsePkt(buff)
                if metadata['code'] is None: # this is a request, not a response
                    continue
                if metadata['code'] == TRYING \
                        or metadata['code'] == RINGING \
                        or metadata['code'] == UNAVAILABLE:
                    gotbadresponse=True
                elif metadata['code'] == NOTALLOWED \
                        or metadata['code'] == NOTIMPLEMENTED \
                        or metadata['code'] == INEXISTENTTRANSACTION \
                        or metadata['code'] == BADREQUEST: # yes, protocol imcopatibility is fatal
                    self.logWarning("received fatal failure response: %s" %(metadata['respfirstline']))
                    return
                elif metadata['code'] == PROXYAUTHREQ \
                        or metadata['code'] == INVALIDPASS \
                        or metadata['code'] == AUTHREQ: # 
                    self.logWarning("SIP server replied with an authentication request '%s' for an random extension; there can be hope!" %(metadata['respfirstline']))
                    return
                else:
                    self._BADUSER = metadata['code']
                    self.logDebug("BADUSER code = %s" % self._BADUSER)
                    gotbadresponse=False
                    break
        except socket.timeout:
            if gotbadresponse:
                self.logWarning("The response we got was not good: %s" % `buff`)
            else:
                self.logWarning("No server response - are you sure that this PBX is listening? run svmap against it to find out")
            return
        except (AttributeError,ValueError,IndexError), err:
            print err
            self.logWarning("bad response .. bailing out")            
            return
        except socket.error,err:
            self.logWarning("socket error: %s" % err)
            return
        if self._BADUSER == AUTHREQ:
            self.logWarning("BADUSER code = %s - svwar will probably not work!" % self._BADUSER)

    def execute(self, ip, port, dictionary, method="REGISTER"):
        self._method = method
        self._targetip = ip
        self._targetport = port
        self._BADUSER = None
        self.getBADUSER()
        if self._BADUSER == None:
            return
        self._doneusernames = list()
        try:
            self._scaniter = fileLineIterator(open(dictionary, 'r'))
        except:
            self.logDebug("caught exception while opening dictionary '%s' (see traceback below):\n%s" %(dictionary,traceback.format_exc()))
            return        
        self.mainLoop()
        if self._doneusernames:
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
    parser.add_argument('--method', '-m',
                        action='store',
                        dest='method',
                        default='REGISTER',
                        help="""specify request method to use (default is REGISTER)""",
                        )
    options = parser.parse_args()
    sip = SipWarrior()
    sip.execute(options.target, int(options.port), options.dictionary, method=options.method)
