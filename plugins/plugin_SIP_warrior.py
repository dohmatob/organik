#!/usr/bin/env python
import re
import random
import socket
import traceback
from argparse import ArgumentParser
from libsip.siplet import SipLet
from libsip.helper import mysendto, dictionaryattack
from libsip.response_codes import *
from core import targets

AUTHOR="""d0hm4t06 3. d0p91m4"""
AUTHOR_EMAIL="""gmdopp@gmail.com"""
DESCRIPTION="""Plugin to enumerate remote SIP usernames"""

ROOTDIR='.'

def targetrule(target):
    """
    Run plugin on targets in the TARGET_SIP_SERVICE category
    """
    return target.getCategory() == "TARGET_SIP_SERVICE"


class SipWarrior(SipLet):    
    def callback(self, srcaddr, meta):
        if meta['headers']['To'] is None:
            # self.logInfo("received failure response: %s" %(meta['respfirstline']))
            return
        match = re.search("^(?P<username>.+?) *?<", meta['headers']['To'])
        username = match.group('username').replace('"', '').replace("'", "")
        if meta['code'] != self._BADUSER:
            if username in self._doneusernames:
                return
            if 200 <= meta['code'] < 300: # ACKnowledge all 2XX (success!) responses
                if meta['headers']['CSeq'] is None:
                    # self.logDebug("received failure response: %s" %(meta['firstline']))
                    return
                match = re.search("^(?P<cseqnum>[0-9]+?) .+?", meta['headers']['CSeq'])
                cseqnum = match.group('cseqnum')
                ToUri = FromUri = 'sip:%s@%s' %(username, srcaddr[0])
                req = self.makeRequest(srcaddr,
                                       method='ACK',
                                       username=username,
                                       callid=meta['headers']['Call-ID'],
                                       cseqnum=cseqnum,
                                       ToUri=ToUri,
                                       FromUri=FromUri,
                                       )
                mysendto(self._sock, req, srcaddr)
            if meta['code'] == OKAY \
                    or meta['code'] == TEMPORARILYUNAVAILABLE \
                    or meta['code'] == AUTHREQ \
                    or meta['code'] == PROXYAUTHREQ \
                    or meta['code'] == INVALIDPASS: # username exists!
                self._doneusernames.append(username)
                authentication = 'reqauth'
                if meta['code'] == OKAY:
                    authentication = 'noauth'
                self.logInfo("cracked username: %s" %(username))
                if self._pcallback:
                    self._pcallback.announceNewTarget(targets.TARGET_SIP_USER(ip=srcaddr[0], 
                                                                              port=srcaddr[1],
                                                                              useragent=meta['headers']['User-Agent'],
                                                                              username=username,
                                                                              authentication=authentication))
        else:
            self.logInfo("received '%s' for username '%s'" %(meta['respfirstline'], username))
            pass

    def genNewRequest(self):
        """
        Generate next request to fire on target SIP UAS
        """
        next = self.getNextScanItem()
        if not next is None:
            username = next
            ToUri = FromUri = 'sip:%s@%s' %(username, self._targetip)
            return (self._targetip,self._targetport), self.makeRequest((self._targetip,self._targetport), method=self._method, username=username, ToUri=ToUri, FromUri=FromUri)
        
    def getBADUSER(self):
        """
        Perform a test 1st .. to find out what error code is returned for unknown users
        Quit if weird codes are returned (the SIP UAS must be sick or somethx \L/
        """
        self.bind()
        if not self._bound:
            return
        randomusername = random.getrandbits(32)
        ToUri = FromUri = 'sip:%s@%s' %(randomusername, self._targetip)
        data = self.makeRequest((self._targetip,
                                 self._targetport), 
                                method=self._method,
                                username=randomusername,
                                ToUri=ToUri,
                                FromUri=FromUri)
        try:
            mysendto(self._sock,data,(self._targetip,self._targetport))
        except socket.error,err:
            self.logWarning("socket error: %s" % err)
            return
        # first we identify the assumed reply for an unknown extension 
        gotbadresponse=False
        try:
            while 1:
                try:
                    buff,srcaddr = self._sock.recvfrom(8192)
                except socket.error,err:
                    self.logWarning("socket error: %s" % err)
                    return
                meta = self.parsePkt(buff)
                if meta['code'] is None: # this is a request, not a response
                    continue
                if meta['code'] == TRYING \
                        or meta['code'] == RINGING \
                        or meta['code'] == UNAVAILABLE:
                    gotbadresponse=True
                elif meta['code'] == NOTALLOWED \
                        or meta['code'] == NOTIMPLEMENTED \
                        or meta['code'] == INEXISTENTTRANSACTION \
                        or meta['code'] == BADREQUEST: # yes, protocol imcopatibility is fatal
                    self.logWarning("received fatal failure response: %s" %(meta['respfirstline']))
                    return
                elif meta['code'] == PROXYAUTHREQ \
                        or meta['code'] == INVALIDPASS \
                        or meta['code'] == AUTHREQ: # 
                    self.logWarning("SIP server replied with an authentication request '%s' for an random extension; there can be hope!" %(meta['respfirstline']))
                    return
                else:
                    self._BADUSER = meta['code']
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
            self._scaniter = dictionaryattack(open(dictionary, 'r'))
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
