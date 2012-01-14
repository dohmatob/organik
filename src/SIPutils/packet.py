#!/usr/bin/env python
import re
from binascii import a2b_hex, b2a_hex
import unittest
import random
import md5
from response_codes import *
from libsip.helper import challengeResponse as getChallengeResponse

__author__ = 'd0hm4t06 3. d0p91m4'

SIP_PKT_PATTERNS = {'reqfirstline':re.compile("^(?P<method>(?:REGISTER|OPTIONS|ACK|BYE|CANCEL|NOTIFY|PRACK|INVITE|UPDATE|PUBLISH|MESSAGE|INFO)) sip:.*? SIP/2.0\r\n"),
                    'respfirstline':re.compile("^SIP/2.0 (?P<code>[1-6][0-9]{2}) .*?\r\n"),
                    'Via':re.compile("(?:Via|v): SIP/2.0/UDP (?P<provider>\S+?);branch=(?P<branch>z9hG4bK\S*?).*?\r\n"),
                    'To':re.compile("(?:To|t): (?P<username>\S+?) *?<(?P<uri>sip:\S+?@.+?)>(?:; *?tag=(?P<tag>.*?))?\r\n"),
                    'From':re.compile("(?:From|f): (?P<username>\S+?) <(?P<uri>sip:\S+?@\S+?)>; *?tag=(?P<tag>.+?)?\r\n"),
                    'CSeq':re.compile("CSeq: (?P<secnum>[0-9]+?) (?P<method>(?:REGISTER|OPTIONS|ACK|BYE|CANCEL|NOTIFY|PRACK|INVITE|UPDATE|PUBLISH|MESSAGE|INFO))\r\n"),
                    'Call-ID':re.compile("(?:Call-ID|i): (?P<callid>\S*?)\r\n"),
                    'Max-Forwards':re.compile("Max-Forwards: (?P<maxforwars>[0-9]+?)\r\n"),
                    'User-Agent':re.compile("(?:User-Agent|Server): (?P<useragent>.+?\r\n)"),
                    'Content-Length':re.compile("(?:Content-Length): (?P<contentlength>[0-9]+?)\r\n"),
                    }

def makeRequest(method,
                dsthost,
                dstport,
                srchost,
                srcport,
                toaddr,
                fromaddr,
                maxforwards=70,
                extension=None,
                contact=None,
                callid=None,
                cseqnum=1,
                localtag=None,
                contenttype=None,
                content='',
                accept='application/sdp',
                useragent='BROKEN-SYSTEMS',
                auth=None):
    """
    CRAFT SIP REQUEST PKT
    """
    superheaders = dict()
    headers = dict()
    finalheaders = dict()
    if extension is None:
        uri = 'sip:%s' %(dsthost)
    else:
        uri = 'sip:%s@%s' %(extension,dsthost)
    superheaders['Via'] = 'SIP/2.0/UDP %s:%s;branch=z9hG4bK-%s;rport' %(srchost,srcport,random.getrandbits(32))
    headers['To'] = toaddr
    headers['From'] = fromaddr
    if localtag is None:
        localtag = random.getrandbits(80)
    headers['From'] += ';tag=%s' %(localtag)
    headers['User-Agent'] = useragent
    if callid is None:
        callid = '%s' %(random.getrandbits(32))
    headers['Call-ID'] = callid
    if contact is None:
        contact = 'sip:%s:1.1.1.1' %(random.getrandbits(9)) # NO WHERE !
    headers['Contact'] = contact
    headers['CSeq'] = '%s %s' %(cseqnum,method)
    headers['Max-Forwards'] = maxforwards
    headers['Accept'] = accept
    finalheaders['Content-Length'] = len(content)
    if contenttype is None and finalheaders['Content-Length'] > 0:
        contentype = 'application/sdp'
    if contenttype is not None:
        finalheaders['Content-Type'] = contenttype
    if auth is not None:
        if auth['algorithm'] == 'MD5':
            response = getMD5ChallengeResponse(auth['username'],
                                            auth['realm'],
                                            auth['password'],
                                            method,
                                            uri,
                                            auth['nonce'])
        else:
            raise TypeError, "only supports 'MD5' digest algorithm"
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

    reqpkt = '%s %s SIP/2.0\r\n' %(method,uri)
    for header in superheaders.iteritems():
        reqpkt += '%s: %s\r\n' %header
    for header in headers.iteritems():
        reqpkt += '%s: %s\r\n' %header
    for header in finalheaders.iteritems():
        reqpkt += '%s: %s\r\n' %header
    reqpkt += '\r\n'
    reqpkt += content
    return reqpkt

def parsePkt(pkt):
    """
    Parse SIP pkt to extract headers/meta-data
    """
    meta = dict()
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
    match_1 = SIP_PKT_PATTERNS['respfirstline'].search(pkt)
    match_2 = SIP_PKT_PATTERNS['reqfirstline'].search(pkt)
    if match_1:
        meta['respfirstline'] = match_1.group().rstrip(' \r\n')
        meta['code'] = int(match_1.group('code'))
    elif match_2:
        meta['reqfirstline'] = match_2.group().rstrip(' \r\n')
        meta['code'] = None
    else:
        print "can't parse rotten SIP pkt:\r\n%s" %(pkt)
        return 
    if meta['code'] == AUTHREQ \
            or meta['code'] == PROXYAUTHREQ:
        meta['auth-header'] = dict()
        auth_match = re.search('(?P<www_or_proxy>(?:WWW|Proxy)-Authenticate): Digest (?P<other_meta>.*)\r\n', pkt)
        if auth_match:
            meta['auth-header']['type'] = auth_match.group('www_or_proxy')
            if meta['auth-header']['type'] == 'WWW-Auth-Header':
                meta['auth-header']['domain'] = re.search('domain="([-\/\\:\.a-zA-Z0-9]+)"', other_meta).group(1)
                meta['auth-header']['qop'] = re.search('qop="([-\/\\:\.a-zA-Z0-9]+)"', other_meta).group(1)
                meta['auth-header']['stale'] = re.search('stale=(?:True|False)', other_meta).group(1)
                meta['auth-header']['opaque'] = re.search('opaque="([-\/\\:\.a-zA-Z0-9]+)"', other_meta).group(1)
            other_meta = auth_match.group('other_meta')
            algo_match = re.search('algorithm=([a-zA-Z0-9]+)', other_meta)
            meta['auth-header']['realm'] = re.search('realm="([-\/\\:_\.a-zA-Z0-9]+)"', other_meta).group(1)
            meta['auth-header']['nonce'] = re.search('nonce="([-\/\\+:_\.a-zA-Z0-9]+)"', other_meta).group(1)
            if algo_match:
                meta['auth-header']['algorithm'] = algo_match.group(1)
            else:
                meta['auth-header']['algorithm'] = 'MD5' 
        else:
            del meta['auth-header']
    meta['headers'] = headers
    return meta

def createTag(data, marker):
    salt = random.getrandbits(32)
    return b2a_hex(data + marker + str(salt))

def decodeTag(tag, marker):
    return a2b_hex(tag).split(marker)[0]

def getMD5ChallengeResponse(username,
                            realm,
                            password,
                            method,
                            uri,
                            nonce
                            ):
    """
    Generates response to SIP (MD5) authentication 'challenge' 
    """
    _tmp1 = md5.new('%s:%s:%s' %(username,realm,password)).hexdigest()
    _tmp2 = md5.new('%s:%s' %(method,uri)).hexdigest()
    return md5.new('%s:%s:%s' %(_tmp1,nonce,_tmp2)).hexdigest()

class TestMakeRequest(unittest.TestCase):
    def test_basic(self):
        method = 'OPTIONS'
        srchost = dsthost = '127.0.0.1'
        dstport = srcport = 5060
        fromaddr = toaddr = '"jack" <sip:100@%s>' %(dsthost)
        reqpkt = makeRequest(method, dsthost, dstport, srchost, srcport, toaddr, fromaddr)
        print reqpkt
        meta = parsePkt(reqpkt)
        self.assertEqual(meta['headers']['Max-Forwards'], '70')
        self.assertEqual(meta['headers']['User-Agent'], 'BROKEN-SYSTEMS')

if __name__ == '__main__':
    unittest.main()
        
    
    
