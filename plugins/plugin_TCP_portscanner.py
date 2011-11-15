#!/usr/bin/env python
import socket
import select
import errno
import traceback
import time
import resource
import fcntl
import sys
import os
from optparse import OptionParser
from coreutils import targets 

DESCRIPTION="""Plugin scans host for open TCP ports by using the connect-select technique"""
AUTHOR="""d0hm4t06 3. d0p91m4"""
AUTHOR_EMAIL="""gmdopp@gmail.com"""

def targetrule(target):
    """
    Run plugin on targets in the 'TARGET_IP' category
    """
    return target.getCategory() == "TARGET_IP"

def run(target, pcallback):
    callback_env = dict()
    callback_env['pcallback'] = pcallback
    ss = SelectScanner(target=target.get('ip'), pcallback=pcallback, verbose=False)
    ss.execute()

class SelectScanner:
    def __init__(self, target='', portslot='1-9001', selecttimeout=0.001, timeout=None, pcallback=None, verbose=True):
        self._target = socket.gethostbyname(target)
        self._selecttimeout = selecttimeout
        self._pcallback = pcallback # invoked an open port is discovered
        self._ports = list()
        self._verbose = verbose
        self.expandPorts(portslot)
        self.setLimits()
        self._socks = dict()
        self._open_ports = list()
        self.setTimeout(timeout)

    def setTimeout(self, timeout):
        self._timeout = len(self._ports)*0.0001 # heuristically, 1s per 10000 ports
        if timeout and timeout > self._timeout:
            self._timeout = timeout
        self._timeout_per_port = self._timeout/len(self._ports)

    def logDebug(self, message):
        if self._pcallback:
            self._pcallback.logDebug(message)
        else:
            print message

    def logWarning(self, message):
        if self._pcallback:
            self._pcallback.logWarning(message)
        else:
            print message

    def logInfo(self, message):
        if self._pcallback:
            self._pcallback.logDebug(message)
        else:
            print message

    def setLimits(self):
        """ 
        Sets limits on resources (fds, etc.) we are allowed to use.
        The heuristic below works for 32-bit linux, u may need to 
        patch it for other UNIX platforms like Mac OS X, etc.
        """
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
        self._max_socks = soft
        # take into account all existent fds, minus stdin stderr stdout 
        for fd in range(3,resource.RLIMIT_NOFILE):
            try:
                fcntl.fcntl(fd, fcntl.F_GETFD)
                self._max_socks -= 1
            except:
                continue
        self._max_socks -= 25 # a heuristic security boundary of 25 fds
        self._max_socks = min(self._max_socks, 1000) # select.select() cannot watch on more than about 1200 fds at once; it throws an exception 

    def expandPorts(self, portslot):
        ports = list()
        if type(portslot) is int:
            ports += list([portslot])
        elif type(portslot) is list:
            ports += portslot
        elif type(portslot) is str:
            token = portslot.split('-')
            if len(token) == 1:
                ports += list([int(token[0])])
            elif len(token) == 2:
                ports += range(int(token[0]), 1 + int(token[1]))
            else:
                self.logDebug('WARNING: invalid portslot %s' %(portslot))
        else:
            self.logDebug('WARNING: invalid portslot type' %(type(portslot)))
        self._ports += ports
        return ports

    def outOfResources(self):
        return len(self._socks) >= self._max_socks

    def execute(self):
        if self._verbose:
            self.logDebug('scanning %s TCP ports on target %s; timeout is %ss' %(len(self._ports), self._target, self._timeout))
        for port in self._ports:
            if not self.outOfResources():
                # configure socket
                sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
                sock.setblocking(0)
                sock.settimeout(0.0)
                self._socks[port] = sock
                # connect
                try:
                    sock.connect((self._target, port))
                except socket.error, error:
                    if error.errno == errno.EINPROGRESS:
                        pass
                    else:
                        self.logWarning(traceback.format_exc())
                        continue
                except:
                    self.logWarning(traceback.format_exc())
                    continue
            else:
                # select on sockets
                self.mainLoop(len(self._socks)*self._timeout_per_port)
        if self._socks:
            self.mainLoop(len(self._socks)*self._timeout_per_port)
        if self._pcallback:
            raw_output = """ REPORT 
            HOST:     %s,
            OPEN PORTS: %s
            """ %(self._target, self._open_ports)
            vid = 1 # XXX dummy
            self._pcallback.reportVuln(vid, raw_output)
        else:
            self.logInfo('OPEN PORTS FOUND: %s' %(', '.join(map(lambda port: str(port), self._open_ports))))

    def freeSock(self, port):
        del self._socks[port]

    def handle(self, hot_socks, read=True):
        for sock in hot_socks:
            try:
                ip, port = sock.getpeername()
                if port in self._open_ports:
                    continue
                self.freeSock(port)
                self._open_ports.append(port)
                if self._pcallback:
                    self._pcallback.announceNewTarget(targets.TARGET_TCP_PORT(ip=self._target, port=port))
                else:
                    self.logInfo('found TCP service at %s:%s' %(ip, port))
            except socket.error, error:
                if error.errno == errno.ENOTCONN:
                    continue
                else:
                    self.logWarning(traceback.format_exc())
            except:
                self.logWarning(traceback.format_exc())

    def mainLoop(self, timeout):
        socks = self._socks.values()
        if self._verbose:
            self.logInfo('scanning a batch of %s ports; timeout is %ss' %(len(socks), timeout))
        while timeout > 0 and socks:
            starttime = time.time()
            try:
                rsocks, wsocks, xsocks = select.select(socks, socks, socks, self._selecttimeout)
                if rsocks:
                    self.handle(rsocks)
                if wsocks:
                    self.handle(wsocks, read=False)
                if xsocks:
                    self.logDebug('WARNING: error on sock object')
                timeout -= time.time() - starttime
                socks = self._socks.values()
            except:
                self.logDebug(traceback.format_exc())
                break
        self._socks = dict() # cleanup
        if self._verbose:
            self.logDebug('done.')
                

if __name__ == '__main__':
    parser = OptionParser(version='%s by dohmatob elvis dopgima' %(sys.argv[0]))
    parser.add_option('--target',
                      dest='target',
                      action='store',
                      default='',
                      help="""specify target host (default is localhost)""",
                      )
    parser.add_option('--portslot',
                      dest='portslot',
                      action='store',
                      default='1-65535',
                      help="""specify portslot to scan (default is '1-65355')""",
                      )
    parser.add_option('--timeout',
                      dest='timeout',
                      action='store',
                      default=0,
                      help="""specify delay timeout for scan""",
                      )
    parser.add_option('--selecttimeout',
                      dest='selecttimeout',
                      action='store',
                      default=0.0003,
                      help="""specify selecttimeout (default is 0.001)""",
                      )
    options, _ = parser.parse_args()
    ss = SelectScanner(target=options.target, portslot=options.portslot, selecttimeout=float(options.selecttimeout), timeout=float(options.timeout))
    ss.execute()
    
    
