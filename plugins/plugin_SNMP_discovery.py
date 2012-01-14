#!/usr/bin/env python
import netsnmp
import re
import sys
import math
import threading
import multiprocessing
import signal
import os
import traceback
from coreutils import targets

DESCRIPTION="""SNMP discovery module"""
AUTHOR="""d0hm4t06 3. d0p91m4"""
AUTHOR_EMAIL="""gmdopp@gmail.com"""

ROOTDIR='.'

def targetrule(target):
    """
    Run plugin on targets in the "TARGET_IP" category
    """
    return target.getCategory() == "TARGET_IP" 

class SnmpProbe:
    """
    NET-SNMP plugin for probing SNMP-enabled systems
    """
    _VERSIONS = xrange(1,3) # XXX TODO: add support for version 3 (authentication-based)
    _COMMUNITIES = list(["public", "private"])

    def __init__(self, pcallback=None):
        self._pcallback = pcallback
        
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

    def probe(self, target_ip, version, community):
        if (target_ip,version,) in self._discoveries:
            return
        self.logDebug("probing %s for SNMPv%s (%s)" %(target_ip, version, community))
        session = netsnmp.Session(Version=version,
                                  DestHost=target_ip,
                                  Community=community,)
        oids = netsnmp.VarList(netsnmp.Varbind("sysDescr", 0), 
                               netsnmp.Varbind("sysName", 0), 
                               netsnmp.Varbind("sysUpTime", 0),
                               netsnmp.Varbind("hrMemorySize", 0),
                               netsnmp.Varbind("sysLocation", 0),
                               netsnmp.Varbind("sysContact", 0),)
        """
        command-line example: snmpget -v1 -c private 192.168.46.1 sysDescr.0 sysName.0 \ 
        sysUpTime.0 hrMemorySize.0 sysContact.0 sysLocation.0
        """
        sysdescr, sysname, sysuptime, hrmemorysize, syslocation, syscontact = session.get(oids)
        if sysdescr:
            self._discoveries.append((target_ip,version,))
            if self._pcallback:
                version = '%s' %version
                if version == '2':
                    version = '2c'
                self._pcallback.announceNewTarget(targets.TARGET_SNMP_SERVICE(ip=target_ip, 
                                                                     port=161, # XXX other UDP ports ?
                                                                     version=version,
                                                                     community=community,
                                                                     sysdescr=sysdescr,
                                                                     sysname=sysname))
            raw_output = """%s serves SNMPv%s (%s):
            sysDescr    : %s
            sysName     : %s
            sysUpTime   : %s
            hrMemorySize: %s
            sysLocation : %s
            sysContact  : %s
            """ %(target_ip,
                  version,
                  community,
                  sysdescr,
                  sysname,
                  sysuptime,
                  hrmemorysize,
                  syslocation,
                  syscontact)
            self.logInfo(raw_output) # XXX report info/vuln            

    
    def execute(self, target_ip, communities=None):
        if not communities:
            communities = self._COMMUNITIES
        self._discoveries = multiprocessing.Manager().list()
        workers = list()
        for community in communities:
            for version in self._VERSIONS:
                worker = threading.Thread(target=self.probe, args=(target_ip, version, community,))
                worker.start()
                workers.append(worker)
        for worker in workers:
            worker.join()

def run(target, pcallback):
    snmpprobe = SnmpProbe(pcallback=pcallback)
    try:
        fh = open("%s/etc/snmp/common_communities.txt" % ROOTDIR, 'r')
        communities = [line.rstrip('\r\n') for line in fh.readlines()]
        fh.close()
    except:
        communities = None
    snmpprobe.execute(target.get("ip"), communities=communities)
    

if __name__ == "__main__":
    snmpprobe = SnmpProbe()
    try:
        fh = open("%s/etc/snmp/common_communities.txt" %ROOTDIR, 'r')
        communities = [line.rstrip('\r\n') for line in fh.readlines()]
        fh.close()
    except:
        communities = None
    snmpprobe.execute(sys.argv[1], communities=communities)
