import netsnmp
import re
import targets

DESCRIPTION="""SNMP discovery module"""
AUTHOR="""d0hm4t06 3. d0p91m4"""
AUTHOR_EMAIL="""gmdopp@gmail.com"""

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
    _COMMUNITY_PATTERN = re.compile("^(?P<community>.+)", re.MULTILINE)
    
    def __init__(self,
                 request_timeout=500000, # default = 500000 microseconds
                 retries=3,
                 pcallback=None):
        self._pcallback = pcallback
        self._request_timeout = request_timeout
        self._retries = retries

    def log(self, msg, debug=False):
        if self._pcallback:
            self._pcallback.log(msg, debug=debug) 
        else:
            print msg

    def execute(self, target_ip, community_file):                
        try:
            fh = open(community_file, 'r')
        except:
            self.log("WARNING: could'nt read community file %s" %(community_file), debug=True)
            return
        doneversions = list()
        for match in self._COMMUNITY_PATTERN.finditer(fh.read()):
            community = match.group("community")
            for version in self._VERSIONS:
                if version in doneversions:
                    continue
                self.log("probing %s for SNMPv%s (%s)" %(target_ip, version, community), debug=True)
                session = netsnmp.Session(Version=version,
                                          DestHost=target_ip,
                                          Community=community,
                                          Timeout=self._request_timeout,
                                          Retries=self._retries,
                                          )
                oids = netsnmp.VarList(netsnmp.Varbind("sysDescr", 0), 
                                       netsnmp.Varbind("sysName", 0), 
                                       netsnmp.Varbind("sysUpTime", 0),
                                       netsnmp.Varbind("hrMemorySize", 0),
                                       netsnmp.Varbind("sysLocation", 0),
                                       netsnmp.Varbind("sysContact", 0),) 
                sysdescr, sysname, sysuptime, hrmemorysize, syslocation, syscontact = session.get(oids)
                if sysdescr:
                    doneversions.append(version)
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
                    self.log(raw_output) # XXX report info/vuln
                    if self._pcallback:
                        self._pcallback.publish(targets.TARGET_SNMP_SERVICE(ip=target_ip, 
                                                                            port=161, # XXX other UDP ports ?
                                                                            version=version,
                                                                            community=community,
                                                                            sysdescr=sysdescr,
                                                                            sysname=sysname))
                                                                            
                    

def run(target, pcallback):
    snmpprobe = SnmpProbe(request_timeout=50000, retries=1, pcallback=pcallback)
    snmpprobe.execute(target.get("ip"), "etc/snmp/common_communities.txt")
    
