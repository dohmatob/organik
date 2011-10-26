import netsnmp
import re

DESCRIPTION="""SNMP discovery module"""
AUTHOR="""d0hm4t06 3. d0p91m4"""
AUTHOR_EMAIL="""gmdopp@gmail.com"""

def targetrule(target):
    return target.getCategory() == "TARGET_IP" 


class SnmpProbe:
    """
    NET-SNMP plugin for probing SNMP-enabled systems
    """
    _versions = xrange(1,3) # XXX TODO: add version "2c" and 3 (authentication-based)
    _community_pattern = re.compile("^(?P<community>.*)", re.MULTILINE)
        
    def __init__(self, pcallback):
        self._pcallback = pcallback

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
        for match in self._community_pattern.finditer(fh.read()):
            community = match.group("community")
            for version in self._versions:
                self.log("Trying SNMPv%s (%s)" %(version, community), debug=True)
                session = netsnmp.Session(Version=version,
                                          DestHost=target_ip,
                                          Community=community,
                                          )
                oids = netsnmp.VarList(netsnmp.Varbind("sysDescr", 0), 
                                       netsnmp.Varbind("sysName", 0), 
                                       netsnmp.Varbind("sysUpTime", 0),
                                       netsnmp.Varbind("hrMemorySize", 0),
                                       netsnmp.Varbind("sysLocation", 0),
                                       netsnmp.Varbind("sysContact", 0),) 
                sysdescr, sysname, sysuptime, hrmemorysize, syslocation, syscontact = session.get(oids)
                if sysdescr:
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
                    self.log(raw_output)
                    return
        

def run(target, pcallback):
    snmpprobe = SnmpProbe(pcallback)
    snmpprobe.execute(target.get("ip"), "etc/snmp/common_communities.txt")
    
