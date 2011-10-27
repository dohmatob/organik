DESCRIPTION="""Plugin to check for obselete SNMP versions ( < 3) --insecure!"""
AUTHOR="""d0hm4t06 3. d0p91m4"""
AUTHOR_EMAIL="""gmdopp@gmail.com"""

def targetrule(target):
    """
    Run plugin on targets in the category "TARGET_SNMP_SERVICE", for which the version is < 3
    """
    return target.getCategory() == "TARGET_SNMP_SERVICE" and int(target.get("version")) < 3

def run(target, pcallback):
    pcallback.log("%s serves obsolete SNMPv%s (%s); this is insecure --should upgrade to version 3" %(target.get("ip"), target.get("version"), target.get("community")))