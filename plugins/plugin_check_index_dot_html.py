import urllib2
from coreutils import targets

DESCRIPTION = """Checks whether /index.html is served on web server"""
AUTHOR = """d0hm4t06 3. d0p91m4"""
AUTHOR_EMAIL="""gmdopp@gmail.com"""

def targetrule(target):
    if target.getCategory() != "TARGET_TCP_PORT":
        return False
    return target.get("port") == 80

def run(target, pcallback):
    try:
        response = urllib2.urlopen("http://%s:%s/index.html" %(target.get("ip"), target.get("port")))
        pcallback.logInfo("%s:%s serves /index.html" %(target.get("ip"), target.get("port")))
    except:
        pcallback.logInfo("%s:%s doesn't serve /index.html" %(target.get("ip"), target.get("port")))
