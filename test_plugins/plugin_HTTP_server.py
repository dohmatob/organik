import urllib2
from engine import targets

DESCRIPTION = "This plugins determines the server (Apache, gws, etc.) that powers a given site"
AUTHOR = "d0hm4t06 3. d0p91m4"
AUTHOR_EMAIL = "gmdopp@gmail.com"

def targetrule(target):
    return target.getCategory() == "TARGET_TCP_PORT" and target.get("port") == 80

def run(target, pcallback=None):
    try:
        url = "http://%s:%s" %(target.get("ip"), target.get("port"))
        response = urllib2.urlopen(url)
        pcallback.logInfo("%s is powered by '%s'" %(url, response.headers["server"]))
    except:
        pass
