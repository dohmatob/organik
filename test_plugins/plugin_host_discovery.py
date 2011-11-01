import nmap 
from engine import targets

DESCRIPTION="""Plugin does host discovery by wrapping nmap (poor; use direct ICMP pinging!!)"""
AUTHOR="""d0hm4t06 3. d0p91m4"""
AUTHOR_EMAIL="""gmdopp@gmail.com"""

def targetrule(target):
    return target.getCategory() == "TARGET_IPRANGE"

def result_callback(host, scan_data):
    try:
        if scan_data['scan'][host]['status']['state'] in list(['up']):
            if plugin_callback:
                plugin_callback.feedback(targets.TARGET_IP(ip=host))
            else:
                print '%s: up'
    except:
        pass

def run(info_iprange, pcallback):
    global plugin_callback
    plugin_callback = pcallback
    nmapper = nmap.PortScannerAsync()
    nmapper.scan(hosts=info_iprange.get('iprange'), arguments='-sP', callback=result_callback)
    pcallback.logDebug('waiting for nmap to start yielding ..')
    nmapper.wait()

