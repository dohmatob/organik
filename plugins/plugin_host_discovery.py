import nmap 
from coreutils import targets

DESCRIPTION="""Plugin does host discovery by wrapping nmap (poor; use direct ICMP pinging!!)"""
AUTHOR="""d0hm4t06 3. d0p91m4"""
AUTHOR_EMAIL="""gmdopp@gmail.com"""

def targetrule(target):
    return target.getCategory() == "TARGET_IPRANGE"

def result_callback(host, scan_data):
    try:
        if scan_data['scan'][host]['status']['state'] in list(['up']):
            if plugin_callback:
                plugin_callback.announceNewTarget(targets.TARGET_IP(ip=host))
            else:
                print '%s: up'
    except:
        pass

def run(target, pcallback):
    global plugin_callback
    plugin_callback = pcallback
    nmapper = nmap.PortScannerAsync()
    raw_target = target.get('iprange')
    if not type(raw_target) is list:
        raw_target = [raw_target]
    for item in raw_target:
        nmapper.scan(hosts=item, arguments='-sP', callback=result_callback)
    pcallback.logDebug('waiting for nmap to start yielding ..')
    nmapper.wait()

