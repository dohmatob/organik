from core import targets

def targetrule(target):
    pass

def run(target, pcallback):
    pcallback.announceNewTarget(targets.TARGET_IP(ip='127.0.0.1'))
