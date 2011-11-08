from core import targets

def targetrule(target):
    return target.getCategory() == 'TARGET_IP'

def run(target, pcallback):
    pcallback.announceNewTarget(targets.TARGET_IP(ip='127.0.0.1'))
