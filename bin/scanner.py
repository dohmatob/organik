#!/usr/bin/env python
from argparse import ArgumentParser
import multiprocessing
import os
import sys
import time
import math
from core import engine, targets

if __name__ == '__main__':
    old_cwd = os.getcwd()
    os.chdir(os.path.dirname(sys.argv[0]))
    rootdir=os.path.dirname(os.getcwd())
    defaultplugindir = "%s/plugins" %(rootdir)
    defaultnbworkerspercpu = 20
    defaulttimeout = -1
    _tmp = os.getcwd()
    os.chdir(old_cwd)
    parser = ArgumentParser(version="w0rkz 0f d0hm4t06 3. d0p91m4")
    parser.add_argument("--target",
                      action="append",
                      dest="target",
                      default=list(),
                      help="""specify target to scan"""
                      )
    parser.add_argument("--nbworkers",
                      dest="nbworkers",
                      default=defaultnbworkerspercpu*20,
                      help="""specify number of workers (default is %s per CPU)""" %(defaultnbworkerspercpu)
                      )
    parser.add_argument("--plugindir",
                      dest="plugindir",
                      default=defaultplugindir,
                      help="""specify directory from which to load plugins (default is production/)"""
                      )
    parser.add_argument("--quiet",
                      dest="quiet",
                      default=False,
                      action="store_true",
                      help="""turn off debug mode""",
                      )
    parser.add_argument("--donotload",
                        action="append",
                        dest="donotload",
                        default=list(),
                        help="""specify plugin to ignore""",
                        ) 
    parser.add_argument("--timeout",
                      dest="timeout",
                      default=defaulttimeout,
                      help="""specify overall timeout"""
                      )
    options = parser.parse_args()
    os.chdir(_tmp)
    os.system("mkdir -p %s/var/log" %(rootdir))
    timestamp = time.ctime().split(' ')
    if '' in timestamp:
        timestamp.remove('')
    timestamp = '-'.join(list([timestamp[2],timestamp[1],timestamp[4]]))
    logfile = "%s/var/log/scanner-%s-%s.log" %(rootdir,timestamp,os.getpid())
    k = engine.Kernel(logfile=logfile, debug=(not options.quiet), rootdir=rootdir)
    target_profile = targets.TARGET_IPRANGE(iprange=options.target)
    k.bootstrap(target_profile, 
                '%s/%s' %(rootdir,options.plugindir), 
                options.donotload, 
                nbworkers=int(options.nbworkers), 
                timeout=int(math.floor(float(options.timeout))))
