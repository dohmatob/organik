#!/usr/bin/env python
from argparse import ArgumentParser
import multiprocessing
import os
import sys
import time
import math
from coreutils import engine, targets

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
                        action="store",
                        dest="target",
                        default="",
                        help="""specify target to scan (you may specify a comma-seperated list of targets like localhost,scanme.org,www.microsoft.com)"""
                        )
    parser.add_argument("--nbworkers",
                        dest="nbworkers",
                        type=int,
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
                        action="store",
                        dest="donotload",
                        default="",
                        help="""specify plugin to ignore (you may specify a comma-seperated list of plugins like plugin_1.py, plugin_ORC.py,plugin_HELL.py)""",
                        ) 
    parser.add_argument("--timeout",
                        dest="timeout",
                        type=int,
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
    target_profile = targets.TARGET_IPRANGE(iprange=options.target.split(","))
    k.bootstrap(target_profile, 
                '%s/%s' %(rootdir,options.plugindir), 
                options.donotload, 
                nbworkers=options.nbworkers, 
                timeout=options.timeout)

