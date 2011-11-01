#!/usr/bin/env python

from argparse import ArgumentParser
import multiprocessing
import os
import sys
import time
from engine import engine, targets

if __name__ == '__main__':
    parser = ArgumentParser(version="w0rkz 0f d0hm4t06 3. d0p91m4\r\n(c) 2011")
    parser.add_argument("--target",
                      action="append",
                      dest="target",
                      default=list(),
                      help="""specify target to scan"""
                      )
    parser.add_argument("--nbworkers",
                      dest="nbworkers",
                      default=multiprocessing.cpu_count()*20,
                      help="""specify number of workers (default is 20 per CPU)"""
                      )
    parser.add_argument("--plugindir",
                      dest="plugindir",
                      default="production/",
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
    options = parser.parse_args()
    os.chdir(os.path.dirname(sys.argv[0]))
    os.system("mkdir -p var/log/")
    timestamp = time.ctime().split(' ')
    timestamp.remove('')
    timestamp = '-'.join(list([timestamp[2],timestamp[1],timestamp[4]]))
    logfile = "var/log/scanner-%s-%s.log" %(timestamp,os.getpid())
    k = engine.Kernel(logfile=logfile, debug=(not options.quiet))
    target_profile = list()
    for target in options.target:
        target_profile.append(targets.TARGET_IPRANGE(iprange=target))
    k.bootstrap(target_profile, int(options.nbworkers), options.plugindir, donotload=options.donotload)
