#!/usr/bin/env python

from optparse import OptionParser
import multiprocessing
import os
import sys
import kernel
import targets

if __name__ == '__main__':
    parser = OptionParser(version="w0rkz 0f d0hm4t06 3. d0p91m4\r\n(c) 2011")
    parser.add_option("--target",
                      action="store",
                      dest="target",
                      default="127.0.0.1",
                      help="""specify target to scan"""
                      )
    parser.add_option("--nbworkers",
                      dest="nbworkers",
                      default=multiprocessing.cpu_count()*20,
                      help="""specify number of workers"""
                      )
    parser.add_option("--plugindir",
                      dest="plugindir",
                      default="production",
                      help="""specify directory from which to load plugins"""
                      )
    options,_ = parser.parse_args()
    os.chdir(os.path.dirname(sys.argv[0]))
    k = kernel.Kernel(logfile='/tmp/kernel.log')
    k.bootstrap(options.plugindir, targets.TARGET_IPRANGE(iprange=options.target), int(options.nbworkers))
