import unittest
import multiprocessing
import os
import sys
import glob
import traceback
import signal
import time
from core import targets

__author__ = 'dohmatob E. dopgima'

def pretty_time():
    """
    Returns current time in the form 15:57:00-Thu-3-Nov-2011
    """
    t = time.ctime().split(' ')
    if '' in t:
        t.remove('')
    return '-'.join([t[3],t[0],t[2],t[1],t[4]])


class PluginCallback:
    """
    Callback used by plugins to feedback into kernel
    """
    def __init__(self, 
                 plugin_name,
                 logfile=None, 
                 announceNewTarget_method=None, 
                 reportVuln_method=None, 
                 reportInfo_method=None,
                 debug=True):
        self._plugin_name = plugin_name
        self._logfile = logfile
        self._announceNewTarget_method = announceNewTarget_method
        self._reportVuln_method = reportVuln_method
        self._reportInfo_method = reportInfo_method
        self._debug = debug

    def log(self, msg):
        """
        /!\ Should never be invoked directly !!!
        """
        formatted_msg = '%s [%s] %s' %(pretty_time(),self._plugin_name,msg)
        print formatted_msg
        if self._logfile:
            try:
                fh = open(self._logfile, 'a')
                fh.write(formatted_msg + '\r\n')
                fh.close()
            except:
                self.logWarning("caught exception while writing logfile %s (see traceback below)\n%s" %(self._logfile,traceback.format_exc()))

    def logDebug(self, msg):
        """
        Logs info pertinent for debugging kernel execution
        """
        if not self._debug:
            return
        formatted_msg = '-DEBUG- %s' %(msg)
        self.log(formatted_msg)

    def logWarning(self, msg):
        """
        Logs warning
        """
        formatted_msg = '-WARNING- %s' %(msg)
        self.log(formatted_msg)

    def logInfo(self, msg):
        """
        Logs pertinent information about discoveries/findings being made
        """
        formatted_msg = '-INFO- %s' %(msg)
        self.log(formatted_msg)

    def announceNewTarget(self, target):
        """
        Announces new target (a plugin invokes this method when they have found a new 
        target/'hole', but for which they are 'unqualified' to further explore; this 
        way, more specialized plugins are invoked to explore the announced target
        """
        if self._announceNewTarget_method:
            self.logDebug('announcing new %s' %(target.__str__()))
            self._announceNewTarget_method(target)

    def reportVuln(self, vid, raw_output):
        """
        Invoked to report identified vulnerability to front-end
        """
        if self._reportVuln_method:
            self._reportVuln_method(vid, raw_output)

    def reportInfo(self, info):
        """
        Invoked to report info to front-end
        """
        if self._reportInfo_method:
            self._reportInfo_method(info)


class Kernel:
    """
    Brainz!
    """
    _MANAGER = multiprocessing.Manager()
    _WORKER_MODEL = multiprocessing.Process
    _PLUGIN_API_METHODS = ['targetrule','run',]

    def __init__(self, 
                 logfile=None, 
                 debug=True,
                 rootdir=None):
        self._logfile = logfile
        self._debug = debug
        self._plugins = dict()
        self._target_profile = self._MANAGER.dict()
        self._task_queue = multiprocessing.JoinableQueue()
        self._workers = list()
        self._pid = os.getpid()
        if not rootdir is None:
            if not os.path.isdir(rootdir):
                self.logDebug("cannot access root directory '%s' (does directory exist?)" %(rootdir))
                return
            self._rootdir = os.path.abspath(rootdir)
        else:
            self._rootdir = os.getcwd()
        if not logfile is None:
            try:
                open(logfile, 'w').close()
            except:
                self._logfile = None
                self.logWarning("couldn't open logfile %s for reading (see traceback below); loggin will be disabled\n%s" %(logfile,traceback.format_exc()))

    def log(self, msg):
        formatted_msg = '%s [kernel] %s' %(pretty_time(),msg)
        print formatted_msg
        if self._logfile:
            try:
                fh = open(self._logfile, 'a')
                fh.write(formatted_msg + '\r\n')
                fh.close()
            except:
                self.logWarning("caught exception while writing logfile %s (see traceback below)\n%s" %(self._logfile,traceback.format_exc()))

    def logDebug(self, msg):
        if not self._debug:
            return
        formatted_msg = '-DEBUG- %s' %(msg)
        self.log(formatted_msg)

    def logWarning(self, msg):
        formatted_msg = '-WARNING- %s' %(msg)
        self.log(formatted_msg)

    def logInfo(self, msg):
        formatted_msg = '-INFO- %s' %(msg)
        self.log(formatted_msg)

    def loadPlugin(self, plugin_name):
        """
        Loads given plugin
        """
        try:
            self.logDebug("loadin: %s" %(plugin_name))
            plugin = __import__(plugin_name)
            # check whether plugin implements API
            for method in self._PLUGIN_API_METHODS:
                if not method in plugin.__dict__:
                    self.logDebug("%s doesn't implement method '%s' of the PLUGIN API; plugin will not be loaded" %(plugin_name,method))
                    return
        except:
            self.logDebug("caught exception while loading %s (see traceback below)\n%s" %(plugin_name,traceback.format_exc()))
            return
        # load plugin into kernel
        plugin.ROOTDIR = self._rootdir
        self._plugins[plugin_name] = plugin

    def loadPlugins(self, plugin_dir, plugin_wildcat='plugin_*.py', donotload=list()):
        """
        Loads all plugins from specified directory, all except an option list of plugins
        """
        if not os.path.isdir(plugin_dir):
            self.logWarning("can't access plugin directory '%s' (does directory exist)" %(plugin_dir))
            return
        plugin_dir = os.path.abspath(plugin_dir)
        self.logDebug("plugin directory: %s" %(plugin_dir))
        plugins_to_load = [os.path.basename(item).replace('.py', '') for item in glob.glob('%s/%s' %(plugin_dir,plugin_wildcat)) if not os.path.basename(item) in donotload]
        self.logDebug('plugins to load: %s' %(len(plugins_to_load)))
        sys.path.append(plugin_dir)
        map(lambda plugin_name: self.loadPlugin(plugin_name), plugins_to_load)
        self.logDebug('loaded: %s plugins out of %s' %(len(self._plugins),len(plugins_to_load)))

    def runPlugin(self, plugin_name, target):
        """
        Runs named plugin on target
        """
        pcallback = PluginCallback(plugin_name,
                                   logfile=self._logfile,
                                   announceNewTarget_method=self.announceNewTarget,
                                   reportVuln_method=self.reportVuln,
                                   reportInfo_method=self.reportInfo,
                                   debug=self._debug,
                                   )
        try:
            self.logDebug("running %s on %s" %(plugin_name, target.__str__()))
            self._plugins[plugin_name].run(target, pcallback)
            self.logDebug("done running %s on %s" %(plugin_name, target.__str__()))
        except:
            self.logWarning("caught exception while running %s on %s (see traceback below)\n%s" %(plugin_name, target.__str__(), traceback.format_exc()))
            
    def targetExists(self, target):
        """
        Checks whether given target was already announced
        """
        category = target.getCategory()
        if not category in self._target_profile:
            return False
        else:
            return [t for t in self._target_profile[category] if t.getContent() == target.getContent()]

    def addTarget(self, target):
        """
        Adjoints given target to foregoing profile
        """
        category = target.getCategory()
        if category in self._target_profile.keys():
            self._target_profile[category].append(target)
        else:
            self._target_profile[category] = [target]

    def announceNewTarget(self, target):
        if self.targetExists(target):
            self.logWarning("%s was already announced; ignoring" %(target.__str__()))
            return
        self.dispatch(target)

    def reportVuln(self, vid, raw_output):
        pass
    
    def reportInfo(self, info):
        pass

    def dispatch(self, target):
        """
        Prepare to deploy all specialized plugins on given target
        """
        self.addTarget(target)
        for plugin_name in self._plugins:
            if self._plugins[plugin_name].targetrule(target):
                newtask = (plugin_name,target)
                self.scheduleNewTask(newtask)
                
    def scheduleNewTask(self, newtask):
        self._task_queue.put(newtask)

    def signalHandler(self, signum, frame):
        """
        Handler for signals trapped herein
        """
        if os.getpid() != self._pid:
            return
        if signum == signal.SIGINT:
            self.logDebug("caught SIGINT; preparing to abort")
            self.finish()
        elif signum == signal.SIGALRM:
            self.logDebug("caught SIGALRM; preparing to abort")
            self.finish()
        else:
            self.logWarning("unhandled signum: %s" %(signum))

    def devil(self):
        """
        Dynamically polls kernel task queue
        """
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
        while True:
            try:
                plugin_name, target = self._task_queue.get()
            except:
                self.logWarning("caught exception while fetching new task (see traceback below)\n%s" %(traceback.format_exc()))
                break
            self.runPlugin(plugin_name, target)
            self._task_queue.task_done()

    def finish(self, signum=signal.SIGTERM):
        """
        Brings down all kernel workers, and then exits clean
        """
        if not self._task_queue._closed:
            self._task_queue.close()
        self.logDebug("terminating")
        try:
            os.kill(0, signum)
        except:
            self.logDebug("caught exception while sending signum %s to process group (see traceback below)\n%s" %(traceback.format_exc()))
            os.kill(0, signal.SIGKILL)

    def serve(self, nbworkers):
        """
        Forever, serves work, until no more there is
        """
        for z in xrange(nbworkers):
            worker = self._WORKER_MODEL(target=self.devil,)
            worker.start()
            self._workers.append(worker)
        self._task_queue.join()
        self.finish()

    def bootstrap(self, target_profile, plugin_dir, donotload=list(), nbworkers=multiprocessing.cpu_count()*20, timeout=0):
        """
        Kick-off !
        """
        if not self._debug:
            self.logInfo("entering silent mode; no debug output will be produced")
        self.logDebug("bootstrapped")
        self.logDebug("pid: %s" %(self._pid))
        self.logDebug("root dir: %s" %(self._rootdir))
        self.logDebug("logfile: %s" %(os.path.abspath(self._logfile)))
        self.loadPlugins(plugin_dir, donotload=donotload)
        self.logDebug("setting trap for SIGINT")
        signal.signal(signal.SIGINT, self.signalHandler)
        if timeout > 0:
            self.logDebug("setting trap for SIGALRM (timeout=%ss)" %(timeout))
            signal.signal(signal.SIGALRM, self.signalHandler)
            signal.alarm(timeout)
        self.announceNewTarget(target_profile)
        self.serve(nbworkers)

class KernelTest(unittest.TestCase):
    # def test_init(self):
    #     k = Kernel()
    #     self.assertFalse(k._plugins)
        
    # def test_loadPlugins(self):
    #     k = Kernel()
    #     plugin_dir = 'dummy_plugins/'
    #     k.loadPlugins(plugin_dir)
    #     k.runPlugin('plugin_dummy1', None)
    #     self.assertEqual(len(k._target_profile["TARGET_IP"]), 1)
    #     k.runPlugin('plugin_dummy2', None)
    #     self.assertEqual(len(k._target_profile["TARGET_IP"]), 1)
    #     k.runPlugin('plugin_dummy3', None)
    #     self.assertEqual(len(k._target_profile["TARGET_IP"]), 2)

    def test_bootstrap(self):
        k = Kernel()
        plugin_dir = "test_plugins/"
        k.bootstrap([targets.TARGET_IP(ip='127.0.0.1')], plugin_dir)


if __name__ == '__main__':
    unittest.main()
