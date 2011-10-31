import os
import sys
import glob
import traceback
import signal
import time
import threading
import multiprocessing

AUTHOR="""d0hm4t06 3. d0p91m4"""

def pretty_time():
    t = time.ctime().split(" ")
    return "-".join(list([t[3], t[0], t[2], t[1], t[4]]))

class PluginCallback:
    """
    Callback used by plugins to feedback to kernel, or invoke dedicated back-end functionality (logging, reporting, etc.)
    """
    def __init__(self, plugin_name, 
                 logfile=None,
                 feedback_method=None, 
                 reportVuln_method=None,
                 reportInfo_method=None):
        self._plugin_name = plugin_name
        self._logfile = logfile
        self._feedback_method = feedback_method
        self._reportVuln_method = reportVuln_method
        self._reportInfo_method = reportInfo_method

    def log(self, msg):
        formatted_msg = "%s %s" %(pretty_time(), msg)
        print formatted_msg
        if self._logfile:
            try:
                fh = open (self._logfile, 'a')
                fh.write(formatted_msg + "\r\n")
                fh.close()
            except:
                self.logDebug("WARNING: caught exception while writing logfile %s (see traceback below)\n%s" %(self._logfile, traceback.format_exc()))

    def logDebug(self, msg):
        self.log("[%s] -DEBUG- %s" %(self._plugin_name, msg))
    
    def logInfo(self, msg):
        self.log("[%s] -INFO- %s" %(self._plugin_name, msg))

    def feedback(self, target):
        self.logDebug("new target %s" %(target.__str__()))
        self._feedback_method(target)
        
    def reportVuln(self, vid, raw_output):
        self._reportVuln_method(self._plugin_name, vid, raw_output)

    def reportInfo(self, info):
        self._reportInfo_method(self._plugin_name, info)
        

class Kernel:
    """
    Brainz!
    """
    _MANAGER = multiprocessing.Manager()
    _WORKER_MODEL = multiprocessing.Process
    _PLUGIN_API_METHODS = list(["targetrule", "run"])

    def __init__(self, logfile=None):
        self._logfile = logfile
        self._taskqueue = multiprocessing.JoinableQueue()
        self._target_profile = self._MANAGER.dict()
        self._plugins = dict()
        try:
            open (self._logfile, 'w').close()
        except:
            self.logDebug("WARNING: caught exception while openning logfile %s (see traceback below)\n%s" %(self._logfile, traceback.format_exc()))
            self._logfile = None

    def log(self, msg):
        """
        Just log
        """
        formatted_msg = "%s %s" %(pretty_time(), msg)
        print formatted_msg
        if self._logfile:
            try:
                fh = open (self._logfile, 'a')
                fh.write(formatted_msg + "\r\n")
                fh.close()
            except:
                self.logDebug("WARNING: caught exception while writing logfile %s (see traceback below)\n%s" %(self._logfile, traceback.format_exc()))

    def logDebug(self, msg):
        """
        Log debug verbose
        """
        self.log("[kernel] -DEBUG- %s" %(msg))
    
    def logInfo(self, msg):
        """
        Log information
        """
        self.log("[kernel] -INFO- %s" %(msg))

    def loadPlugin(self, plugin_name):
        """
        Load specified plugin
        """
        try:
            self.logDebug("loadin: %s" %(plugin_name))
            self._plugins[plugin_name] = __import__(plugin_name)
            for method in self._PLUGIN_API_METHODS:
                if not method in self._plugins[plugin_name].__dict__:
                    self.logDebug("WARNING: %s.py doesn't implement method '%s' of the plugin API; plugin will not be loaded" %(plugin_name, method))
                    break
        except:
            self.logDebug("WARNING: caught exception while loading %s (see traceback below); plugin will not be loaded\nq" %(plugin_name, traceback.format_exc()))
    
    def loadPlugins(self, plugin_dir, plugin_regexp="plugin_*.py"):
        """
        Load specified plugins from given plugin directory
        """
        if not os.path.isdir(plugin_dir):
            self.logDebug("WARNING: can't access plugin directory '%s'" %(plugin_dir))
            return
        plugin_dir_abspath = os.path.abspath(plugin_dir)
        sys.path.append(plugin_dir_abspath)
        loaded_plugins = len(self._plugins)
        plugins_to_load = glob.glob(plugin_dir_abspath + "/" + plugin_regexp)
        self.logDebug("plugins to load: %s" %(len(plugins_to_load)))
        for item in plugins_to_load:
            plugin_name = os.path.basename(item).replace(".py", "")
            self.loadPlugin(plugin_name)
        self.logDebug("loaded: %s plugins out of %s" %(len(self._plugins) - loaded_plugins, len(plugins_to_load)))
        
    def reportVuln(self, plugin_name, vid, raw_output):
        """
        Report vuln to front-end
        """
        pass # XXX TODO: code
        

    def reportInfo(self, plugin_name, info):
        """
        Report Info to fronr-end
        """
        pass # XXX TODO: code
        

    def targetExists(self, target):
        """
        Check whether given target is in kernel-maintained target profile
        """
        if not target.getCategory() in self._target_profile:
            return False
        return [t for t in self._target_profile[target.getCategory()] if t.getContent() == target.getContent()]

    def addTarget(self, target):
        """
        Add new target to kernel-maintained target profile
        """
        category = target.getCategory()
        if category in self._target_profile:
            self._target_profile[category].append(target)
        else:
            self._target_profile[category] = list([target])

    def feedback(self, target):
        """
        Feed-back discovery into kenel-maintained target profile
        """
        if self.targetExists(target):
            self.logDebug("WARNING: %s already exists in profile; ignoring" %(target.__str__()))
            return
        self.addTarget(target)
        self.dispatch(target)

    def dispatch(self, target):
        """
        Delegates incoming target profile to all specialized plugins
        """
        for plugin in self._plugins.values():
            if plugin.targetrule(target):
                task = (plugin.__name__,target,)
                self._taskqueue.put(task)

    def runPlugin(self, plugin_name, target):
        """
        Runs plugin in 'chroot jail'
        """
        self.logDebug("running %s on %s" %(plugin_name, target.__str__()))
        try:
            pcallback = PluginCallback(plugin_name=plugin_name, 
                                       logfile=self._logfile,
                                       feedback_method=self.feedback, 
                                       reportVuln_method=self.reportVuln, 
                                       reportInfo_method=self.reportInfo)
            self._plugins[plugin_name].run(target, pcallback)
            self.logDebug("done running %s on %s" %(plugin_name, target.__str__()))
        except:
            self.logDebug("WARNING: caught exception while running %s on %s (see traceback below)\n%s" %(plugin_name, target.__str__(), traceback.format_exc()))
            
    def signalHandler(self, signum, frame):
        """
        The kernel's signal handler
        """
        if signum == signal.SIGINT:
            # self.logDebug("caught SIGINT")
            self.finish(signal.SIGTERM)
        else:
            self.logDebug("WARNING: unhandled signum %s" %(signum))

    def registerSignals(self):
        """
        Register pertinent signals (SIGINT, etc.) against the kernel's signal handler
        """
        self.logDebug("registering signals")
        signal.signal(signal.SIGINT, self.signalHandler)

    def devil(self):
        """
        Payload for kernel workers
        """
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        while True:
            try:
                plugin_name, target = self._taskqueue.get()
            except:
                self.logDebug("WARNING: caught exception while fetching new task (see traceback below)\n%s" %(traceback.format_exc()))
                continue # XXX break ?
            self.runPlugin(plugin_name, target)
            self._taskqueue.task_done()

    def start(self, plugin_dir, target_profile):
        """
        Start kernel
        """
        self.logDebug("starting")
        self.registerSignals()
        self.logDebug("pid: %s" %(os.getpid()))
        self.logDebug("logfile: %s" %(self._logfile))
        self.logDebug("plugin directory: %s" %(plugin_dir))
        self.loadPlugins(plugin_dir)
        self.feedback(target_profile)

    def finish(self, signum=signal.SIGTERM):
        """
        Finish kernel and all workers thereof
        """
        # self.logDebug("finishing")
        os.kill(0, signum)

    def serve(self, nbworkers):
        """
        Server task queue to workers
        """
        self.logDebug("deploying %s workers on task queue" %(nbworkers))
        for z in xrange(nbworkers):
            worker = self._WORKER_MODEL(target=self.devil,)
            worker.start()
        self._taskqueue.join() # our only business is to complete all tasks; so no need 'join' on workers if we're done !!!
        
    def bootstrap(self, plugin_dir, target, nbworkers=1):
        """
        Bootstrap kernel 
        """
        self.logDebug("bootstrapped")
        self.start(plugin_dir, target)
        self.serve(nbworkers)
        self.finish()
        

if __name__ == "__main__":
    print "w0rkz 0f %s\r\n(c) %s - 2011" %(AUTHOR, AUTHOR)
