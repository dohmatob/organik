#!/usr/bin/env python
import os
import sys
import signal
import glob
import traceback
import multiprocessing
import time
import unittest
import targets
import termcolor

def pretty_time():
    t_var = time.ctime().split(' ')
    return t_var[3] + '-' + t_var[0] + '-' + t_var[2] + '-' + t_var[1] + '-' + t_var[4]


class KernelTask:
    """ 
    Encapsulates a kernel task
    """
    def __init__(self, plugin_name, target):
        self._settings = dict()
        self.set('plugin_name', plugin_name)
        self.set('target', target)

    def set(self, param, value):
        self._settings[param] = value

    def get(self, param):
        return self._settings[param]

    def __str__(self):
        return '(%s, %s)' %(self._settings['plugin_name'], self._settings['target'].__str__())


class KernelWorker(multiprocessing.Process):
    """
    Extensible kernel worker model
    """
    def daemonize(self):
        """
        Daemonic workers can't have children!!!
        """
        self.daemon = True 


class PluginCallback:
    """
    Encapsulates handlers (for logging, reporting, publishing, etc.) invoked by plugins to communicate with the kernel
    """
    def __init__(self, plugin_name, logfile=None, publish_method=None, reportVuln_method=None):
        self._plugin_name = plugin_name
        self._logfile = logfile
        self._publish_method = publish_method
        self._reportVuln_method = reportVuln_method

    def publish(self, target):
        """
        Publish information, so kernel and other plugins can benefit too
        """
        self.log('publishing %s' %(target.__str__()), debug=True)
        self._publish_method(target)

    def reportVuln(self, vid, raw_output):
        """
        Report vulnerability with given vid (vulnerability id)
        """
        self._reportVuln_method(vid, raw_output)

    def log(self, msg, debug=False):
        """
        Log message
        """
        comment = "INFO"
        if debug:
            comment = "DEBUG" 
        formatted_msg = '%s [%s] -%s- %s' %(pretty_time(), self._plugin_name, comment, msg)
        print formatted_msg
        if self._logfile:
            fh = open(self._logfile, 'a')
            fh.write(formatted_msg + '\r\n')
            fh.close()


class Kernel:
    """
    Brain
    """
    def __init__(self, logfile=None):
        self._env = dict()
        self.setEnv('plugins', dict()) # contains plugins loaded by the kenel
        self.setEnv('info_pool', multiprocessing.Manager().dict()) # maintains pool of incoming information
        self.setEnv('task_queue', multiprocessing.JoinableQueue()) # queue of kernel tasks dynamically dispatched by kernel
        self.setEnv('workers', list()) # list of kernel workers
        self.setEnv('logfile', logfile) # logging ?
        if logfile:
            try:
                fh = open(logfile, 'w')
                fh.close()
            except:
                print 'WARNING: caught unhandled exception while openning logfile'
                print traceback.format_exc()
                self.setEnv('logfile', None)

    def setEnv(self, param, value):
        self._env[param] = value

    def getEnv(self, param):
        return self._env[param]

    def log(self, msg, debug=False):
        """
        Log message with given debug level
        """
        comment = "INFO"
        if debug:
            comment = "DEBUG"
        formatted_msg = '%s [kernel] -%s- %s' %(pretty_time(), comment, msg)
        print formatted_msg
        if self._env['logfile']:
            try:
                fh = open(self._env['logfile'], 'a')
                fh.write(formatted_msg + '\r\n')
                fh.close()
            except:
                print 'caught unhandled exception while openning logfile'
                print traceback.format_exc()
                self.setEnv('logfile', None)            

    def loadPlugin(self, plugin_name):
        """
        Load plugin plugin_name
        """
        self.log('loading: %s' %(plugin_name), debug=True)
        self._env['plugins'][plugin_name] = __import__(plugin_name)
        plugin_attrs = dir(self._env['plugins'][plugin_name])
        for method in list(['targetrule', 'run']):
            if not method in plugin_attrs:
                self.log("WARNING: %s doesn't implement method '%s' of the API (plugin will not be loaded)" %(plugin_name, method), debug=True)
                del self._env['plugins'][plugin_name]
                return

    def loadPlugins(self, plugin_dir, plugin_regexp='plugin_*.py'):
        """
        Load all plugins plugin_*.py from plugin_dir
        """
        if not os.path.isdir(plugin_dir):
            self.log("WARNING: cannot access plugin directory '%s' (does directory exist?)" %(plugin_dir), debug=True)
            return
        abs_plugin_dir = os.path.abspath(plugin_dir)
        sys.path.append(abs_plugin_dir)
        loaded_plugins = len(self._env['plugins'])
        plugins_to_load = glob.glob(abs_plugin_dir + '/' + plugin_regexp)
        self.log('plugins to load: %s' %(len(plugins_to_load)), debug=True)
        for item in plugins_to_load:
            plugin_name = os.path.basename(item).replace('.py', '')
            try:
                self.loadPlugin(plugin_name)
            except:
                self.log("WARNING: caught unhandled exception while loading %s (see tb below)\n%s" %(plugin_name, traceback.format_exc()), debug=True)
        self.log("loaded %s plugins from %s" %(len(self._env['plugins']) - loaded_plugins, abs_plugin_dir), debug=True)

    def published(self, target):
        """
        Returns True if target has already been published; False otherwise
        """
        if not target.getCategory() in self._env['info_pool'].keys():
            return False
        return [j for j in self._env['info_pool'][target.getCategory()] if j.getContent() == target.getContent()]

    def addInfo(self, info):
        info_name = info.getCategory()
        if info_name in self._env['info_pool']:
            self._env['info_pool'][info_name].append(info)
        else:
            self._env['info_pool'][info_name] = list([info])
        
    def publish(self, target, tag=False):
        if tag:
            self.log('publishing %s' %(target.__str__()), debug=True)
        if self.published(target):
            self.log('ignoring duplicate publication, %s has already been published' %(target.__str__()), debug=True)
            return
        self.addInfo(target)
        self.dispatch(target)

    def dispatch(self, target):
        for plugin_name in self._env['plugins']:
            try:
                if self._env['plugins'][plugin_name].targetrule(target):
                    task = KernelTask(plugin_name, target)
                    self._env['task_queue'].put(task)
            except:
                self.log("WARNING: caught unhandled exception while reading the requirements of plugin '%s' (see tb below)\n%s" %(plugin_name, traceback.format_exc()))
                self.log("WARNING: plugin will be disabled", debug=True)
                del self._env['plugins'][plugin_name]

    def reportVuln(self, vid, raw_output):
        pass

    def runPlugin(self, plugin_name, target):
        self.log("running %s on %s" %(plugin_name, target.__str__()), debug=True)
        pcallback = PluginCallback(plugin_name, logfile=self._env['logfile'], publish_method=self.publish, reportVuln_method=self.reportVuln)
        self._env['plugins'][plugin_name].run(target, pcallback)
        self.log("done running %s on %s" %(plugin_name, target.__str__()), debug=True)

    def grabTask(self):
        try:
            return self._env['task_queue'].get()
        except:
            self.log('WARNING: caught unhandled exception while fetching task from task queue (see tb below)\n%s' %(traceback.format_exc()), debug=True)

    def executeTask(self, task):
        try:
            self.runPlugin(task.get('plugin_name'), task.get('target'))
        except:
            self.log('WARNING: caught unhandled exception while executing task %s (see tb below)\n%s' %(task.__str__(), traceback.format_exc()), debug=True)            
    
    def work(self):
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        while True:
            task = self.grabTask()
            self.executeTask(task)
            self._env['task_queue'].task_done()

    def serve(self, nbworkers):
        self.log('deploying %s workers on task queue ..' %(nbworkers), debug=True)
        for z in xrange(nbworkers):
            worker = KernelWorker(target=self.work)
            worker.start()
            self._env['workers'].append(worker)
        self._env['task_queue'].join()

    def signalHandler(self, signum, frame):
        if signum == signal.SIGINT:
            self.log("recv'd SIGINT", debug=True)
            self.finish()
        else:
            self.log('unhandled signum: %s; shutting down' %(signum), debug=True)
            self.finish()

    def registerSignalHandlers(self):
        self.log('registering signal handlers', debug=True)
        signal.signal(signal.SIGINT, self.signalHandler)

    def start(self, plugin_dir):
        self.log('starting', debug=True)
        self.registerSignalHandlers()
        if self._env['logfile']:
            self.log('logfile: %s' %(os.path.abspath(self._env['logfile'])), debug=True)
        self.log('plugin directory: %s' %(plugin_dir), debug=True)
        self.loadPlugins(plugin_dir)
   
    def stop(self, stop_signal):
        self.log('stopping', debug=True)
        os.kill(0, stop_signal)

    def finish(self):
        self.log('finishing', debug=True)
        self.stop(signal.SIGTERM)

    def bootstrap(self, plugin_dir, target_profile, nbworkers=multiprocessing.cpu_count()*20):
        self.log('bootstrapped', debug=True)
        self.start(plugin_dir)
        self.publish(target_profile, tag=True)
        self.serve(nbworkers)
        self.finish()


class KernelTest(unittest.TestCase):
    def test_init(self):
        k = Kernel()
        self.assertFalse(k.getEnv('plugins'))

    def test_loadPlugins(self):
        k = Kernel()
        plugin_dir = 'test_plugins'
        k.loadPlugins(plugin_dir)
        self.assertTrue(type(k.getEnv('plugins')['plugin_1']) is type(kernel_info))


if __name__ == '__main__':
    if os.environ.has_key('TEST'):
        unittest.main()
    k = Kernel(logfile='/tmp/kernel.log')
    k.bootstrap("test_plugins/", targets.TARGET_IPRANGE(iprange=sys.argv[1]), int(sys.argv[2]))

    
