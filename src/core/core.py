import unittest
import multiprocessing
import os
import sys
import glob
import traceback

class Kernel:
    _MANAGER = multiprocessing.Manager()
    _PLUGIN_API_METHODS = ['targetrule','run',]

    def __init__(self):
        self._plugins = dict()
        self._target_profile = self._MANAGER.dict()

    def logDebug(self, msg):
        print msg

    def loadPlugin(self, plugin_name):
        try:
            self._plugins[plugin_name] = __import__(plugin_name)
            for method in self._PLUGIN_API_METHODS:
                if not method in self._plugins[plugin_name].__dict__:
                    self.logDebug("%s doesn't implement method '%s' of the PLUGIN API; plugin will not be loaded" %(plugin_name,method))
        except:
            self.logDebug("caught exception while loading %s (see traceback below)\n%s" %(plugin_name,traceback.format_exc()))

    def loadPlugins(self, plugin_dir, plugin_regexp='plugin_*.py', donotload=list()):
        if not os.path.isdir(plugin_dir):
            self.logWarning("can't access plugin directory '%s' (does directory exist)")
            return
        plugin_dir = os.path.abspath(plugin_dir)
        plugins_to_load = [os.path.basename(item).replace('.py', '') for item in glob.glob(plugin_dir + '/' + plugin_regexp) if not os.path.basename(item) in donotload]
        self.logDebug('plugins to load: %s' %(len(plugins_to_load)))
        sys.path.append(plugin_dir)
        map(lambda plugin_name: self.loadPlugin(plugin_name), plugins_to_load)
        self.logDebug('loaded: %s plugins out of %s' %(len(self._plugins),len(plugins_to_load)))


class KernelTest(unittest.TestCase):
    def test_init(self):
        k = Kernel()
        self.assertFalse(k._plugins)
        
    def test_loadPlugins(self):
        k = Kernel()
        plugin_dir = 'test_plugins/'
        k.loadPlugins(plugin_dir)
        k.runPlugin('plugin_dummy1.py', None)
        self.assertEqual(len(self._target_profile), 1)
        k.runPlugin('plugin_dumm2.py', None)
        self.assertEqual(len(self._target_profile), 1)
        k.runPlugin('plugin_dumm3.py', None)
        self.assertEqual(len(self._target_profile), 3)


if __name__ == '__main__':
    unittest.main()
