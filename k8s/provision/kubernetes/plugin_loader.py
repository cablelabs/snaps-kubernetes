
"""
    Generic Deployment Plugin Loading framework
"""
import logging
import os
import sys
#import pluginbase
#from plugin import kargo
__author__ = '_ARICENT'

logger = logging.getLogger('plugin_operations')


class PluginLoader(object) :

    #def load(self, plugin, data, operation):
    def load(self,data, operation):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        plugin_path=dir_path+"/plugin/"
        logger.info(plugin_path)
        sys.path.insert(0, plugin_path)
        #sys.path.append(plugin_path)
        #module = __import__(plugin)
        module = __import__("kargo")
        print "*****data operation *****"
        #print plugin
        print operation
        return module.Deploy().execute(data, operation)
