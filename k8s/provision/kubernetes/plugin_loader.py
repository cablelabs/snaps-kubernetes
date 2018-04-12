#* Copyright 2018 ARICENT HOLDINGS LUXEMBOURG SARL and Cable Television
# Laboratories, Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This script is responsible for deploying Aricent_Iaas environments and
# Kubernetes Services

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
