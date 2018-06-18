###########################################################################
# Copyright 2018 ARICENT HOLDINGS LUXEMBOURG SARL. and
# Cable Television Laboratories, Inc.
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
###########################################################################


"""
    Generic Deployment Plugin Loading framework
"""
import logging
import sys
import os

__author__ = '_ARICENT'

logger = logging.getLogger('plugin_operations')

class PluginLoader(object):
    """
    Plugin Loader class. It should be similar across all plugins
    """
    def load(self, data, operation, deploy_file):
        """
        load: This functions triggers deployment
        """
        logger.info("\n Argument List:" + "\n data:" + str(data) +
                    "\n operation:" + operation  + "\n deploy_file:" +
                    deploy_file)

        dir_path = os.path.dirname(os.path.realpath(__file__))
        plugin_path = dir_path + "/plugin/"
        logger.info(plugin_path)
        sys.path.insert(0, plugin_path)
        kube_mod = __import__("kubespray")
        logger.info('Data operation %s', operation)
        logger.info('Exit')

        return kube_mod.Deploy().execute(data, operation, deploy_file)
