# * Copyright 2018 ARICENT HOLDINGS LUXEMBOURG SARL and Cable Television
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

import pluginbase
import logging
from snaps_k8s.provision.kubernetes.plugin.k8_impl import k8_utils

logger = logging.getLogger('k8')


class Deploy(pluginbase.PluginBase):
    """
    Plugin Deploy class. It should be similar across all plugins
    """

    def dummy_function(self):
        """
        dummy_function: It is a simple dummy function
        """
        pass

    def execute(self, data, operation, deploy_file):
        """
        execute: Based on imputs from user this function triggers
        releveant calls
        """
        ret = False
        if operation == "clean_k8":
            ret = k8_utils.clean_k8(data)
        elif operation == "deploy_k8":
            ret = k8_utils.execute(data, deploy_file)
        logger.info('Exit')
        return ret
