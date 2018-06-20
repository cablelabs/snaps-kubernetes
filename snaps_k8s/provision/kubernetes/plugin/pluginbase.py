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

import abc
import six
import logging
logger = logging.getLogger('plugin_base')

@six.add_metaclass(abc.ABCMeta)
class PluginBase(object):
    """Base class for example plugin .
    """
    @abc.abstractmethod
    def execute(self, data, operation):
        """
        Execute would be implemented differently for each of the given plugin.

        :param data: A dictionary with string keys and simple types as
                     values.
        :type operation: dict(str:?)
        :returns: boolean.
        """

        logger.info("\n Argument List:" + "\n data:" + str(data) +
                    "operation:" + operation)
        logger.info('exit')
