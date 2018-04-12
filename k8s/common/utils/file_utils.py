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

import os
import urllib2
import logging

import yaml


"""
Utilities for file handling functions
"""

logger = logging.getLogger('file_utils')



def read_yaml(config_file_path):
    """
    Reads the yaml file and returns a dictionary object
    :param config_file_path: The file path of config in yaml
    :return: a dictionary
    """
    logger.debug('Loading configuration file - ' + config_file_path)
    with open(config_file_path) as config_file:
        config = yaml.safe_load(config_file)
        logger.info('Configuration Loaded')
    config_file.close()
    logger.info('Closing config file')
    return config
