
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
