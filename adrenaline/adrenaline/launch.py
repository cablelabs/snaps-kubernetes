# Copyright 2018 ARICENT HOLDINGS LUXEMBOURG SARL and Cable Television
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
import argparse
import logging

import os
import sys

from ruamel import yaml
from jinja2 import Environment, FileSystemLoader
from snaps import file_utils
from snaps_k8s.common.utils import validation_utils
from snaps_k8s.common.utils import config_utils as k8s_config_utils

import adrenaline.deployment.boot.deployer as boot_deployer
import adrenaline.deployment.kubernetes.deployer as k8s_deployer
from adrenaline.deployment import config_utils

__author__ = 'spisarski'

logger = logging.getLogger('adrenaline_launcher')

ARG_NOT_SET = "argument not set"


def __launch(task, boot_tmplt_file, hb_conf_file, env_file,
             os_env_file):
    """
    Deploys Adrenaline
    :param task: the task to perform
    :param boot_tmplt_file: the path to the snaps-boot template config file
    :param hb_conf_file: the path to the adrenaline configuration
                             template file
    :param env_file: the Jinga2 environment file to apply against the
                     boot_tmplt_filename and k8s_tmplt_filename
    :param os_env_file: if environment is on OpenStack, this file is required
                        for rebooting nodes
    :raises Exception - exceptions can be raised
    """
    boot_conf, hb_conf, k8s_conf = __generate_confs(
        boot_tmplt_file, hb_conf_file, env_file)

    if task.startswith('deploy'):
        logger.info('Starting Adrenaline boot process')
        user = hb_conf['node_info']['user']

        if task.endswith('all') or task.endswith('boot'):
            logger.info('Starting Adrenaline boot process')
            boot_timeout = hb_conf['build_info']['reboot_timeout']
            boot_deployer.deploy(
                boot_conf, hb_conf, user, os_env_file, boot_timeout)
            logger.info('Completed Adrenaline boot process')

        if task.endswith('all') or task.endswith('k8s'):
            k8s_conf_str = yaml.dump(k8s_conf, Dumper=yaml.RoundTripDumper)
            proj_name = k8s_config_utils.get_project_name(k8s_conf)
            file_utils.save_string_to_file(
                k8s_conf_str, '/tmp/deployment-{}.yaml'.format(proj_name))
            logger.debug('Deploying k8s - %s', hb_conf)
            logger.info('Starting Kubernetes deployment')
            k8s_deployer.deploy(k8s_conf, user)
            logger.info('Completed Kubernetes deployment')
    else:
        logger.info('Starting Adrenaline cleanup')
        if task.endswith('all') or task.endswith('k8s'):
            try:
                k8s_deployer.undeploy(k8s_conf)
            except:
                pass

        if task.endswith('all') or task.endswith('boot'):
            try:
                boot_deployer.undeploy(boot_conf)
            except:
                pass


def __generate_confs(boot_tmplt_file, hb_conf_file, env_file):
    """
    Returns a tuple 3 respectively: boot_conf, hb_conf, k8s_conf
    :param boot_tmplt_file: the path to the snaps-boot template config file
    :param hb_conf_file: the path to the adrenaline configuration
    :param env_file: the Jinga2 environment file to apply against the
                     boot_tmplt_filename and k8s_tmplt_filename
    :return: tuple3 dictionaries
    """
    logger.info('Adrenaline setting up boot and k8s config')
    if env_file:
        env = Environment(loader=FileSystemLoader(
            searchpath=os.path.dirname(hb_conf_file)))
        hb_tmplt = env.get_template(os.path.basename(hb_conf_file))

        env_dict = file_utils.read_yaml(env_file)
        hb_output = hb_tmplt.render(**env_dict)
        hb_conf = yaml.safe_load(hb_output)
    else:
        hb_conf = file_utils.read_yaml(hb_conf_file)

    if env_file:
        # Apply env_file/substitution file to template
        env = Environment(loader=FileSystemLoader(
            searchpath=os.path.dirname(boot_tmplt_file)))
        boot_tmplt = env.get_template(os.path.basename(boot_tmplt_file))

        env_dict = file_utils.read_yaml(env_file)
        boot_output = boot_tmplt.render(**env_dict)
        boot_conf = yaml.safe_load(boot_output)
    else:
        with open(boot_tmplt_file, 'r') as boot_conf_file:
            boot_conf_file.close()
        boot_conf = file_utils.read_yaml(boot_tmplt_file)

    # Setup k8s config
    k8s_conf = config_utils.k8s_conf_dict(boot_conf, hb_conf)
    logger.info('k8s_conf -\n%s', k8s_conf)
    validation_utils.validate_deployment_file(k8s_conf)

    return boot_conf, hb_conf, k8s_conf


if __name__ == '__main__':
    # To ensure any files referenced via a relative path will begin from the
    # directory in which this file resides
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-t', '--task', dest='task', required=True,
        choices=[
            'deploy_all', 'deploy_boot', 'deploy_k8s', 'clean_all',
            'clean_boot', 'clean_k8s'],
        help='Task to perform')
    parser.add_argument(
        '-b', '--boot-tmplt', dest='boot_conf_file', required=True,
        help='The snaps-boot configuration YAML file - REQUIRED')
    parser.add_argument(
        '-k', '--k8s-tmplt', dest='k8s_conf_file', required=True,
        help='The snaps-kubernetes configuration YAML file - REQUIRED')
    parser.add_argument(
        '-e', '--env-file', dest='env_file',
        help='Yaml file containing substitution values to the env file')
    parser.add_argument(
        '-o', '--os-env', dest='os_env_file', default=None,
        help='If deployment is on openstack, this file is required for '
             'rebooting nodes')
    parser.add_argument(
        '-l', '--log-level', dest='log_level', default='INFO',
        help='Logging Level (INFO|DEBUG)')
    args = parser.parse_args()

    if args.log_level == 'DEBUG':
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    else:
        logging.basicConfig(stream=sys.stdout, level=logging.INFO)

    logger.info('Launching adrenaline')
    __launch(args.task, args.boot_conf_file, args.k8s_conf_file, args.env_file,
             args.os_env_file)

    exit(0)
