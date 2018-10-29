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
# This script is responsible for deploying Aricent_Iaas environments and
# Kubernetes Services


import argparse
import logging
import sys
import os

from snaps_common.ansible_snaps import ansible_utils

from snaps_k8s.common.utils import file_utils
from snaps_k8s.common.consts import consts
from snaps_k8s.common.utils.validation_utils import validate_deployment_file
from snaps_k8s.provision import k8_utils

__author__ = '_ARICENT'

logger = logging.getLogger('launch_provisioning')


def __installation_logs(cmdln_args):
    """
     This will initialize the logging for Kubernetes installation
     :param cmdln_args : the command line arguments
    """
    level_value = cmdln_args.log_level

    log_file_name = consts.K8_INSTALLATION_LOGS
    if level_value.upper() == 'INFO':
        level_value = logging.INFO
    elif level_value.upper() == 'ERROR':
        level_value = logging.ERROR
    elif level_value.upper() == 'DEBUG':
        level_value = logging.DEBUG
    elif level_value.upper() == 'WARNING':
        level_value = logging.WARNING
    elif level_value.upper() == 'CRITICAL':
        level_value = logging.CRITICAL
    else:
        print("Incorrect log level %s received as input from user" %
              level_value)
        exit(1)

    logger.setLevel(level_value)

    log_output = cmdln_args.log_out
    if log_output == 'stderr':
        logging.basicConfig(level=logging.DEBUG)
    elif log_output == 'stdout':
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    else:
        logging.basicConfig(
            format='%(asctime)s %(levelname)s [%(filename)s:'
                   '%(lineno)s - %(funcName)2s() ] %(message)s ',
            datefmt='%b %d %H:%M', filename=log_file_name, filemode='w',
            level=level_value)
        logging.getLogger().addHandler(logging.StreamHandler())


def __launcher_conf():
    """
    Performs build server setup
    """
    logger.info('Setting up build server with playbook [%s]',
                consts.BUILD_PREREQS)
    ansible_utils.apply_playbook(consts.BUILD_PREREQS)


def run(arguments):
    """
     This will launch the provisioning of Bare metal & IaaS.
     There is pxe based configuration defined to provision the bare metal.
     For IaaS provisioning different deployment models are supported.
     Relevant conf files related to PXE based Hw provisioning & IaaS must be
     present in ./conf folder.
     :param arguments: This expects command line options to be entered by user
                       for relevant operations.
     :return: To the OS
    """
    __installation_logs(arguments)

    logger.info('Launching Operation Starts ........')

    dir_path = os.path.dirname(os.path.realpath(__file__))
    export_path = dir_path + "/"
    os.environ['CWD_IAAS'] = export_path
    logger.info('Current Exported Relevant Path - %s', export_path)

    config = file_utils.read_yaml(arguments.config)
    logger.info('Read configuration file - %s', arguments.config)

    if arguments.deploy_kubernetes:
        __launcher_conf()
        validate_deployment_file(config)
        k8_utils.execute(config)
    if arguments.clean_kubernetes:
        k8_utils.clean_k8(config)


if __name__ == '__main__':
    # To ensure any files referenced via a relative path will begin from the
    # directory in which this file resides
    os.chdir(os.path.dirname(os.path.realpath(__file__)))

    parser = argparse.ArgumentParser()
    parser_group = parser.add_mutually_exclusive_group()
    required_group = parser.add_mutually_exclusive_group(required=True)
    required_group.add_argument('-f', '--file', dest='config',
                                help='The configuration file in YAML format',
                                metavar="FILE")
    parser_group.add_argument('-k8_d', '--deploy_kubernetes',
                              action='store_true',
                              help='When used, deployment of kubernetes '
                                   'will be started')
    parser_group.add_argument('-k8_c', '--clean_kubernetes',
                              action='store_true',
                              help='When used, the kubernetes cluster '
                                   'will be removed')
    parser.add_argument('-l', '--log-level', default='INFO',
                        help='Logging Level (INFO|DEBUG|ERROR)')
    parser.add_argument('-o', '--log-out', default='file', dest='log_out',
                        help='Logging output (file(default)|stdout|stderr)')
    args = parser.parse_args()

    if (args.deploy_kubernetes or args.clean_kubernetes) and not args.config:
        logger.info(
            "Cannot start Kubernetes related operations without filename. "
            "Choose the option -f/--file")
        exit(1)

    run(args)
