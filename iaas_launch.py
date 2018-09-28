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
import subprocess
import sys
import os
import re

from snaps_k8s.common.utils import file_utils
from snaps_k8s.common.consts import consts
from snaps_k8s.common.utils.validation_utils import validate_deployment_file
from snaps_k8s.provision.kubernetes.deployment import deploy_infra

sys.path.append("common/utils")


# configure logging
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

    log_output = cmdln_args.log_output
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


# Configure the launcher node
def __launcher_conf(config):
    proxy_fname = "proxy.txt"
    logger.info('Updating proxy in apt.conf')
    apt_fname = "/etc/apt/apt.conf"
    env_fname = "/etc/environment"
    kubectl_fname = "/etc/apt/sources.list.d/kubernetes.list"
    http_pattern = '\"http:'
    https_pattern = '\"https:'
    ftp_pattern = "\"ftp:"
    no_pattern = '\"127.0.0.1'
    os.system(
        "grep -i 'https_proxy:|http_proxy:|ftp_proxy:|no_proxy:' "
        + config + "|awk '{print $2}' >proxy.txt")
    with open(proxy_fname) as proxy_file_handle:
        out = open(apt_fname, "w")
        env_file = open(env_fname, "w")
        env_file.write(
            "PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:"
            "/usr/bin:/sbin:/bin:/usr/games:/usr/local/games\"\n")
        for line in proxy_file_handle:
            if re.match(http_pattern, line):
                http_line1 = "Acquire::http::Proxy " + line
                http_line = http_line1.strip('\t\n\r')
                http_line = http_line + ";" + "\n"
                out.write(http_line)
                http_line2 = "export http_proxy=" + line
                http_line3 = http_line2.strip('\t\n\r')
                http_line3 = http_line3 + "\n"
                env_file.write(http_line3)
            elif re.match(https_pattern, line):
                https_line1 = "Acquire::https::Proxy " + line
                https_line = https_line1.strip('\t\n\r')
                https_line = https_line + ";" + "\n"
                out.write(https_line)
                https_line = "export https_proxy=" + line
                https_line4 = https_line.strip('\t\n\r')
                https_line4 = https_line4 + "\n"
                env_file.write(https_line4)

            elif re.match(ftp_pattern, line):
                ftp_line1 = "Acquire::ftp::Proxy " + line
                ftp_line = ftp_line1.strip('\t\n\r')
                ftp_line = ftp_line + ";" + "\n"
                out.write(ftp_line)
            elif re.match(no_pattern, line):
                https_line = "export no_proxy=" + line
                https_line4 = https_line.strip('\t\n\r')
                https_line4 = https_line4 + "\n"
                env_file.write(https_line4)

        out.close()
        env_file.close()
        proxy_file_handle.close()

    os.system("rm proxy.txt")

    logger.info('apt-get install -y ansible')
    command = "sudo apt-get install -y ansible"
    res = subprocess.call(command, shell=True)
    if not res:
        logger.error('error in apt-get install -y ansible')

    logger.info('apt-get install sshpass')
    command = "sudo apt-get install sshpass"
    res = subprocess.call(command, shell=True)
    if not res:
        logger.error('error in apt-get install sshpass')

    logger.info('pip install pyOpenSSL==16.2.0 ')
    command = "sudo pip install pyOpenSSL==16.2.0"
    res = subprocess.call(command, shell=True)
    if not res:
        logger.error('error in pip install pyOpenSSL==16.2.0')

    logger.info('apt-get install dos2unix')
    command = "apt-get install dos2unix"
    res = subprocess.call(command, shell=True)
    if not res:
        logger.error('error in apt-get install dos2unix')

    out = open(kubectl_fname, "w")
    out.write("deb http://apt.kubernetes.io/ kubernetes-xenial main")
    out.close()

    logger.info('apt-get install -y apt-transport-https')
    command = "sudo apt-get install -y apt-transport-https"
    res = subprocess.call(command, shell=True)
    if not res:
        logger.error('error in apt-get install -y apt-transport-https')

    logger.info(
        'curl -k https://packages.cloud.google.com'
        '/apt/doc/apt-key.gpg | apt-key add -')
    command = "sudo curl -k https://packages.cloud.google.com" \
              "/apt/doc/apt-key.gpg | apt-key add -"
    res = subprocess.call(command, shell=True)
    if not res:
        logger.error(
            'curl -k https://packages.cloud.google.com'
            '/apt/doc/apt-key.gpg|apt-key add -')

    logger.info('apt-get update')
    command = "sudo apt-get update"
    res = subprocess.call(command, shell=True)
    if not res:
        logger.error('error in apt-get update')

    logger.info('apt-get install -y kubectl')
    command = "sudo apt-get install -y kubectl"
    res = subprocess.call(command, shell=True)
    if not res:
        logger.error('apt-get install -y kubectl')


__author__ = '_ARICENT'

logger = logging.getLogger('launch_provisioning')


def __manage_operation(config, operation, deploy_file):
    """
     This will launch the provisioning of kubernetes setup on the cluster node
     which are defined in the deployment.yaml.
     :param config : This configuration data extracted from the provided yaml
                     file.
    """
    ret_value = False
    if config and isinstance(config, dict):
        if config.get('kubernetes'):
            logger.info("Yaml Configuration %s", config)
            logger.info("Read & Validate functionality for Kubernetes %s",
                        operation)
            ret_value = deploy_infra(config, operation, deploy_file)
        else:
            logger.error("Configuration Error ")
    else:
        logger.info("Installation of additional services")
        ret_value = deploy_infra(config, operation, deploy_file)

    return ret_value


def main(arguments):
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
    ret_value = False
    __installation_logs(arguments)

    logger.info('Launching Operation Starts ........')

    dir_path = os.path.dirname(os.path.realpath(__file__))
    export_path = dir_path + "/"
    os.environ['CWD_IAAS'] = export_path
    logger.info('Current Exported Relevant Path - %s', export_path)

    config = file_utils.read_yaml(arguments.config)
    logger.info('Read configuration file - %s', arguments.config)

    if arguments.deploy_kubernetes:
        __launcher_conf(arguments.config)
        validate_deployment_file(config)
        ret_value = __manage_operation(config, "deploy_k8", arguments.config)
    if arguments.clean_kubernetes:
        ret_value = __manage_operation(config, "clean_k8", arguments.config)
    if ret_value:
        logger.info('Completed operation successfully')
    else:
        logger.info('Operation unsuccessful')


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
    parser.add_argument('-o', '--log_out', default='stdout',
                        help='Logging output (file(default)|stdout|stderr)')
    args = parser.parse_args()

    if (args.deploy_kubernetes or args.clean_kubernetes) and not args.config:
        # args.enable_multus_network_plugin or
        # args.cleanup_multus_network_plugin or
        # args.add_nodes_kubernetes or args.clean_nodes_kubernetes) and
        # not args.config:
        logger.info(
            "Cannot start Kubernetes related operations without filename. "
            "Choose the option -f/--file")
        exit(1)

    main(args)
