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
import getpass
import logging
import re
import subprocess
import time

from snaps.provisioning import ansible_utils

import ansible_playbook_launcher as apbl
from snaps_k8s.common.consts import consts
from snaps_k8s.common.utils import file_utils

DEFAULT_REPLACE_EXTENSIONS = None

logger = logging.getLogger('deploy_ansible_configuration')


def provision_preparation(proxy_dict):
    """
    This method is responsible for writing the hosts info in ansible hosts file
    proxy inf in ansible proxy file
    : param proxy_dict: proxy data in the dictionary format
    : return ret :
    """
    logger.info("\n Argument List: \n proxy_dict: %s", proxy_dict)

    ret = True

    if proxy_dict:
        logger.debug("Adding proxies")
        proxy_file_in = open(consts.PROXY_DATA_FILE, "r+")
        proxy_file_in.seek(0)
        proxy_file_in.truncate()
        proxy_file_out = open(consts.PROXY_DATA_FILE, "w")
        proxy_file_out.write("---")
        proxy_file_out.write("\n")
        for key, value in proxy_dict.items():
            if value == '':
                value = "\"\""
            logger.info("%s : %s", key, value)
            logger.debug("Proxies added in file: %s : %s", key, value)
            proxy_file_out.write(key + ": " + str(value) + "\n")
        proxy_file_out.close()
        proxy_file_in.close()
        return ret


def clean_up_k8_addons(**k8_addon):
    """
    function to delete all addons : such as metrics server
    :param k8_addon:
    :return:
    """
    logger.info("Argument List: \n k8_addon: %s", k8_addon)
    return_stmt = False
    hostname_map = k8_addon.get("hostname_map")
    host_node_type_map = k8_addon.get("host_node_type_map")
    for addon in k8_addon:
        if addon == "metrics_server" and k8_addon.get("metrics_server"):
            return_stmt = clean_up_metrics_server(hostname_map,
                                                  host_node_type_map)

    return return_stmt


def clean_up_k8(git_branch, project_name, multus_enabled_str):
    """
    This function is used for clean/Reset the kubernetes cluster
    """
    logger.info("\n Argument List: \n git_branch: %s\n "
                "project_name: %s\n multus_enabled_str: %s",
                git_branch, project_name, multus_enabled_str)
    multus_enabled = str(multus_enabled_str)
    logger.info('multus_enabled_str : %s', multus_enabled)
    logger.info('pip install --upgrade ansible==2.4.1.0')
    command = "pip install --upgrade ansible==2.4.1.0"
    ret_hosts = subprocess.call(command, shell=True)
    if not ret_hosts:
        logger.info('error in pip install --upgrade ansible==2.4.1.0')

    logger.info('EXECUTING CLEAN K8 CLUSTER PLAY')
    logger.info(consts.K8_CLEAN_UP)
    ret_hosts = apbl.clean_k8(
        consts.K8_CLEAN_UP,
        consts.INVENTORY_SOURCE_FOLDER,
        consts.VARIABLE_FILE,
        consts.PROXY_DATA_FILE,
        git_branch,
        project_name)
    if not ret_hosts:
        logger.error('FAILED IN CLEAN UP KUBERNETES CLUSTER ')
        exit(1)
    host_name_map_ip = get_hostname_ip_map_list(project_name)
    logger.info("Docker cleanup starts")
    for host_name, ip in host_name_map_ip.items():
        ret_val = apbl.clean_docker(
            consts.K8_DOCKER_CLEAN_UP_ON_NODES, host_name)
        if not ret_val:
            logger.error('FAILED IN DOCKER CLEANUP  ')
            exit(1)
    for host_name, ip in host_name_map_ip.items():
        logger.info('EXECUTING DELETE NODES PLAY')
        logger.info(consts.K8_REMOVE_NODE_K8)
        ret_hosts = apbl.delete_host_k8(consts.K8_REMOVE_NODE_K8, ip,
                                        host_name, consts.HOSTS_FILE,
                                        consts.ANSIBLE_HOSTS_FILE,
                                        consts.VARIABLE_FILE,
                                        project_name, multus_enabled)
        if not ret_hosts:
            logger.error('FAILED IN DELTING NODE')
            exit(1)
    logger.info('EXECUTING REMOVE PROJECT FOLDER PLAY')
    logger.info(consts.K8_REMOVE_FOLDER)
    ret_hosts = apbl.delete_project_folder(
        consts.K8_REMOVE_FOLDER, consts.VARIABLE_FILE,
        consts.INVENTORY_SOURCE_FOLDER, project_name,
        consts.PROXY_DATA_FILE)
    if not ret_hosts:
        logger.error('FAILED IN CLEAN UP KUBERNETES CLUSTER ')
        exit(1)

    return ret_hosts


def clean_sriov_rc_local(hosts_data_dict):
    ret_hosts = None
    for node in hosts_data_dict:
        for key in node:
            if key == "Sriov":
                all_hosts = node.get("Sriov")
                for host_data in all_hosts:
                    hostdetails = host_data.get("host")
                    networks = hostdetails.get("networks")
                    node_hostname = hostdetails.get("hostname")
                    for network in networks:
                        sriov_intf = network.get("sriov_intf")
                        ret_hosts = apbl.clean_sriov_rc_local(
                            consts.K8_SRIOV_CLEAN_RC_LOCAL, node_hostname,
                            sriov_intf)

    return ret_hosts


def clean_up_k8_docker(host_dict):
    """
    This function is used for clean docker on cluster nodes
    :param host_dict:
    """
    logger.info("Argument List: host_dict is %s", host_dict)
    ret_val = None
    for host_name in host_dict:
        ret_val = apbl.clean_docker(
            consts.K8_DOCKER_CLEAN_UP_ON_NODES, host_name)
        if not ret_val:
            logger.error('FAILED IN CLEAN UP KUBERNETES CLUSTER ')
            exit(1)
    return ret_val


def launch_provisioning_kubernetes(host_name_map, host_node_type_map,
                                   host_port_map, service_subnet, pod_subnet,
                                   networking_plugin, docker_repo,
                                   hosts, git_branch, project_name,
                                   config, ha_enabled):
    """
    This function is used for deploy the kubernet cluster
    """

    logger.info('EXECUTING CLONE PACKAGES PLAY')
    logger.info(consts.K8_CLONE_PACKAGES)
    ret_hosts = apbl.clone_packages(
        consts.K8_CLONE_PACKAGES, consts.PROXY_DATA_FILE, consts.VARIABLE_FILE,
        consts.K8_PACKAGE_PATH, git_branch)
    if not ret_hosts:
        logger.error('FAILED TO CLONE PACKAGES')
        exit(1)

    master_hostname = None
    for key, node_type in host_node_type_map.items():
        if node_type == "master":
            master_hostname = key

    ips = []
    user = getpass.getuser()
    for host_name, ip_val in host_name_map.items():
        ips.append(ip_val)
        ansible_utils.apply_playbook(
            consts.K8_SET_HOSTNAME, hosts_inv=[ip_val], host_user=user,
            variables={'host_name': host_name})

    ansible_utils.apply_playbook(
        consts.K8_SET_PACKAGES, ips, user, password=None, variables={
            'PROXY_DATA_FILE': consts.PROXY_DATA_FILE,
            'VARIABLE_FILE': consts.VARIABLE_FILE,
            'APT_ARCHIVES_SRC': consts.APT_ARCHIVES_PATH,
            'SRC_PACKAGE_PATH': consts.INVENTORY_SOURCE_FOLDER,
        })

    for host_name, ip_val in host_name_map.items():
        registry_port = host_port_map.get(host_name)
        ansible_utils.apply_playbook(
            consts.K8_CONFIG_DOCKER, hosts_inv=[ip_val], host_user=user,
            variables={
                'PROXY_DATA_FILE': consts.PROXY_DATA_FILE,
                'VARIABLE_FILE': consts.VARIABLE_FILE,
                'APT_ARCHIVES_SRC': consts.APT_ARCHIVES_PATH,
                'SRC_PACKAGE_PATH': consts.INVENTORY_SOURCE_FOLDER,
                'registry_port': registry_port,
            })

    if docker_repo:
        docker_ip = docker_repo.get(consts.IP)
        docker_port = docker_repo.get(consts.PORT)
        logger.info('EXECUTING CREATING PRIVATE DOCKER REPO PLAY')
        logger.info(consts.K8_PRIVATE_DOCKER)
        ret_hosts = apbl.creating_docker_repo(
            consts.K8_PRIVATE_DOCKER, consts.PROXY_DATA_FILE,
            consts.VARIABLE_FILE, docker_ip, docker_port,
            consts.APT_ARCHIVES_PATH, consts.INVENTORY_SOURCE_FOLDER)
        if not ret_hosts:
            logger.error('FAILED IN  CREATING PRIVATE DOCKER REPO ')
            exit(1)
        for host_name, ip in host_name_map.items():
            logger.info('EXECUTING CONFIGURE DOCKER REPO PLAY')
            logger.info(consts.K8_CONF_DOCKER_REPO)
            ret_hosts = apbl.docker_conf(
                consts.K8_CONF_DOCKER_REPO, ip, host_name,
                consts.PROXY_DATA_FILE, consts.VARIABLE_FILE, docker_ip,
                docker_port)
            if not ret_hosts:
                logger.error('FAILED IN CONFIGURE DOCKER REPO')
                exit(1)

    logger.info('CREATING INVENTORY FILE PLAY')
    logger.info(consts.K8_CREATE_INVENTORY_FILE)
    ret_hosts = apbl.create_inventory_file(
        consts.K8_CREATE_INVENTORY_FILE, consts.INVENTORY_SOURCE_FOLDER,
        consts.VARIABLE_FILE, consts.CWD, project_name)
    if not ret_hosts:
        logger.error('CREATING INVENTORY FILE')
        exit(1)
    logger.info('EXECUTING MODIFIY INVENTORY FILES PLAY')
    logger.info(consts.KUBERNETES_NEW_INVENTORY)
    ret_hosts = modify_inventory_file(consts.KUBERNETES_NEW_INVENTORY,
                                      consts.KUBERNETES_CREATE_INVENTORY,
                                      host_name_map,
                                      host_node_type_map, project_name)
    if not ret_hosts:
        logger.error('FAILED TO MODIFIY INVENTORY FILES')
        exit(1)

    logger.info('EXECUTING CLONE KUBESPRAY CODE PLAY')
    logger.info(consts.K8_CLONE_CODE)
    ret_hosts = apbl.kubespray_play(consts.K8_CLONE_CODE,
                                    consts.PROXY_DATA_FILE,
                                    consts.VARIABLE_FILE,
                                    consts.INVENTORY_SOURCE_FOLDER,
                                    git_branch, project_name)
    if not ret_hosts:
        logger.error('FAILED TO CLONE KUBESPRAY CODE')
        exit(1)

    enable_logging = config.get(consts.KUBERNETES).get(consts.ENABLE_LOGGING)
    if enable_logging is not None:
        if enable_logging is not True and enable_logging is not False:
            logger.error('either enabled logging or disabled logging')
            exit(1)
        if enable_logging:
            value = "True"
            log_level = config.get(consts.KUBERNETES).get(consts.LOG_LEVEL)
            if log_level != "fatal" and log_level != "warning" and \
                            log_level != "info" and log_level != "debug" and \
                            log_level != "critical":
                logger.error('enter valid log_level')
                exit(1)
            logging_port = config.get(consts.KUBERNETES).get(
                consts.LOGGING_PORT)
            ret_hosts = enable_cluster_logging(value, project_name,
                                               log_level, logging_port)
            if not ret_hosts:
                logger.error('failed to enable logging ')
    else:
        logger.info('logging is disabled ')

    if config.get(consts.KUBERNETES).get(consts.CPU_ALLOCATION_SUPPORT):
        if config.get(consts.KUBERNETES).get(consts.CPU_ALLOCATION_SUPPORT):
            if launch_cpu_pinning_kubernetes(
                    config,
                    consts.PROXY_DATA_FILE,
                    consts.VARIABLE_FILE):
                logger.info('CPU ALLOCATION DONE SUCCESSFULLY')
            else:
                logger.error('CPU ALLOCATION FAILED')
                exit(1)
        else:
            logger.info('Exclusive_CPU_alloc_support: %s',
                        config.get(consts.KUBERNETES).
                        get(consts.CPU_ALLOCATION_SUPPORT))

    logger.info('pip install --upgrade ansible==2.4.1.0')
    command = "pip install --upgrade ansible==2.4.1.0"
    ret_hosts = subprocess.call(command, shell=True)
    if not ret_hosts:
        logger.info('error in pip install --upgrade ansible==2.4.1.0')

    logger.info('EXECUTING CONFIGURATION AND INSTALLATION OF '
                'KUBERNETES CLUSTER')
    logger.info(consts.KUBERNETES_SET_LAUNCHER)
    kube_version = config.get(consts.KUBERNETES).get(consts.K8_VERSION)
    ret_hosts = apbl.launch_k8s(consts.KUBERNETES_SET_LAUNCHER,
                                service_subnet, pod_subnet, networking_plugin,
                                consts.PROXY_DATA_FILE, consts.VARIABLE_FILE,
                                consts.INVENTORY_SOURCE_FOLDER, consts.CWD,
                                git_branch, project_name, kube_version)
    if not ret_hosts:
        logger.error('FAILED IN CONFIGURATION AND INSTALLATION OF '
                     'KUBERNETES CLUSTER')
        exit(1)

    logger.info('Calling kubectl installation function')
    install_kubectl(
        host_name_map, host_node_type_map, ha_enabled, project_name, config,
        consts.VARIABLE_FILE, consts.INVENTORY_SOURCE_FOLDER)

    if hosts:
        for i in range(len(hosts)):
            host = hosts[i].get(consts.HOST)
            label_key = host.get(consts.LABEL_KEY)
            hostname = host.get(consts.HOSTNAME)
            label_value = host.get(consts.LABEL_VALUE)
            logger.info(consts.K8_NODE_LABELING)
            ret_hosts = apbl.node_labeling(
                consts.K8_NODE_LABELING, master_hostname,
                hostname, label_key, label_value, consts.PROXY_DATA_FILE)
            if not ret_hosts:
                logger.error('FAILED IN INSTALLING FILE PLAY')
                exit(1)

    for host_name, node_type in host_node_type_map.items():
        if node_type == "master":
            logger.info('EXECUTING WEAVE SCOPE PLAY')
            logger.info(consts.KUBERNETES_WEAVE_SCOPE)
            ret_hosts = apbl.weave_scope(consts.KUBERNETES_WEAVE_SCOPE,
                                         host_name,
                                         consts.INVENTORY_SOURCE_FOLDER,
                                         consts.VARIABLE_FILE,
                                         consts.PROXY_DATA_FILE)
            if not ret_hosts:
                logger.error('FAILED IN INSTALLING FILE PLAY')
                exit(1)

            logger.info('EXECUTING KUBE PROXY PLAY')
            ret_hosts = apbl.kube_proxy(consts.KUBERNETES_KUBE_PROXY,
                                        host_name,
                                        consts.INVENTORY_SOURCE_FOLDER,
                                        consts.VARIABLE_FILE,
                                        consts.PROXY_DATA_FILE)
            if not ret_hosts:
                logger.error('FAILED IN KUBE PROXY FILE PLAY')
                exit(1)
            else:
                logger.info('Started KUBE PROXY')

    logger.info('Completed launch_provisioning_kubernetes()')
    logger.info('Exit')
    return ret_hosts


def modify_user_list(user_name, user_password, user_id):
    logger.info(
        "Argument List: \n user_name: %s\n user_password: %s\n user_id: %s",
        user_name, user_password, user_id)

    ret_hosts = apbl.update_user_list(
        consts.KUBERNETES_USER_LIST, user_name, user_password, user_id,
        consts.INVENTORY_SOURCE_FOLDER)
    if not ret_hosts:
        logger.error('FAILED SET HOSTS PLAY')
        exit(1)
    return ret_hosts


def update_kube_api_manifest_file(master_host_name):
    logger.info("Argument List: \n master_host_name: %s", master_host_name)

    ret_hosts = apbl.launch_authentication(
        consts.KUBERNETES_AUTHENTICATION, master_host_name,
        consts.INVENTORY_SOURCE_FOLDER, consts.VARIABLE_FILE)
    if not ret_hosts:
        logger.error('FAILED SET HOSTS PLAY')
        exit(1)
    return ret_hosts


def modify_inventory_file(playbook1, playbook2, host_name_map,
                          host_node_type_map, project_name):
    logger.info("\n Argument List: \n playbook1: %s \n playbook2: %s"
                "\n host_name_map: %s \n host_node_type_map: %s"
                "\n project_name: %s", playbook1, playbook2, host_name_map,
                host_node_type_map, project_name)

    for host_name, ip in host_name_map.items():
        logger.info('EXECUTING MODIFIED INVENTORY FILE PLAY')
        logger.info(playbook1)
        ret_hosts = apbl.launch_new_inventory(
            playbook1, ip, host_name, consts.INVENTORY_SOURCE_FOLDER,
            consts.VARIABLE_FILE,
            consts.CWD, project_name)
        if not ret_hosts:
            logger.error('FAILED IN MODIFIED INVENTORY FILE PLAY')
            exit(1)

    ret_hosts = False
    for host_name, node_type in host_node_type_map.items():
        logger.info('EXECUTING MODIFIED INVENTORY FILE PLAY')
        logger.info(playbook2)
        ret_hosts = apbl.launch_inventory(
            playbook2, node_type, host_name, consts.INVENTORY_SOURCE_FOLDER,
            consts.VARIABLE_FILE,
            project_name)
        if not ret_hosts:
            logger.error('FAILED IN MODIFIED INVENTORY FILE PLAY')
            exit(1)
    return ret_hosts


def launch_crd_network(host_name_map, host_node_type_map):
    """
    This function is used to create crd network
    """
    logger.info("Argument List:\n host_name_map: %s\n host_node_type_map: %s",
                host_name_map, host_node_type_map)

    master_ip = None
    master_host_name = None
    for host_name, node_type in host_node_type_map.items():
        for key, value in host_name_map.items():
            if node_type == "master" and key == host_name:
                master_ip = value
                master_host_name = key
                logger.info('master IP is %s', master_ip)
                logger.info('master hostname is %s', master_host_name)

    logger.info('EXECUTING CRD NETWORK CREATION PLAY. Master ip - %s, '
                'Master Host Name - %s', master_ip, master_host_name)
    ret_val = apbl.create_crd_network(
        consts.K8_CREATE_CRD_NETWORK, master_ip, master_host_name,
        consts.INVENTORY_SOURCE_FOLDER, consts.PROXY_DATA_FILE)
    if not ret_val:
        logger.error('FAILED IN CREATING CRD NETWORK')
        exit(1)

    logger.info('Exit')
    return ret_val


def launch_multus_cni(host_name_map, host_node_type_map, networking_plugin):
    """
    This function is used to launch multus cni
    """
    logger.info("Argument List:\n host_name_map: %s\n host_node_type_map: %s"
                "\n networking_plugin: %s", host_name_map, host_node_type_map,
                networking_plugin)

    ret_hosts = False
    logger.info('EXECUTING MULTUS CNI PLAY')
    for host_name, node_type in host_node_type_map.items():
        logger.info(consts.K8_MULTUS_SET_MASTER)
        for host_name1, ip in host_name_map.items():
            if node_type == "master" and host_name1 == host_name:
                logger.info('IP is %s', ip)
                logger.info('Host name is %s', host_name)
                logger.info('EXECUTING MASTER MULTUS PLAY')
                ret_hosts = apbl.master_multus(
                    consts.K8_MULTUS_SET_MASTER, ip, host_name,
                    networking_plugin, consts.INVENTORY_SOURCE_FOLDER,
                    consts.PROXY_DATA_FILE)
                if not ret_hosts:
                    logger.error('FAILED IN INSTALLING MULTUS AT MASTER')
                    exit(1)
            elif node_type == "minion" and host_name1 == host_name:
                logger.info('IP is %s', ip)
                logger.info('Host name is %s', host_name)
                logger.info('EXECUTING SCP MULTUS PLAY')
                ret_hosts = apbl.copy_multus(
                    consts.K8_MULTUS_SCP_MULTUS_CNI, ip, host_name,
                    networking_plugin, consts.INVENTORY_SOURCE_FOLDER)
                if not ret_hosts:
                    logger.error('FAILED IN SCP MULTUS AT NODE')
                    exit(1)
                logger.info('EXECUTING NODE MULTUS PLAY')
                ret_hosts = apbl.node_multus(
                    consts.K8_MULTUS_SET_NODE, ip, host_name,
                    networking_plugin, consts.INVENTORY_SOURCE_FOLDER)
                if not ret_hosts:
                    logger.error('FAILED IN INSTALLING MULTUS AT NODE')
                    exit(1)

    return ret_hosts


def launch_flannel_interface(host_name_map, host_node_type_map,
                             networking_plugin, item):
    """
    This function is used to launch flannel interface
    """
    logger.info("Argument List: \n host_name_map: %s\n host_node_type_map: %s"
                "\n networking_plugin: %s\n item: %s", host_name_map,
                host_node_type_map, networking_plugin, item)

    logger.info('EXECUTING FLANNEL INTERFACE CREATION PLAY')
    network_dict = item.get("flannel_network")
    network = network_dict.get('network')
    subnet_len = network_dict.get('subnetLen')
    vni = network_dict.get('vni')
    master_ip = None
    ret_hosts = False

    for host_name, node_type in host_node_type_map.items():
        logger.info(consts.K8_CONF_FLANNEL_INTERFACE_AT_MASTER)
        for host_name1, ip in host_name_map.items():
            if node_type == "master" and host_name1 == host_name:
                logger.info('IP is %s', ip)
                logger.info('Hostname is %s', host_name)
                master_ip = ip

                logger.info('master_ip is %s', master_ip)
                logger.info('network is %s', network)
                logger.info('subnetLen is %s', subnet_len)
                logger.info('vni is %s', vni)

                logger.info('EXECUTING FLANNEL INTF PLAY AT MASTER')
                ret_hosts = apbl.master_flannel(
                    consts.K8_CONF_FLANNEL_INTERFACE_AT_MASTER, ip, host_name,
                    networking_plugin, network, subnet_len, vni,
                    consts.INVENTORY_SOURCE_FOLDER)
                if not ret_hosts:
                    logger.error(
                        'FAILED IN CONFIGURING FLANNEL INTERFACE AT MASTER')
                    exit(1)

    for host_name, node_type in host_node_type_map.items():
        logger.info(consts.K8_CONF_FLANNEL_INTERFACE_AT_MASTER)
        for host_name1, ip in host_name_map.items():
            if node_type == "minion" and host_name1 == host_name:
                logger.info('IP is %s', ip)
                logger.info('Hostname is %s', host_name)
                logger.info('master_ip is %s', master_ip)
                logger.info('network is %s', network)
                logger.info('subnetLen is %s', subnet_len)
                logger.info('vni is %s', vni)

                logger.info('EXECUTING FLANNEL INTF PLAY AT NODE')
                ret_hosts = apbl.node_flannel(
                    consts.K8_CONF_FLANNEL_INTERFACE_AT_NODE, ip, host_name,
                    networking_plugin, network, subnet_len, vni, master_ip,
                    consts.INVENTORY_SOURCE_FOLDER)
                if not ret_hosts:
                    logger.error('FAILED IN CONFIGURING FLANNEL '
                                 'INTERFACE AT NODE')
                    exit(1)

    return ret_hosts


def create_flannel_networks(host_name_map, host_node_type_map,
                            networking_plugin, item):
    """
    This function is used to create flannel networks
    """
    logger.info("Argument List: \n host_name_map: %s\n host_node_type_map: %s"
                "\n networking_plugin: %s\n item: %s", host_name_map,
                host_node_type_map, networking_plugin, item)

    logger.info('CREATING FLANNEL NETWORK')
    network_dict = item.get("flannel_network")
    network_name = network_dict.get('network_name')
    vni = network_dict.get('vni')
    logger.info('networkName is %s', network_name)
    logger.info('vni is %s', vni)
    vni_int = int(vni)
    vni_temp1 = (vni_int - 1)
    vni_temp = str(vni_temp1)

    ret_hosts = False
    for host_name, node_type in host_node_type_map.items():
        logger.info(consts.K8_CONF_FLANNEL_NETWORK_CREATION)
        for host_name1, ip in host_name_map.items():
            if node_type == "master" and host_name1 == host_name:
                logger.info('IP is %s', ip)
                logger.info('Hostname is %s', host_name)
                logger.info('networkName is %s', network_name)
                logger.info('vni is %s', vni)

                logger.info('CREATING FLANNEL NETWORKS')
                ret_hosts = apbl.create_flannel_networks(
                    consts.K8_CONF_FLANNEL_NETWORK_CREATION, ip, host_name,
                    network_name, vni, vni_temp,
                    consts.INVENTORY_SOURCE_FOLDER,
                    consts.PROXY_DATA_FILE)
                if not ret_hosts:
                    logger.error('FAILED IN CONFIGURING FLANNEL '
                                 'INTERFACE AT MASTER')
                    exit(1)
    return ret_hosts


def launch_sriov_cni_configuration(host_node_type_map, hosts_data_dict,
                                   project_name):
    """
    This function is used to launch sriov cni
    """
    logger.info("Argument List: \n host_node_type_map: %s\n hosts_data_dict: "
                "%s\n project_name: %s", host_node_type_map, hosts_data_dict,
                project_name)

    minion_list = []
    logger.info('EXECUTING SRIOV CNI PLAY')
    logger.info("INSIDE launch_sriov_cni")
    dpdk_enable = "no"

    config = file_utils.read_yaml(consts.VARIABLE_FILE)
    project_path = config.get(consts.PROJECT_PATH)
    inventory_file_path = project_path + project_name + "/k8s-cluster.yml"
    logger.info('Inventory file path is %s', inventory_file_path)
    networking_plugin = None
    with open(inventory_file_path) as file_handle:
        for line in file_handle:
            if "kube_network_plugin:" in line:
                network_plugin1 = line.split("kube_network_plugin:", 1)[1]
                networking_plugin = network_plugin1.strip(' \t\n\r')
                logger.info('networking_plugin - %s', networking_plugin)
    file_handle.close()

    dpdk_driver = None
    for node in hosts_data_dict:
        for key in node:
            if "Sriov" == key:
                all_hosts = node.get("Sriov")
                logger.info('Host list is %s', all_hosts)
                for host_data in all_hosts:
                    logger.info('Host data is %s', host_data)
                    hostdetails = host_data.get("host")
                    hostname = hostdetails.get("hostname")
                    networks = hostdetails.get("networks")
                    logger.info('Hostname is %s', hostname)
                    minion_list.append(hostname)
                    for network in networks:
                        dpdk_driver = 'vfio-pci'
                        dpdk_enable = network.get("dpdk_enable")
                        sriov_intf = network.get("sriov_intf")
                        logger.info('SRIOV CONFIGURATION ON NODES')
                        apbl.enable_sriov(
                            consts.K8_SRIOV_ENABLE, hostname,
                            sriov_intf,
                            consts.K8_SRIOV_CONFIG_SCRIPT,
                            networking_plugin)

    ret_hosts = apbl.build_sriov(
        consts.K8_SRIOV_CNI_BUILD, consts.INVENTORY_SOURCE_FOLDER,
        consts.PROXY_DATA_FILE)
    logger.info('DPDK flag is %s', dpdk_enable)
    if dpdk_enable == "yes":
        ret_hosts = apbl.build_sriov_dpdk(
            consts.K8_SRIOV_DPDK_CNI, consts.INVENTORY_SOURCE_FOLDER,
            consts.PROXY_DATA_FILE)
    for host_name in get_master_host_name_list(host_node_type_map):
        logger.info('Executing for master %s', host_name)
        logger.info('INSTALLING SRIOV BIN ON MASTER')
        ret_hosts = apbl.sriov_install(
            consts.K8_SRIOV_CNI_BIN_INST, host_name,
            consts.INVENTORY_SOURCE_FOLDER)
        if dpdk_enable == "yes":
            logger.info('INSTALLING SRIOV DPDK BIN ON MASTER')
            ret_hosts = apbl.sriov_dpdk_install(
                consts.K8_SRIOV_DPDK_CNI_BIN_INST, host_name,
                consts.INVENTORY_SOURCE_FOLDER)

    for host_name in minion_list:
        logger.info('Executing for  minion %s', host_name)
        logger.info('INSTALLING SRIOV BIN ON WORKER nodes')
        ret_hosts = apbl.sriov_install(
            consts.K8_SRIOV_CNI_BIN_INST, host_name,
            consts.INVENTORY_SOURCE_FOLDER)
        if dpdk_enable == "yes":
            logger.info('INSTALLING SRIOV DPDK BIN ON WORKERS')
            apbl.dpdk_driver_load(
                consts.K8_SRIOV_DPDK_DRIVER_LOAD, host_name, dpdk_driver)
            ret_hosts = apbl.sriov_dpdk_install(
                consts.K8_SRIOV_DPDK_CNI_BIN_INST, host_name,
                consts.INVENTORY_SOURCE_FOLDER)

    return ret_hosts


def launch_sriov_network_creation(host_node_type_map, hosts_data_dict,
                                  project_name):
    logger.info(
        "Argument List: \n host_node_type_map: %s\n hosts_data_dict: %s"
        "\n project_name: %s", host_node_type_map, hosts_data_dict,
        project_name)

    ret_hosts = False
    master_list = get_master_host_name_list(host_node_type_map)
    logger.info('Master list is %s', master_list)
    master_host = get_host_master_name(project_name)
    logger.info('Performing config for node %s', master_host)
    for node in hosts_data_dict:
        for key in node:
            if "Sriov" == key:
                all_hosts = node.get("Sriov")
                for host_data in all_hosts:
                    host_details = host_data.get("host")
                    networks = host_details.get("networks")
                    node_hostname = host_details.get("hostname")
                    for network in networks:
                        dpdk_tool = '/etc/cni/scripts/dpdk-devbind.py'
                        dpdk_driver = 'vfio-pci'
                        dpdk_enable = network.get("dpdk_enable")
                        range_end = network.get("rangeEnd")
                        range_start = network.get("rangeStart")
                        host = network.get("type")
                        sriov_gateway = network.get("sriov_gateway")
                        sriov_intf = network.get("sriov_intf")
                        sriov_subnet = network.get("sriov_subnet")
                        sriov_nw_name = network.get("network_name")
                        master_plugin = network.get(consts.MASTER_PLUGIN)
                        logger.info('Master host is %s', master_host)
                        logger.info('Node hostname is %s', node_hostname)
                        logger.info('dpdk_tool: %s', dpdk_tool)
                        logger.info('dpdk_driver: %s', dpdk_driver)
                        logger.info('dpdk_enable: %s', dpdk_enable)
                        logger.info('sriov_intf: %s', sriov_intf)
                        logger.info('master_host: %s', master_host)
                        logger.info('sriov_nw_name: %s', sriov_nw_name)
                        logger.info('rangeStart:%s', range_start)
                        logger.info('rangeEnd: %s', range_end)
                        logger.info('sriov_subnet: %s', sriov_subnet)
                        logger.info('sriov_gateway : %s', sriov_gateway)
                        if dpdk_enable == "yes":
                            logger.info(
                                'SRIOV NETWORK CREATION STARTED USING DPDK '
                                'DRIVER')
                            ret_hosts = apbl.sriov_dpdk_crd_nw(
                                consts.K8_SRIOV_DPDK_CR_NW, sriov_intf,
                                master_host, sriov_nw_name, dpdk_driver,
                                dpdk_tool, node_hostname, master_plugin,
                                consts.PROXY_DATA_FILE)

                        if dpdk_enable == "no":
                            if host == "host-local":
                                logger.info(
                                    'SRIOV NETWORK CREATION STARTED USING '
                                    'KERNEL DRIVER WITH IPAM host-local')
                                ret_hosts = apbl.sriov_crd_nw(
                                    consts.K8_SRIOV_CR_NW, sriov_intf,
                                    master_host, sriov_nw_name, range_start,
                                    range_end, sriov_subnet, sriov_gateway,
                                    master_plugin, consts.PROXY_DATA_FILE)

                            if host == "dhcp":
                                logger.info(
                                    'SRIOV NETWORK CREATION STARTED USING '
                                    'KERNEL DRIVER WITH IPAM host-dhcp')
                                ret_hosts = apbl.sriov_dhcp_crd_nw(
                                    consts.K8_SRIOV_DHCP_CR_NW,
                                    sriov_intf, master_host, sriov_nw_name,
                                    consts.PROXY_DATA_FILE)

    return ret_hosts


def get_master_host_name_list(host_node_type_map):
    logger.info(
        "Argument List: \n host_node_type_map: %s", host_node_type_map)

    master_list = []
    logger.info('host_node_type_map is: %s', host_node_type_map)
    for key, value in host_node_type_map.items():
        if value == "master":
            master_list.append(key)
    return master_list


def create_default_network(host_name_map, host_node_type_map,
                           networking_plugin, item):
    """
    This function is create default network
    """
    ret_hosts = False
    logger.info("Argument List: \n host_name_map: %s\n host_node_type_map: %s"
                "\n networking_plugin: %s\n item: %s", host_name_map,
                host_node_type_map, networking_plugin, item)

    logger.info('EXECUTING CREATE DEFAULT NETWORK PLAY')

    subnet = item.get(consts.POD_SUBNET)
    network_name = item.get(consts.NETWORK_NAME)
    master_plugin = item.get(consts.MASTER_PLUGIN)
    logger.info('subnet is %s', subnet)
    logger.info('networkName is %s', network_name)

    for host_name, node_type in host_node_type_map.items():
        for host_name1, ip in host_name_map.items():
            if node_type == "master" and host_name1 == host_name:
                ret_hosts = apbl.create_default_network(
                    consts.K8_CREATE_DEFAULT_NETWORK, ip, host_name,
                    network_name, subnet, networking_plugin, master_plugin,
                    consts.INVENTORY_SOURCE_FOLDER,
                    consts.PROXY_DATA_FILE)
                if not ret_hosts:
                    logger.error('FAILED IN CREATING DEFAULT NETWORK')

    return ret_hosts


def create_flannel_interface(host_name_map, host_node_type_map,
                             project_name, hosts_data_dict):
    logger.info("\n Argument List: \n host_name_map: %s\n host_node_type_map: "
                "%s\n project_name: %s\n hosts_data_dict: %s", host_name_map,
                host_node_type_map, project_name, hosts_data_dict)

    logger.info('EXECUTING FLANNEL INTERFACE CREATION PLAY IN CREATE FUNC')
    master_list = get_master_host_name_list(host_node_type_map)
    logger.info('master_list - %s', master_list)
    master_host = get_host_master_name(project_name)
    logger.info('Doing config for node - %s', master_host)

    for item1 in hosts_data_dict:
        for key1 in item1:
            if key1 == "Multus_network":
                multus_network = item1.get("Multus_network")
                for item2 in multus_network:
                    for key2 in item2:
                        if key2 == "CNI_Configuration":
                            logger.info('CNI key: %s', key2)
                            cni_configuration = item2.get("CNI_Configuration")
                            for item3 in cni_configuration:
                                for key3 in item3:
                                    __cni_config(
                                        host_node_type_map, host_name_map,
                                        key3, item3)


def __cni_config(host_node_type_map, host_name_map, item3, key3):
    logger.info('Network key: %s', key3)
    logger.info("consts.FLANNEL_NETWORK value is %s", consts.FLANNEL_NETWORK)
    ret_val = None
    network_name = None
    master_ip = None
    master_host_name = None
    network = None
    master_plugin = None

    if consts.FLANNEL_NETWORK == key3:
        all_hosts = item3.get(consts.FLANNEL_NETWORK)
        for host_data in all_hosts:
            hostdetails = host_data.get(consts.FLANNEL_NETWORK_DETAILS)
            network_name = hostdetails.get(consts.NETWORK_NAME)
            network = hostdetails.get(consts.NETWORK)
            cidr = hostdetails.get(consts.SUBNET)
            master_plugin = hostdetails.get(consts.MASTER_PLUGIN)
            logger.info('network is %s', network)
            for host_name, node_type in host_node_type_map.items():
                for host_name1, ip in host_name_map.items():
                    if node_type == "master" and host_name1 == host_name:
                        logger.info('ip: %s', ip)
                        logger.info('host_name: %s', host_name)
                        master_ip = ip
                        master_host_name = host_name
                        logger.info('master_ip :%s', master_ip)
                        logger.info('master_host_name :%s', master_host_name)
                        logger.info(
                            'Calling flannel daemon')
                        logger.info(
                            'Calling %s with IP - %s, network - %s, cidr - %s',
                            consts.K8_CONF_FLANNEL_DAEMON_AT_MASTER,
                            master_ip, network,
                            cidr)
                        ret_val = apbl.flannel_daemon(
                            consts.K8_CONF_FLANNEL_DAEMON_AT_MASTER,
                            master_ip, network,
                            cidr,
                            master_plugin,
                            consts.INVENTORY_SOURCE_FOLDER)
                        if not ret_val:
                            logger.error('FAILED IN CREATING FLANNEL NETWORK')

                        ret_val = apbl.copy_flannel_cni(
                            consts.K8_CONF_COPY_FLANNEL_CNI,
                            master_ip,
                            master_host_name,
                            network,
                            consts.INVENTORY_SOURCE_FOLDER)
                        if not ret_val:
                            ret_val = False
                            logger.error(
                                'FAILED IN COPYING FLANNEL CNI')
    logger.info('networkName is %s', network_name)

    ret_hosts = False
    if ret_val:
        time.sleep(30)
        ret_hosts = apbl.create_flannel_interface(
            consts.K8_CONF_FLANNEL_INTF_CREATION_AT_MASTER, master_ip,
            master_host_name, network_name, network, master_plugin,
            consts.INVENTORY_SOURCE_FOLDER, consts.PROXY_DATA_FILE)
        if not ret_hosts:
            ret_hosts = False
            logger.error('FAILED IN CREATING FLANNEL NETWORK')

    return ret_hosts


def create_weave_interface(host_name_map, host_node_type_map,
                           networking_plugin, item):
    """
    This function is used to create weave interace and network
    """
    logger.info("\n Argument List: \n host_name_map: %s\n host_node_type_map: "
                "%s\n networking_plugin: %s\n item: %s", host_name_map,
                host_node_type_map, networking_plugin, item)

    ret_hosts = False
    logger.info('CREATING WEAVE NETWORK')
    network_dict = item.get(consts.WEAVE_NETWORK_DETAILS)
    network_name = network_dict.get(consts.NETWORK_NAME)
    subnet = network_dict.get(consts.SUBNET)
    master_plugin = network_dict.get(consts.MASTER_PLUGIN)
    logger.info('networkName is %s', network_name)
    logger.info('subnet is %s', subnet)

    master_ip = None
    master_host_name = None
    for host_name, node_type in host_node_type_map.items():
        logger.info(consts.K8_CONF_WEAVE_NETWORK_CREATION)
        for host_name1, ip in host_name_map.items():
            if node_type == "master" and host_name1 == host_name:
                logger.info('IP is %s', ip)
                master_ip = ip
                master_host_name = host_name
                ret_hosts = apbl.create_weave_network(
                    consts.K8_CONF_COPY_WEAVE_CNI, ip, host_name,
                    network_name, subnet, master_plugin,
                    consts.INVENTORY_SOURCE_FOLDER,
                    consts.PROXY_DATA_FILE)
                if not ret_hosts:
                    logger.error('FAILED IN CONFIGURING WEAVE INTERFACE')
                    exit(1)

    logger.info('CREATING WEAVE NETWORKS %s, %s', master_ip, master_host_name)
    ret_val = apbl.create_weave_network(
        consts.K8_CONF_WEAVE_NETWORK_CREATION, master_ip, master_host_name,
        network_name, subnet, master_plugin, consts.INVENTORY_SOURCE_FOLDER,
        consts.PROXY_DATA_FILE)
    if not ret_val:
        logger.error('FAILED IN CONFIGURING WEAVE INTERFACE')
        exit(1)

    for host_name, node_type in host_node_type_map.items():
        logger.info(consts.K8_CONF_FILES_DELETION_AFTER_MULTUS)
        for host_name1, ip in host_name_map.items():
            if node_type == "minion" and host_name1 == host_name:
                logger.info('IP is %s', ip)
                logger.info('DELETING CONF FILE')
                ret_hosts = apbl.delete_weave_conf(
                    consts.K8_CONF_FILES_DELETION_AFTER_MULTUS, ip, host_name,
                    networking_plugin, consts.INVENTORY_SOURCE_FOLDER)
                if not ret_hosts:
                    logger.error('FAILED IN CONFIGURING WEAVE INTERFACE')
                    exit(1)
    return ret_hosts


def __hostname_list(hosts):
    logger.info("Argument List: \n hosts: %s", hosts)

    logger.info("Creating host name list")
    out_list = []
    for i in range(len(hosts)):
        name = hosts[i].get(consts.HOST).get(consts.HOST_NAME)
        if name:
            host_name = name
            out_list.append(host_name)
    return out_list


def launch_metrics_server(hostname_map, host_node_type_map):
    logger.info("Argument List: \n hostname_map: %s"
                "\n host_node_type_map: %s", hostname_map, host_node_type_map)
    return_stmnt = False
    logger.info("launch_metrics_server function")
    count = 0
    for host_name, node_type in host_node_type_map.items():
        if node_type == "master" and count == 0:
            logger.info('CONFIGURING METRICS SERVER on - %s ---> %s --> %s',
                        node_type, host_name, hostname_map[host_name])
            count = count + 1
            return_stmnt = apbl.metrics_server(
                consts.K8_METRRICS_SERVER, hostname_map[host_name],
                host_name, consts.PROXY_DATA_FILE)

    logger.info('Exit')
    return return_stmnt


def clean_up_metrics_server(hostname_map, host_node_type_map):
    logger.info("Argument List: \n hostname_map: %s"
                "\n host_node_type_map: %s", hostname_map, host_node_type_map)

    logger.info("clean_up_metrics_server")
    return_stmnt = False
    count = 0

    for host_name, node_type in host_node_type_map.items():
        if node_type == "master" and count == 0:
            count = count + 1
            logger.info('REMOVING METRICS SERVER on - %s ---> %s --> %s',
                        node_type, host_name, hostname_map[host_name])

            return_stmnt = apbl.metrics_server_clean(
                consts.K8_METRRICS_SERVER_CLEAN, hostname_map[host_name],
                host_name, consts.PROXY_DATA_FILE)

    return return_stmnt


def launch_ceph_kubernetes(host_node_type_map,
                           hosts, ceph_hosts):
    """
    This function is used for deploy the ceph
    """
    logger.info("Argument List: \n host_node_type_map: %s\n hosts: %s"
                "\n ceph_hosts: %s", host_node_type_map, hosts, ceph_hosts)

    ret_hosts = False
    master_hostname = None

    for key, node_type1 in host_node_type_map.items():
        if node_type1 == "master":
            master_hostname = key
    if hosts:
        count = 0
        for i in range(len(hosts)):
            logger.info(consts.KUBERNETES_CEPH_DELETE_SECRET)
            node_type = hosts[i].get(consts.HOST).get(consts.NODE_TYPE)
            logger.info(node_type)
            if node_type == "master" and count == 0:
                count = count + 1
                ret_hosts = apbl.delete_secret(
                    consts.KUBERNETES_CEPH_DELETE_SECRET, master_hostname,
                    consts.PROXY_DATA_FILE)
                if not ret_hosts:
                    logger.error('FAILED IN INSTALLING FILE PLAY')
                    exit(1)
    controller_host_name = None
    ceph_controller_ip = None
    flag_second_storage = None

    if ceph_hosts:
        ceph_hostnamelist = __hostname_list(ceph_hosts)
        for i in range(len(ceph_hosts)):
            host_ip = ceph_hosts[i].get(consts.HOST).get(consts.IP)
            host_name = ceph_hosts[i].get(consts.HOST).get(consts.HOSTNAME)
            node_type = ceph_hosts[i].get(consts.HOST).get(consts.NODE_TYPE)
            ret_hosts = apbl.ceph_volume_first(
                consts.KUBERNETES_CEPH_VOL_FIRST, host_name,
                consts.INVENTORY_SOURCE_FOLDER,
                consts.VARIABLE_FILE, consts.PROXY_DATA_FILE, host_ip)
            if not ret_hosts:
                logger.error('FAILED IN INSTALLING FILE PLAY')
                exit(1)
            if node_type == "ceph_controller":
                ceph_controller_ip = ceph_hosts[i].get(
                    consts.HOST).get(consts.IP)
                logger.info('EXECUTING CEPH VOLUME PLAY')
                logger.info(consts.KUBERNETES_CEPH_VOL)
                controller_host_name = host_name
                for j in range(len(ceph_hostnamelist)):
                    osd_host_name = ceph_hostnamelist[j]
                    user_id = ceph_hosts[j].get(consts.HOST).get(consts.USER)
                    passwd = ceph_hosts[j].get(consts.HOST).get(
                        consts.PASSWORD)
                    osd_ip = ceph_hosts[j].get(consts.HOST).get(consts.IP)
                    ret_hosts = apbl.ceph_volume(
                        consts.KUBERNETES_CEPH_VOL, host_name,
                        consts.INVENTORY_SOURCE_FOLDER,
                        consts.VARIABLE_FILE, consts.PROXY_DATA_FILE,
                        osd_host_name, user_id, passwd, osd_ip)
                if not ret_hosts:
                    logger.error('FAILED IN INSTALLING FILE PLAY')
                    exit(1)
        for i in range(len(ceph_hostnamelist)):
            host_name = ceph_hostnamelist[i]
            user_id = ceph_hosts[i].get(consts.HOST).get(consts.USER)
            passwd = ceph_hosts[i].get(consts.HOST).get(consts.PASSWORD)
            logger.info(consts.CEPH_DEPLOY)
            ret_hosts = apbl.ceph_deploy(
                consts.CEPH_DEPLOY, host_name, controller_host_name,
                consts.VARIABLE_FILE, consts.PROXY_DATA_FILE, user_id, passwd)
            if not ret_hosts:
                logger.error('FAILED IN INSTALLING FILE PLAY')
                exit(1)
        logger.info(consts.CEPH_MON)
        ret_hosts = apbl.ceph_mon(consts.CEPH_MON, controller_host_name,
                                  consts.VARIABLE_FILE,
                                  consts.PROXY_DATA_FILE)
        if not ret_hosts:
            logger.error('FAILED IN INSTALLING FILE PLAY')
            exit(1)

        for i in range(len(ceph_hosts)):
            host_name = ceph_hosts[i].get(consts.HOST).get(consts.HOSTNAME)
            node_type = ceph_hosts[i].get(consts.HOST).get(consts.NODE_TYPE)
            flag_second_storage = 0
            if node_type == "ceph_osd":
                flag_second_storage = 1
                second_storage = ceph_hosts[i].get(consts.HOST).get(
                    consts.STORAGE_TYPE)
                logger.info("secondstorage is")
                if second_storage is not None:
                    for j in range(len(second_storage)):
                        storage = second_storage[j]
                        logger.info('EXECUTING CEPH STORAGE PLAY')
                        logger.info(consts.KUBERNETES_CEPH_STORAGE)
                        ret_hosts = apbl.ceph_storage(
                            consts.KUBERNETES_CEPH_STORAGE, host_name,
                            controller_host_name,
                            consts.INVENTORY_SOURCE_FOLDER,
                            consts.VARIABLE_FILE, storage,
                            consts.PROXY_DATA_FILE, node_type)
                        if not ret_hosts:
                            logger.error('FAILED IN INSTALLING FILE PLAY')
                            exit(1)
        for i in range(len(ceph_hostnamelist)):
            host_name = ceph_hostnamelist[i]
            logger.info(consts.CEPH_DEPLOY_ADMIN)
            ret_hosts = apbl.ceph_deploy_admin(
                consts.CEPH_DEPLOY_ADMIN, host_name,
                controller_host_name, consts.VARIABLE_FILE,
                consts.PROXY_DATA_FILE)
            if not ret_hosts:
                logger.error('FAILED IN INSTALLING FILE PLAY')
                exit(1)
        logger.info(consts.CEPH_MDS)
        ret_hosts = apbl.ceph_mon(
            consts.CEPH_MDS, controller_host_name,
            consts.VARIABLE_FILE, consts.PROXY_DATA_FILE)
        if not ret_hosts:
            logger.error('FAILED IN INSTALLING FILE PLAY')
            exit(1)
    if hosts:
        count = 0
        for i in range(len(hosts)):
            host = hosts[i].get(consts.HOST)
            node_type = host.get(consts.NODE_TYPE)
            logger.info(node_type)
            if node_type == "master" and count == 0:
                count = count + 1  # changes for ha
                hostname = host.get(consts.HOSTNAME)
                logger.info(consts.KUBERNETES_CEPH_VOL2)
                logger.info("flag secondstorage is")
                logger.info(flag_second_storage)
                if 1 == flag_second_storage:
                    ceph_claims = ceph_hosts[i].get(consts.HOST).get(
                        consts.CEPH_CLAIMS)
                    for j in range(len(ceph_claims)):
                        ceph_claim_name = ceph_claims[j].get(
                            consts.CLAIM_PARAMETERS).get(
                            consts.CEPH_CLAIM_NAME)
                        logger.info('ceph_claim name is %s', ceph_claim_name)
                        ceph_storage_size = ceph_claims[j].get(
                            consts.CLAIM_PARAMETERS).get(consts.CEPH_STORAGE)
                        logger.info('ceph_storage_size is %s',
                                    ceph_storage_size)
                        ret_hosts = apbl.ceph_volume2(
                            consts.KUBERNETES_CEPH_VOL2, hostname,
                            consts.INVENTORY_SOURCE_FOLDER,
                            consts.VARIABLE_FILE, ceph_storage_size,
                            ceph_claim_name,
                            consts.PROXY_DATA_FILE, controller_host_name,
                            ceph_controller_ip)
                        if not ret_hosts:
                            logger.error('FAILED IN INSTALLING FILE PLAY')
                            exit(1)
    return ret_hosts


def launch_persitent_volume_kubernetes(host_node_type_map,
                                       persistent_vol):
    """
    This function is used for deploy the persistent_volume
    """
    logger.info("Argument List: \n host_node_type_map: %s\n "
                "persistent_vol: %s", host_node_type_map, persistent_vol)

    ret_hosts = False
    count = 0
    for host_name, node_type in host_node_type_map.items():
        if node_type == "master" and count == 0:
            for vol in persistent_vol:
                count = count + 1
                storage_size = vol.get(consts.CLAIM_PARAMETERS).get(
                    consts.STORAGE)
                claim_name = vol.get(consts.CLAIM_PARAMETERS).get(
                    consts.CLAIM_NAME)
                logger.info('EXECUTING PERSISTENT VOLUME PLAY')
                logger.info(consts.KUBERNETES_PERSISTENT_VOL)
                ret_hosts = apbl.persistent_volume(
                    consts.KUBERNETES_PERSISTENT_VOL, host_name,
                    consts.INVENTORY_SOURCE_FOLDER, consts.VARIABLE_FILE,
                    storage_size, claim_name,
                    consts.PROXY_DATA_FILE)
                if not ret_hosts:
                    logger.error('FAILED IN INSTALLING FILE PLAY')
                    exit(1)
    return ret_hosts


def get_host_master_name(project_name):
    logger.info("\n Argument List:\n project_name: %s", project_name)

    config = file_utils.read_yaml(consts.VARIABLE_FILE)
    project_path = config.get(consts.PROJECT_PATH)
    inventory_file_path = project_path + project_name + "/inventory.cfg"
    logger.info("Inventory file path - %s", inventory_file_path)
    master_hostname = None
    with open(inventory_file_path) as file_handle:
        for line in file_handle:
            if re.match("\[kube-master\]", line):
                master_hostname1 = file_handle.next()
                master_hostname = master_hostname1.strip(' \t\n\r')
                logger.info('master_hostname is %s', master_hostname)
    file_handle.close()
    logger.info('Exit')
    return master_hostname


def get_hostname_ip_map_list(project_name):
    logger.info("\n Argument List:\n project_name: %s", project_name)

    config = file_utils.read_yaml(consts.VARIABLE_FILE)
    project_path = config.get(consts.PROJECT_PATH)
    inventory_file_path = project_path + project_name + "/inventory.cfg"
    logger.info("Inventory file path - %s", inventory_file_path)
    hostname_map = {}
    with open(inventory_file_path) as file_handle:
        for line in file_handle:
            if "ansible_ssh_host=" in line:
                host_ip1 = line.split("ansible_ssh_host=", 1)[1]
                host_ip = host_ip1.strip(' \t\n\r')
                host_name = line.split(" ")[0]
                host_name = host_name.strip(' \t\n\r')
                if host_ip:
                    if host_name:
                        hostname_map[host_name] = host_ip
    file_handle.close()
    logger.info(' hostname_map is %s', hostname_map)
    return hostname_map


def get_first_node_host_name(project_name):
    logger.info("\n Argument List:\n project_name: %s", project_name)

    config = file_utils.read_yaml(consts.VARIABLE_FILE)
    project_path = config.get(consts.PROJECT_PATH)
    inventory_file_path = project_path + project_name + "/inventory.cfg"
    logger.info('Inventory file path is %s', inventory_file_path)
    node_hostname = None
    with open(inventory_file_path) as file_handle:
        for line in file_handle:
            if re.match("\[kube-node\]", line):
                node_hostname1 = file_handle.next()
                node_hostname = node_hostname1.strip(' \t\n\r')
                logger.info('node_hostname is %s', node_hostname)
    file_handle.close()
    logger.info('Exit')
    return node_hostname


def launch_cpu_pinning_kubernetes(config, proxy_data_file, variable_file):
    logger.info("Argument List: \n config: %s\n proxy_data_file: %s"
                "\n variable_file: %s", config, proxy_data_file,
                variable_file)

    try:
        logger.info("launch_cpu_pinning_kubernetes")
        ret_val = apbl.cpu_manager_configuration(
            consts.K8_CPU_PINNING_CONFIG, proxy_data_file, variable_file)
    except Exception as e:
        logger.error('CPU MANAGER CONFIGURATION FAILED [%s]', e)
        ret_val = False

    logger.info('Exit')
    return ret_val


def delete_existing_conf_files(dynamic_hostname_map, project_name):
    """
    This function is used to delete existing conf files
    """
    logger.info("Argument List: \n dynamic_hostname_map: %s"
                "\n project_name: %s", dynamic_hostname_map, project_name)

    ret_hosts = False
    logger.info('DELETING EXISTING CONF FILES')
    config = file_utils.read_yaml(consts.VARIABLE_FILE)
    project_path = config.get(consts.PROJECT_PATH)
    inventory_file_path = project_path + project_name + "/k8s-cluster.yml"
    logger.info('Inventory file path is %s', inventory_file_path)
    networking_plugin = None
    with open(inventory_file_path) as file_handle:
        for line in file_handle:
            if "kube_network_plugin:" in line:
                network_plugin1 = line.split("kube_network_plugin:", 1)[1]
                networking_plugin = network_plugin1.strip(' \t\n\r')
                logger.info("networking plugin - %s", networking_plugin)
    file_handle.close()

    for host_name, ip in dynamic_hostname_map.items():
        logger.info('IP is %s', ip)
        logger.info('Hostname is %s', host_name)
        logger.info('EXECUTING DELETE CONF FILES PLAY ON DYNAMIC NODE')
        ret_hosts = apbl.delete_conf_files(
            consts.K8_CONF_FILES_DELETION_AFTER_MULTUS, ip, host_name,
            networking_plugin, consts.INVENTORY_SOURCE_FOLDER)
        if not ret_hosts:
            logger.error('FAILED IN DELETING CONF FILES ON DYNAMIC NODE')
            exit(1)

    return ret_hosts


def enable_cluster_logging(value, project_name, log_level, logging_port):
    """
    This function is used to enable logging in cluster
    :param value:- Check whether to enable logging or not
    :param project_name:- Project name
    :param log_level:
    :param logging_port:
    :return: True/False - True if successful otherwise return false
    """
    logger.info("Argument List:\n value: %s\n project_name: %s\n log_level: "
                "%s\n logging_port: %s", value, project_name, log_level,
                logging_port)

    logger.info('EXECUTING LOGGING ENABLE PLAY')
    logger.info(consts.K8_LOGGING_PLAY)
    ret_val = apbl.enable_loggings(
        consts.K8_LOGGING_PLAY, consts.PROXY_DATA_FILE, consts.VARIABLE_FILE,
        value, project_name, log_level, consts.LOG_FILE_PATH, logging_port)

    logger.info('Exit')

    return ret_val


def delete_existing_conf_files_after_additional_plugins(
        host_name_map, host_node_type_map, networking_plugin):
    """
    This function is used to delete existing conf files
    """
    logger.info("\n Argument List: \n host_name_map: %s\n "
                "host_node_type_map: %s\n networking_plugin: %s",
                host_name_map, host_node_type_map, networking_plugin)

    ret_hosts = False
    logger.info('DELETING EXISTING CONF FILES AFTER MULTUS')
    for host_name, node_type in host_node_type_map.items():
        logger.info(consts.K8_CONF_FILES_DELETION_AFTER_MULTUS)
        for host_name1, ip in host_name_map.items():
            if node_type == "minion" and host_name1 == host_name:
                logger.info('IP is %s', ip)
                logger.info('Hostname is %s', host_name)
                logger.info('EXECUTING DELETE CONF FILES PLAY')
                ret_hosts = apbl.delete_conf_files(
                    consts.K8_CONF_FILES_DELETION_AFTER_MULTUS,
                    ip, host_name, networking_plugin,
                    consts.INVENTORY_SOURCE_FOLDER)
                if not ret_hosts:
                    logger.error('FAILED IN DELETING CONF FILES')
                    exit(1)

    return ret_hosts


def install_kubectl(host_name_map, host_node_type_map, ha_enabled,
                    project_name, config, variable_file, src_package_path):
    """
    This function is used to install kubectl at bootstrap node
    """
    logger.info("\n Argument List: \n host_name_map: %s\n "
                "host_node_type_map: %s\n ha_enabled: %s\n "
                "project_name: %s\n "
                "config: %s\n variable_file: %s\n src_package_path: %s",
                host_name_map,
                host_node_type_map, ha_enabled, project_name, config,
                variable_file,
                src_package_path)

    master_ip = None
    master_host_name = None

    for host_name, node_type in host_node_type_map.items():
        for host_name1, ip in host_name_map.items():
            if node_type == "master" and host_name1 == host_name:
                master_ip = ip
                master_host_name = host_name
                logger.info(master_ip)
                logger.info(master_host_name)
                break

    lb_ip = "127.0.0.1"
    ha_configuration = config.get(consts.KUBERNETES).get(consts.HA_CONFIG)
    if ha_configuration:
        for ha_config_list_data in ha_configuration:
            lb_ip = ha_config_list_data.get(consts.HA_API_EXT_LB).get("ip")

    logger.info("Load balancer ip %s", lb_ip)

    try:
        ret_val = apbl.launch_install_kubectl(
            consts.K8_KUBECTL_INSTALLATION, master_ip, master_host_name,
            ha_enabled, project_name, lb_ip, variable_file,
            src_package_path,
            consts.PROXY_DATA_FILE)
    except Exception as exception_v:
        logger.error('FAILED IN KUBECTL INSTALLTION')
        logger.error(exception_v)
        ret_val = False
        exit(1)

    logger.info('Exit')
    return ret_val


def set_kubectl_context(project_name, variable_file, src_package_path):
    """
    This function is used to set kubectl context
    """
    logger.info("\n Argument List: \n project_name: %s\n variable_file: %s"
                "\n src_package_path: %s", project_name, variable_file,
                src_package_path)

    logger.info('SET KUBECTL CONTEXT')
    try:
        ret_val = apbl.launch_set_kubectl_context(
            consts.K8_ENABLE_KUBECTL_CONTEXT, project_name, variable_file,
            src_package_path, consts.PROXY_DATA_FILE)
    except Exception as e:
        logger.error('FAILED IN SETTING KUBECTL CONTEXT [%s]', e)
        ret_val = False
        exit(1)

    logger.info('Exit')
    return ret_val


def delete_default_weave_interface(host_name_map, host_node_type_map,
                                   hosts_data_dict, project_name):
    """
    This function is used to delete default weave interface
    """
    logger.info("\n Argument List: \n host_name_map: %s\n "
                "host_node_type_map: %s\n hosts_data_dict: %s\n "
                "project_name: %s", host_name_map, host_node_type_map,
                hosts_data_dict, project_name)

    networking_plugin = None
    logger.info('EXECUTING DEFAULT WEAVE INTERFACE DELETION PLAY')

    for item1 in hosts_data_dict:
        for key in item1:
            if key == "Default_Network":
                default_network = item1.get("Default_Network")
                if default_network:
                    networking_plugin = default_network.get(
                        consts.NETWORKING_PLUGIN)
                    network_name = default_network.get(consts.NETWORK_NAME)
                    logger.info('networkName is %s', network_name)

    if networking_plugin != "weave":
        logger.info('DEFAULT NETWORKING PLUGIN IS NOT WEAVE, '
                    'NO NEED TO CLEAN WEAVE')
        ret_hosts = True
        return ret_hosts

    master_ip = None
    master_host_name = None
    network_name = None

    for host_name, node_type in host_node_type_map.items():
        logger.info(consts.K8_DELETE_WEAVE_INTERFACE)
        for host_name1, ip in host_name_map.items():
            if node_type == "master" and host_name1 == host_name:
                master_ip = ip
                master_host_name = host_name
                logger.info('master_ip is %s', master_ip)
                logger.info('master_host_name is %s', master_host_name)
                break

    node_type = "master"
    ret_hosts = apbl.launch_delete_weave_interface(
        consts.K8_DELETE_WEAVE_INTERFACE, master_ip, master_host_name,
        node_type, network_name, consts.INVENTORY_SOURCE_FOLDER,
        consts.PROXY_DATA_FILE)
    if not ret_hosts:
        logger.error('FAILED IN DELETING DEFAULT WEAVE INTERFACE')

    host_name_map_ip = get_hostname_ip_map_list(project_name)
    for host_name, ip in host_name_map_ip.items():
        if master_host_name != host_name:
            logger.info('clean up node ip is %s', ip)
            logger.info('clean up host name is %s', host_name)
            node_type = "minion"
            ret_hosts = apbl.launch_delete_weave_interface(
                consts.K8_DELETE_WEAVE_INTERFACE, ip, host_name,
                node_type, network_name,
                consts.INVENTORY_SOURCE_FOLDER,
                consts.PROXY_DATA_FILE)
            if not ret_hosts:
                logger.error('FAILED IN DELETING WEAVE INTERFACE')

    return ret_hosts


def delete_flannel_interfaces(host_name_map, host_node_type_map,
                              hosts_data_dict, project_name):
    """
    This function is used to delete flannel interfaces
    """
    logger.info("\n Argument List: \n host_name_map: %s\n "
                "host_node_type_map: %s\n hosts_data_dict: %s\n "
                "project_name: %s", host_name_map, host_node_type_map,
                hosts_data_dict, project_name)

    logger.info('EXECUTING FLANNEL INTERFACE DELETION PLAY')
    network_name = None
    master_host_name = None
    master_ip = None

    for item1 in hosts_data_dict:
        for key1 in item1:
            if key1 == "Multus_network":
                multus_network = item1.get("Multus_network")
                for item2 in multus_network:
                    for key2 in item2:
                        if key2 == "CNI_Configuration":
                            cni_configuration = item2.get(
                                "CNI_Configuration")
                            for item3 in cni_configuration:
                                for key3 in item3:
                                    if consts.FLANNEL_NETWORK == key3:
                                        all_hosts = item3.get(
                                            consts.FLANNEL_NETWORK)
                                        for host_data in all_hosts:
                                            hostdetails = host_data.get(
                                                consts.FLANNEL_NETWORK_DETAILS)
                                            network_name = hostdetails.get(
                                                consts.NETWORK_NAME)

        logger.info('networkName :%s', network_name)
    for host_name, node_type in host_node_type_map.items():
        for host_name1, ip in host_name_map.items():
            if node_type == "master" and host_name1 == host_name:
                master_ip = ip
                master_host_name = host_name
                logger.info('master_ip : %s', master_ip)
                logger.info('master_host_name %s', master_host_name)
                break

    try:
        logger.info('DELETING FLANNEL INTERFACE. Master ip - %s, '
                    'Master Host Name - %s', master_ip, master_host_name)
        logger.info(consts.K8_DELETE_FLANNEL_INTERFACE)
        node_type = "master"
        ret_hosts = apbl.launch_delete_flannel_interfaces(
            consts.K8_DELETE_FLANNEL_INTERFACE, master_ip,
            master_host_name, node_type, network_name,
            consts.INVENTORY_SOURCE_FOLDER,
            consts.PROXY_DATA_FILE)
    except Exception as e:
        logger.error('FAILED IN DELETING FLANNEL INTERFACE [%s]', e)
        ret_hosts = False

    host_name_map_ip = get_hostname_ip_map_list(project_name)
    for host_name, ip in host_name_map_ip.items():
        if master_host_name != host_name:
            logger.info("clean up node ip: %s", ip)
            logger.info("clean up host name: %s", host_name)
            node_type = "minion"
            ret_hosts = apbl.launch_delete_flannel_interfaces(
                consts.K8_DELETE_FLANNEL_INTERFACE, ip, host_name,
                node_type, network_name, consts.INVENTORY_SOURCE_FOLDER,
                consts.PROXY_DATA_FILE)
            if not ret_hosts:
                logger.error('FAILED IN DELETING FLANNEL INTERFACE')
                exit(1)

    return ret_hosts


def delete_weave_interface(host_name_map, host_node_type_map,
                           hosts_data_dict, project_name):
    """
    This function is used to delete weave interface
    """
    logger.info("\n Argument List: \n host_name_map: %s\n "
                "host_node_type_map: %s\n hosts_data_dict: %s\n "
                "project_name: %s", host_name_map, host_node_type_map,
                hosts_data_dict, project_name)

    logger.info('EXECUTING WEAVE INTERFACE DELETION PLAY')
    network_name = None
    for item1 in hosts_data_dict:
        for key in item1:
            if key == "Multus_network":
                multus_network = item1.get("Multus_network")
                for item2 in multus_network:
                    for key2 in item2:
                        if key2 == "CNI_Configuration":
                            cni_configuration = item2.get(
                                "CNI_Configuration")
                            for item3 in cni_configuration:
                                for key3 in item3:
                                    if consts.WEAVE_NETWORK == key3:
                                        weave_network = item3.get(
                                            consts.WEAVE_NETWORK)
                                        for weave_item in weave_network:
                                            weave_network1 = weave_item.get(
                                                consts.WEAVE_NETWORK_DETAILS)
                                            network_name = weave_network1.get(
                                                consts.NETWORK_NAME)
                                            logger.info(
                                                'networkName is %s',
                                                network_name)

    hostname_master = None
    ip = None
    host_name = None
    master_ip = None
    master_host_name = None

    for host_name, node_type in host_node_type_map.items():
        logger.info(consts.K8_DELETE_WEAVE_INTERFACE)
        for host_name1, ip in host_name_map.items():
            if node_type == "master" and host_name1 == host_name:
                master_ip = ip
                master_host_name = host_name
                logger.info('master_ip is %s', master_ip)
                logger.info('master_host_name is %s', master_host_name)
                hostname_master = host_name1
                break

    node_type = "master"
    logger.info('DELETING WEAVE INTERFACE.. Master ip: %s, Master Host '
                'Name: %s', ip, host_name)
    ret_hosts = apbl.launch_delete_weave_interface(
        consts.K8_DELETE_WEAVE_INTERFACE, master_ip, master_host_name,
        node_type, network_name, consts.INVENTORY_SOURCE_FOLDER,
        consts.PROXY_DATA_FILE)
    if not ret_hosts:
        logger.error('FAILED IN DELETING WEAVE INTERFACE')

    host_name_map_ip = get_hostname_ip_map_list(project_name)
    for host_name, ip in host_name_map_ip.items():
        if hostname_master != host_name:
            logger.info('clean up node ip is %s', ip)
            logger.info('clean up host name is %s', host_name)
            node_type = "minion"
            ret_hosts = apbl.launch_delete_weave_interface(
                consts.K8_DELETE_WEAVE_INTERFACE, ip, host_name, node_type,
                network_name, consts.INVENTORY_SOURCE_FOLDER,
                consts.PROXY_DATA_FILE)
            if not ret_hosts:
                logger.error('FAILED IN DELETING WEAVE INTERFACE')

    return ret_hosts
