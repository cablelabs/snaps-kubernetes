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
import time

from snaps_common.ansible_snaps import ansible_utils

import ansible_playbook_launcher as apbl
from snaps_k8s.common.consts import consts
from snaps_k8s.common.utils import file_utils

DEFAULT_REPLACE_EXTENSIONS = None

logger = logging.getLogger('ansible_configuration')


def provision_preparation(proxy_dict):
    """
    TODO - REMOVE ME once PROXY_DATA_FILE is no longer being used by playbooks
    This method is responsible for writing the hosts info in ansible hosts file
    proxy inf in ansible proxy file
    : param proxy_dict: proxy data in the dictionary format
    """
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


def clean_up_k8_addons(**k8_addon):
    """
    function to delete all addons : such as metrics server
    :param k8_addon:
    """
    hostname_map = k8_addon.get("hostname_map")
    host_node_type_map = k8_addon.get("host_node_type_map")
    for addon in k8_addon:
        if addon == "metrics_server" and k8_addon.get("metrics_server"):
            clean_up_metrics_server(hostname_map, host_node_type_map)


def clean_up_k8(git_branch, project_name, multus_enabled_str):
    """
    This function is used for clean/Reset the kubernetes cluster
    """
    multus_enabled = str(multus_enabled_str)
    logger.info('multus_enabled_str : %s', multus_enabled)

    logger.info('EXECUTING CLEAN K8 CLUSTER PLAY')
    logger.info(consts.K8_CLEAN_UP)
    ret_hosts = apbl.clean_k8(
        consts.K8_CLEAN_UP,
        consts.SRC_PKG_FLDR,
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
        consts.SRC_PKG_FLDR, project_name,
        consts.PROXY_DATA_FILE)
    if not ret_hosts:
        logger.error('FAILED IN CLEAN UP KUBERNETES CLUSTER ')
        exit(1)


def start_k8s_install(host_name_map, host_node_type_map,
                      host_port_map, service_subnet, pod_subnet,
                      networking_plugin, docker_repo,
                      hosts, git_branch, project_name,
                      k8s_conf, ha_enabled):
    """
    This function is used for deploy the kubernet cluster
    """

    base_pb_vars = {
        'SRC_PACKAGE_PATH': consts.SRC_PKG_FLDR,
    }
    base_pb_vars.update(file_utils.read_yaml(consts.PROXY_DATA_FILE))

    # TODO - UNCOMMENT ME!!!
    # pb_vars = {
    #     'Git_branch': git_branch,
    # }
    # pb_vars.update(base_pb_vars)
    # ansible_utils.apply_playbook(consts.K8_CLONE_PACKAGES, variables=pb_vars)
    #
    # user = getpass.getuser()
    #
    # __set_hostnames(host_name_map, user, base_pb_vars)
    # __configure_docker(host_name_map, host_port_map, user, base_pb_vars)
    #
    # if docker_repo:
    #     __prepare_docker_repo(docker_repo, host_name_map, base_pb_vars)
    #
    # __kubespray(k8s_conf, host_name_map, host_node_type_map, project_name,
    #             service_subnet, pod_subnet, networking_plugin, git_branch,
    #             base_pb_vars)

    __complete_k8s_install(k8s_conf, hosts, host_name_map, host_node_type_map,
                           ha_enabled, project_name, base_pb_vars)

    logger.info('Completed start_k8s_install()')


def modify_user_list(user_name, user_password, user_id):
    apbl.update_user_list(
        consts.KUBERNETES_USER_LIST, user_name, user_password, user_id,
        consts.SRC_PKG_FLDR)


def update_kube_api_manifest_file(master_host_name):
    ret_hosts = apbl.launch_authentication(
        consts.KUBERNETES_AUTHENTICATION, master_host_name,
        consts.SRC_PKG_FLDR, consts.VARIABLE_FILE)
    if not ret_hosts:
        logger.error('FAILED SET HOSTS PLAY')
        exit(1)


def __set_hostnames(host_name_map, user, base_pb_vars):
    ips = list()
    for host_name, ip_val in host_name_map.items():
        ips.append(ip_val)
        ansible_utils.apply_playbook(
            consts.K8_SET_HOSTNAME, hosts_inv=[ip_val], host_user=user,
            variables={'host_name': host_name})

    pb_vars = {
        'APT_ARCHIVES_SRC': consts.APT_ARCHIVES_PATH,
        'APT_CONF_DEST': consts.APT_CONF_DEST
    }
    pb_vars.update(base_pb_vars)
    ansible_utils.apply_playbook(
        consts.K8_SET_PACKAGES, ips, user, password=None,
        variables=pb_vars)


def __configure_docker(host_name_map, host_port_map, user, base_pb_vars):

    ip_val = None
    registry_port = None
    for host_name, ip_val in host_name_map.items():
        registry_port = host_port_map.get(host_name)
        break

    if not ip_val or not registry_port:
        raise Exception('Cannot locate IP or registry port')

    pb_vars = {'registry_port': registry_port,
               'HTTP_PROXY_DEST': consts.HTTP_PROXY_DEST}
    pb_vars.update(base_pb_vars)
    ansible_utils.apply_playbook(
        consts.K8_CONFIG_DOCKER, hosts_inv=[ip_val], host_user=user,
        variables=pb_vars)


def __prepare_docker_repo(docker_repo, host_name_map, base_pb_vars):
    docker_ip = docker_repo.get(consts.IP_KEY)
    docker_port = docker_repo.get(consts.PORT_KEY)
    pb_vars = {
        'docker_ip': docker_ip,
        'docker_port': docker_port,
        'HTTP_PROXY_DEST': consts.HTTP_PROXY_DEST,
    }
    pb_vars.update(base_pb_vars)
    ansible_utils.apply_playbook(consts.K8_PRIVATE_DOCKER,
                                 variables=pb_vars)

    ips = list()
    for host_name, ip in host_name_map.items():
        ips.append(ip)

    pb_vars = {
        'docker_ip': docker_ip,
        'docker_port': docker_port,
        'HTTP_PROXY_DEST': consts.HTTP_PROXY_DEST,
        'DAEMON_FILE': consts.DAEMON_FILE
    }
    pb_vars.update(base_pb_vars)
    ansible_utils.apply_playbook(consts.K8_CONF_DOCKER_REPO, ips,
                                 variables=pb_vars)


def __kubespray(k8s_conf, host_name_map, host_node_type_map, project_name,
                service_subnet, pod_subnet, networking_plugin, git_branch,
                base_pb_vars):
    pb_vars = {
        'SRC_PACKAGE_PATH': consts.SRC_PKG_FLDR,
        'PROJECT_PATH': consts.PROJECT_PATH,
        'Project_name': project_name,
    }
    ansible_utils.apply_playbook(
        consts.K8_CREATE_INVENTORY_FILE, variables=pb_vars)

    for host_name, ip in host_name_map.items():
        pb_vars = {
            'ip': ip,
            'host_name': host_name,
            'SRC_PACKAGE_PATH': consts.SRC_PKG_FLDR,
            'PROJECT_PATH': consts.PROJECT_PATH,
            'Project_name': project_name,
        }
        ansible_utils.apply_playbook(consts.KUBERNETES_NEW_INVENTORY,
                                     variables=pb_vars)

    for host_name, node_type in host_node_type_map.items():
        pb_vars = {
            'node_type': node_type,
            'host_name': host_name,
            'PROJECT_PATH': consts.PROJECT_PATH,
            'Project_name': project_name,
        }
        ansible_utils.apply_playbook(consts.KUBERNETES_CREATE_INVENTORY,
                                     variables=pb_vars)

    pb_vars = {
        'Git_branch': git_branch,
        'Project_name': project_name,
        'KUBESPRAY_PATH': consts.KUBESPRAY_PATH,
        'PROJECT_PATH': consts.PROJECT_PATH,
    }
    pb_vars.update(base_pb_vars)
    ansible_utils.apply_playbook(consts.K8_CLONE_CODE, variables=pb_vars)

    __enable_cluster_logging(k8s_conf, project_name)

    if k8s_conf[consts.K8S_KEY].get(consts.CPU_ALLOC_KEY):
        ansible_utils.apply_playbook(
            consts.K8_CPU_PINNING_CONFIG,
            variables={'KUBESPRAY_PATH': consts.KUBESPRAY_PATH})
    else:
        logger.info('Exclusive_CPU_alloc_support: %s',
                    k8s_conf[consts.K8S_KEY].get(
                        consts.CPU_ALLOC_KEY))

    logger.info('*** EXECUTING INSTALLATION OF KUBERNETES CLUSTER ***')
    kube_version = k8s_conf[consts.K8S_KEY][consts.K8_VER_KEY]
    pb_vars = {
        'service_subnet': service_subnet,
        'pod_subnet': pod_subnet,
        'networking_plugin': networking_plugin,
        'kube_version': kube_version,
        'Git_branch': git_branch,
        'Project_name': project_name,
        'CURRENT_DIR': consts.CWD,
        'host_name_map': host_name_map,
        'PROJECT_PATH': consts.PROJECT_PATH,
        'KUBESPRAY_PATH': consts.KUBESPRAY_PATH,
    }
    pb_vars.update(base_pb_vars)
    ansible_utils.apply_playbook(consts.KUBERNETES_SET_LAUNCHER,
                                 variables=pb_vars)


def launch_crd_network(host_name_map, host_node_type_map):
    """
    This function is used to create crd network
    """
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
        consts.SRC_PKG_FLDR, consts.PROXY_DATA_FILE)
    if not ret_val:
        logger.error('FAILED IN CREATING CRD NETWORK')
        exit(1)


def launch_multus_cni(host_name_map, host_node_type_map, networking_plugin):
    """
    This function is used to launch multus cni
    """
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
                    networking_plugin, consts.SRC_PKG_FLDR,
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
                    networking_plugin, consts.SRC_PKG_FLDR)
                if not ret_hosts:
                    logger.error('FAILED IN SCP MULTUS AT NODE')
                    exit(1)
                logger.info('EXECUTING NODE MULTUS PLAY')
                ret_hosts = apbl.node_multus(
                    consts.K8_MULTUS_SET_NODE, ip, host_name,
                    networking_plugin, consts.SRC_PKG_FLDR)
                if not ret_hosts:
                    logger.error('FAILED IN INSTALLING MULTUS AT NODE')
                    exit(1)

    return ret_hosts


def launch_sriov_cni_configuration(host_node_type_map, hosts_data_dict,
                                   project_name):
    """
    This function is used to launch sriov cni
    """
    minion_list = []
    logger.info('EXECUTING SRIOV CNI PLAY')
    logger.info("INSIDE launch_sriov_cni")
    dpdk_enable = "no"

    inventory_file_path = "{}/{}/{}".format(
        consts.PROJECT_PATH, project_name, "k8s-cluster.yml")
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

    apbl.build_sriov(
        consts.K8_SRIOV_CNI_BUILD, consts.SRC_PKG_FLDR,
        consts.PROXY_DATA_FILE)
    logger.info('DPDK flag is %s', dpdk_enable)
    if dpdk_enable == "yes":
        apbl.build_sriov_dpdk(
            consts.K8_SRIOV_DPDK_CNI, consts.SRC_PKG_FLDR,
            consts.PROXY_DATA_FILE)
    for host_name in get_master_host_name_list(host_node_type_map):
        logger.info('Executing for master %s', host_name)
        logger.info('INSTALLING SRIOV BIN ON MASTER')
        apbl.sriov_install(
            consts.K8_SRIOV_CNI_BIN_INST, host_name,
            consts.SRC_PKG_FLDR)
        if dpdk_enable == "yes":
            logger.info('INSTALLING SRIOV DPDK BIN ON MASTER')
            apbl.sriov_dpdk_install(
                consts.K8_SRIOV_DPDK_CNI_BIN_INST, host_name,
                consts.SRC_PKG_FLDR)

    for host_name in minion_list:
        logger.info('Executing for  minion %s', host_name)
        logger.info('INSTALLING SRIOV BIN ON WORKER nodes')
        apbl.sriov_install(
            consts.K8_SRIOV_CNI_BIN_INST, host_name,
            consts.SRC_PKG_FLDR)
        if dpdk_enable == "yes":
            logger.info('INSTALLING SRIOV DPDK BIN ON WORKERS')
            apbl.dpdk_driver_load(
                consts.K8_SRIOV_DPDK_DRIVER_LOAD, host_name, dpdk_driver)
            apbl.sriov_dpdk_install(
                consts.K8_SRIOV_DPDK_CNI_BIN_INST, host_name,
                consts.SRC_PKG_FLDR)


def launch_sriov_network_creation(host_node_type_map, hosts_data_dict,
                                  project_name):
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
                        master_plugin = network.get(consts.MASTER_PLUGIN_KEY)
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
    logger.info('EXECUTING CREATE DEFAULT NETWORK PLAY')

    subnet = item.get(consts.POD_SUB_KEY)
    network_name = item.get(consts.NETWORK_NAME_KEY)
    master_plugin = item.get(consts.MASTER_PLUGIN_KEY)
    logger.info('subnet is %s', subnet)
    logger.info('networkName is %s', network_name)

    for host_name, node_type in host_node_type_map.items():
        for host_name1, ip in host_name_map.items():
            if node_type == "master" and host_name1 == host_name:
                ret_hosts = apbl.create_default_network(
                    consts.K8_CREATE_DEFAULT_NETWORK, ip, host_name,
                    network_name, subnet, networking_plugin, master_plugin,
                    consts.SRC_PKG_FLDR,
                    consts.PROXY_DATA_FILE)
                if not ret_hosts:
                    logger.error('FAILED IN CREATING DEFAULT NETWORK')

    return ret_hosts


def create_flannel_interface(host_name_map, host_node_type_map,
                             project_name, hosts_data_dict):
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
    logger.info("consts.FLANNEL_NET_TYPE value is %s", consts.FLANNEL_NET_TYPE)
    ret_val = None
    network_name = None
    master_ip = None
    master_host_name = None
    network = None
    master_plugin = None

    if consts.FLANNEL_NET_TYPE == key3:
        all_hosts = item3.get(consts.FLANNEL_NET_TYPE)
        for host_data in all_hosts:
            hostdetails = host_data.get(consts.FLANNEL_NET_DTLS_KEY)
            network_name = hostdetails.get(consts.NETWORK_NAME_KEY)
            network = hostdetails.get(consts.NETWORK_KEY)
            cidr = hostdetails.get(consts.SUBNET_KEY)
            master_plugin = hostdetails.get(consts.MASTER_PLUGIN_KEY)
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
                            consts.SRC_PKG_FLDR)
                        if not ret_val:
                            logger.error('FAILED IN CREATING FLANNEL NETWORK')

                        ret_val = apbl.copy_flannel_cni(
                            consts.K8_CONF_COPY_FLANNEL_CNI,
                            master_ip,
                            master_host_name,
                            network,
                            consts.SRC_PKG_FLDR)
                        if not ret_val:
                            ret_val = False
                            logger.error(
                                'FAILED IN COPYING FLANNEL CNI')
    logger.info('networkName is %s', network_name)

    if ret_val:
        time.sleep(30)
        ret_hosts = apbl.create_flannel_interface(
            consts.K8_CONF_FLANNEL_INTF_CREATION_AT_MASTER, master_ip,
            master_host_name, network_name, network, master_plugin,
            consts.SRC_PKG_FLDR, consts.PROXY_DATA_FILE)
        if not ret_hosts:
            logger.error('FAILED IN CREATING FLANNEL NETWORK')


def create_weave_interface(host_name_map, host_node_type_map,
                           networking_plugin, item):
    """
    This function is used to create weave interace and network
    """
    ret_hosts = False
    logger.info('CREATING WEAVE NETWORK')
    network_dict = item.get(consts.WEAVE_NET_DTLS_KEY)
    network_name = network_dict.get(consts.NETWORK_NAME_KEY)
    subnet = network_dict.get(consts.SUBNET_KEY)
    master_plugin = network_dict.get(consts.MASTER_PLUGIN_KEY)
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
                    consts.SRC_PKG_FLDR,
                    consts.PROXY_DATA_FILE)
                if not ret_hosts:
                    logger.error('FAILED IN CONFIGURING WEAVE INTERFACE')
                    exit(1)

    logger.info('CREATING WEAVE NETWORKS %s, %s', master_ip, master_host_name)
    ret_val = apbl.create_weave_network(
        consts.K8_CONF_WEAVE_NETWORK_CREATION, master_ip, master_host_name,
        network_name, subnet, master_plugin, consts.SRC_PKG_FLDR,
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
                    networking_plugin, consts.SRC_PKG_FLDR)
                if not ret_hosts:
                    logger.error('FAILED IN CONFIGURING WEAVE INTERFACE')
                    exit(1)
    return ret_hosts


def __hostname_list(hosts):
    logger.info("Creating host name list")
    out_list = []
    for i in range(len(hosts)):
        name = hosts[i].get(consts.HOST_KEY).get(consts.HOSTNAME_KEY)
        if name:
            host_name = name
            out_list.append(host_name)
    return out_list


def launch_metrics_server(hostname_map, host_node_type_map):
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

    return return_stmnt


def clean_up_metrics_server(hostname_map, host_node_type_map):
    logger.info("clean_up_metrics_server")
    count = 0

    for host_name, node_type in host_node_type_map.items():
        if node_type == "master" and count == 0:
            count = count + 1
            logger.info('REMOVING METRICS SERVER on - %s ---> %s --> %s',
                        node_type, host_name, hostname_map[host_name])

            apbl.metrics_server_clean(
                consts.K8_METRRICS_SERVER_CLEAN, hostname_map[host_name],
                host_name, consts.PROXY_DATA_FILE)


def launch_ceph_kubernetes(host_node_type_map, hosts, ceph_hosts):
    """
    This function is used for deploy the ceph
    """
    ret_hosts = False
    master_hostname = None

    for key, node_type1 in host_node_type_map.items():
        if node_type1 == "master":
            master_hostname = key
    if hosts:
        count = 0
        for i in range(len(hosts)):
            logger.info(consts.KUBERNETES_CEPH_DELETE_SECRET)
            node_type = hosts[i].get(consts.HOST_KEY).get(consts.NODE_TYPE_KEY)
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
            host_ip = ceph_hosts[i].get(consts.HOST_KEY).get(consts.IP_KEY)
            host_name = ceph_hosts[i].get(consts.HOST_KEY).get(
                consts.HOSTNAME_KEY)
            node_type = ceph_hosts[i].get(consts.HOST_KEY).get(
                consts.NODE_TYPE_KEY)
            ret_hosts = apbl.ceph_volume_first(
                consts.KUBERNETES_CEPH_VOL_FIRST, host_name,
                consts.SRC_PKG_FLDR,
                consts.VARIABLE_FILE, consts.PROXY_DATA_FILE, host_ip)
            if not ret_hosts:
                logger.error('FAILED IN INSTALLING FILE PLAY')
                exit(1)
            if node_type == "ceph_controller":
                ceph_controller_ip = ceph_hosts[i].get(
                    consts.HOST_KEY).get(consts.IP_KEY)
                logger.info('EXECUTING CEPH VOLUME PLAY')
                logger.info(consts.KUBERNETES_CEPH_VOL)
                controller_host_name = host_name
                for j in range(len(ceph_hostnamelist)):
                    osd_host_name = ceph_hostnamelist[j]
                    user_id = ceph_hosts[j].get(consts.HOST_KEY).get(
                        consts.USER_KEY)
                    passwd = ceph_hosts[j].get(consts.HOST_KEY).get(
                        consts.PASSWORD_KEY)
                    osd_ip = ceph_hosts[j].get(consts.HOST_KEY).get(
                        consts.IP_KEY)
                    ret_hosts = apbl.ceph_volume(
                        consts.KUBERNETES_CEPH_VOL, host_name,
                        consts.SRC_PKG_FLDR,
                        consts.VARIABLE_FILE, consts.PROXY_DATA_FILE,
                        osd_host_name, user_id, passwd, osd_ip)
                if not ret_hosts:
                    logger.error('FAILED IN INSTALLING FILE PLAY')
                    exit(1)
        for i in range(len(ceph_hostnamelist)):
            host_name = ceph_hostnamelist[i]
            user_id = ceph_hosts[i].get(consts.HOST_KEY).get(consts.USER_KEY)
            passwd = ceph_hosts[i].get(consts.HOST_KEY).get(
                consts.PASSWORD_KEY)
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
            host_name = ceph_hosts[i].get(consts.HOST_KEY).get(
                consts.HOSTNAME_KEY)
            node_type = ceph_hosts[i].get(consts.HOST_KEY).get(
                consts.NODE_TYPE_KEY)
            flag_second_storage = 0
            if node_type == "ceph_osd":
                flag_second_storage = 1
                second_storage = ceph_hosts[i].get(consts.HOST_KEY).get(
                    consts.STORAGE_TYPE_KEY)
                logger.info("secondstorage is")
                if second_storage is not None:
                    for j in range(len(second_storage)):
                        storage = second_storage[j]
                        logger.info('EXECUTING CEPH STORAGE PLAY')
                        logger.info(consts.KUBERNETES_CEPH_STORAGE)
                        ret_hosts = apbl.ceph_storage(
                            consts.KUBERNETES_CEPH_STORAGE, host_name,
                            controller_host_name,
                            consts.SRC_PKG_FLDR,
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
            host = hosts[i].get(consts.HOST_KEY)
            node_type = host.get(consts.NODE_TYPE_KEY)
            logger.info(node_type)
            if node_type == "master" and count == 0:
                count = count + 1  # changes for ha
                hostname = host.get(consts.HOSTNAME_KEY)
                logger.info(consts.KUBERNETES_CEPH_VOL2)
                logger.info("flag secondstorage is")
                logger.info(flag_second_storage)
                if 1 == flag_second_storage:
                    ceph_claims = ceph_hosts[i].get(consts.HOST_KEY).get(
                        consts.CEPH_CLAIMS_KEY)
                    for j in range(len(ceph_claims)):
                        ceph_claim_name = ceph_claims[j].get(
                            consts.CLAIM_PARAMS_KEY).get(
                            consts.CEPH_CLAIM_NAME_KEY)
                        logger.info('ceph_claim name is %s', ceph_claim_name)
                        ceph_storage_size = ceph_claims[j].get(
                            consts.CLAIM_PARAMS_KEY).get(
                            consts.CEPH_STORAGE_KEY)
                        logger.info('ceph_storage_size is %s',
                                    ceph_storage_size)
                        ret_hosts = apbl.ceph_volume2(
                            consts.KUBERNETES_CEPH_VOL2, hostname,
                            consts.SRC_PKG_FLDR,
                            consts.VARIABLE_FILE, ceph_storage_size,
                            ceph_claim_name,
                            consts.PROXY_DATA_FILE, controller_host_name,
                            ceph_controller_ip)
                        if not ret_hosts:
                            logger.error('FAILED IN INSTALLING FILE PLAY')
                            exit(1)
    return ret_hosts


def launch_persitent_volume_kubernetes(host_node_type_map, persistent_vol):
    """
    This function is used for deploy the persistent_volume
    """
    ret_hosts = False
    count = 0
    for host_name, node_type in host_node_type_map.items():
        if node_type == "master" and count == 0:
            for vol in persistent_vol:
                count = count + 1
                storage_size = vol.get(consts.CLAIM_PARAMS_KEY).get(
                    consts.STORAGE_KEY)
                claim_name = vol.get(consts.CLAIM_PARAMS_KEY).get(
                    consts.CLAIM_NAME_KEY)
                logger.info('EXECUTING PERSISTENT VOLUME PLAY')
                logger.info(consts.KUBERNETES_PERSISTENT_VOL)
                ret_hosts = apbl.persistent_volume(
                    consts.KUBERNETES_PERSISTENT_VOL, host_name,
                    consts.SRC_PKG_FLDR, consts.VARIABLE_FILE,
                    storage_size, claim_name,
                    consts.PROXY_DATA_FILE)
                if not ret_hosts:
                    logger.error('FAILED IN INSTALLING FILE PLAY')
                    exit(1)
    return ret_hosts


def get_host_master_name(k8s_conf):
    """
    Returns the first hostname of type 'master'
    :param k8s_conf: the k8s configuration dict
    :return: the first master hostname
    """
    if ('kubernetes' in k8s_conf
            and 'node_configuration' in k8s_conf['kubernetes']):
        host_confs = k8s_conf['kubernetes']['node_configuration']
        for host_conf in host_confs:
            if host_conf['host']['node_type'] == 'master':
                return host_conf['host']['hostname']

    logger.warn('Unable to access the master host with conf %s', k8s_conf)


def get_hostname_ip_map_list(project_name):
    inventory_file_path = "{}/{}/{}".format(
        consts.PROJECT_PATH, project_name, "inventory.cfg")
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


def __enable_cluster_logging(k8s_conf, project_name):
    """
    This function is used to enable logging in cluster
    :param k8s_conf: k8s config
    :param project_name: Project name
    """
    enable_logging = k8s_conf[consts.K8S_KEY][consts.ENABLE_LOG_KEY]
    if enable_logging is not None:
        if enable_logging is not True and enable_logging is not False:
            raise Exception('Either enabled logging or disabled logging')

        if enable_logging:
            value = "True"
            log_level = k8s_conf[consts.K8S_KEY][consts.LOG_LEVEL_KEY]
            if (log_level != "fatal" and log_level != "warning"
                    and log_level != "info" and log_level != "debug"
                    and log_level != "critical"):
                raise Exception('Invalid log_level')
            logging_port = k8s_conf[consts.K8S_KEY][consts.LOG_PORT_KEY]
            pb_vars = {
                "logging": value,
                'Project_name': project_name,
                "log_level": log_level,
                "file_path": consts.LOG_FILE_PATH,
                "logging_port": logging_port,
                "KUBESPRAY_PATH": consts.KUBESPRAY_PATH,
                "PROJECT_PATH": consts.PROJECT_PATH,
            }
            pb_vars.update(file_utils.read_yaml(consts.PROXY_DATA_FILE))
            ansible_utils.apply_playbook(consts.K8_LOGGING_PLAY,
                                         variables=pb_vars)
    else:
        logger.warn('Logging not configured')


def delete_existing_conf_files_after_additional_plugins(
        host_name_map, host_node_type_map, networking_plugin):
    """
    This function is used to delete existing conf files
    """
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
                    consts.SRC_PKG_FLDR)
                if not ret_hosts:
                    logger.error('FAILED IN DELETING CONF FILES')
                    exit(1)

    return ret_hosts


def __complete_k8s_install(k8s_conf, hosts, host_name_map, host_node_type_map,
                           ha_enabled, project_name, base_pb_vars):

    print '*****'
    # TODO - UNCOMMENT ME!!!
    # __install_kubectl(
    #     host_name_map, host_node_type_map, ha_enabled, project_name, k8s_conf)
    __label_nodes(hosts)
    __config_master(host_node_type_map, base_pb_vars)


def __install_kubectl(host_name_map, host_node_type_map, ha_enabled,
                      project_name, config):
    """
    This function is used to install kubectl at bootstrap node
    """
    ip = None
    host_name = None
    for host_name, node_type in host_node_type_map.items():
        for host_name1, ip in host_name_map.items():
            if node_type == "master" and host_name1 == host_name:
                master_ip = ip
                master_host_name = host_name
                logger.info(master_ip)
                logger.info(master_host_name)
                break

    lb_ip = "127.0.0.1"
    ha_configuration = config[consts.K8S_KEY].get(consts.HA_CONFIG_KEY)
    if ha_configuration:
        for ha_config_list_data in ha_configuration:
            lb_ip = ha_config_list_data.get(consts.HA_API_EXT_LB_KEY).get("ip")

    logger.info("Load balancer ip %s", lb_ip)

    if not ip or not host_name:
        raise Exception('Unable to locate IP or hostname')

    pb_vars = {
        'ip': ip,
        'host_name': host_name,
        'ha_enabled': ha_enabled,
        'Project_name': project_name,
        'lb_ip': lb_ip,
        'PROJECT_PATH': consts.PROJECT_PATH,
        'SRC_PACKAGE_PATH': consts.SRC_PKG_FLDR,
    }
    pb_vars.update(file_utils.read_yaml(consts.PROXY_DATA_FILE))
    ansible_utils.apply_playbook(consts.K8_KUBECTL_INSTALLATION,
                                 variables=pb_vars)


def __config_master(host_node_type_map, base_pb_vars):
    for host_name, node_type in host_node_type_map.items():
        pb_vars = {
            'SRC_PACKAGE_PATH': consts.SRC_PKG_FLDR,
        }
        if node_type == "master":
            ansible_utils.apply_playbook(consts.KUBERNETES_WEAVE_SCOPE,
                                         variables=pb_vars)
            pb_vars = {
                'host_name': host_name,
            }
            pb_vars.update(base_pb_vars)
            ansible_utils.apply_playbook(
                consts.KUBERNETES_KUBE_PROXY, [host_name], variables=pb_vars)
            logger.info('Started KUBE PROXY')


def __label_nodes(hosts):
    for i in range(len(hosts)):
        host = hosts[i].get(consts.HOST_KEY)
        label_key = host.get(consts.LABEL_KEY)
        hostname = host.get(consts.HOSTNAME_KEY)
        label_value = host.get(consts.LBL_VAL_KEY)
        pb_vars = {
            'hostname': hostname,
            'label_key': label_key,
            'label_value': label_value,
        }
        ansible_utils.apply_playbook(
            consts.K8_NODE_LABELING, variables=pb_vars)


def set_kubectl_context(project_name, variable_file, src_package_path):
    """
    This function is used to set kubectl context
    """
    logger.info('SET KUBECTL CONTEXT')
    try:
        ret_val = apbl.launch_set_kubectl_context(
            consts.K8_ENABLE_KUBECTL_CONTEXT, project_name, variable_file,
            src_package_path, consts.PROXY_DATA_FILE)
    except Exception as e:
        logger.error('FAILED IN SETTING KUBECTL CONTEXT [%s]', e)
        ret_val = False
        exit(1)

    return ret_val


def delete_default_weave_interface(host_name_map, host_node_type_map,
                                   hosts_data_dict, project_name):
    """
    This function is used to delete default weave interface
    """
    networking_plugin = None
    logger.info('EXECUTING DEFAULT WEAVE INTERFACE DELETION PLAY')

    for item1 in hosts_data_dict:
        for key in item1:
            if key == "Default_Network":
                default_network = item1.get("Default_Network")
                if default_network:
                    networking_plugin = default_network.get(
                        consts.NET_PLUGIN_KEY)
                    network_name = default_network.get(consts.NETWORK_NAME_KEY)
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
        node_type, network_name, consts.SRC_PKG_FLDR,
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
                consts.SRC_PKG_FLDR,
                consts.PROXY_DATA_FILE)
            if not ret_hosts:
                logger.error('FAILED IN DELETING WEAVE INTERFACE')

    return ret_hosts


def delete_flannel_interfaces(host_name_map, host_node_type_map,
                              hosts_data_dict, project_name):
    """
    This function is used to delete flannel interfaces
    """
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
                                    if consts.FLANNEL_NET_TYPE == key3:
                                        all_hosts = item3.get(
                                            consts.FLANNEL_NET_TYPE)
                                        for host_data in all_hosts:
                                            hostdetails = host_data.get(
                                                consts.FLANNEL_NET_DTLS_KEY)
                                            network_name = hostdetails.get(
                                                consts.NETWORK_NAME_KEY)

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
            consts.SRC_PKG_FLDR,
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
                node_type, network_name, consts.SRC_PKG_FLDR,
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
                                    if consts.WEAVE_NET_TYPE == key3:
                                        weave_network = item3.get(
                                            consts.WEAVE_NET_TYPE)
                                        for weave_item in weave_network:
                                            weave_network1 = weave_item.get(
                                                consts.WEAVE_NET_DTLS_KEY)
                                            network_name = weave_network1.get(
                                                consts.NETWORK_NAME_KEY)
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
        node_type, network_name, consts.SRC_PKG_FLDR,
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
                network_name, consts.SRC_PKG_FLDR,
                consts.PROXY_DATA_FILE)
            if not ret_hosts:
                logger.error('FAILED IN DELETING WEAVE INTERFACE')

    return ret_hosts
