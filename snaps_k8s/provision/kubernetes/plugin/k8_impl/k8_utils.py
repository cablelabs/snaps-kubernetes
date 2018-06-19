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

"""
Purpose : kubernetes Provisioning
Date :27/12/2017
Created By :Aricent
"""
import logging
import re
import subprocess
import time

import netaddr
import os
from pathlib import Path

import snaps_k8s.ansible_p.ansible_utils.ansible_configuration as aconf
import snaps_k8s.ansible_p.ansible_utils.ansible_playbook_launcher as apbl
from snaps_k8s.common.consts import consts
from snaps_k8s.common.utils import file_utils

logger = logging.getLogger('k8_utils')


def execute(config):
    if config:
        logger.info('host entries')
        hosts = config.get(consts.KUBERNETES).get(consts.HOSTS)
        __add_ansible_hosts(hosts)
        proxy_dic = __create_proxy_dic(config)
        logger.info('PROXY - %s', proxy_dic)
        ret = aconf.provision_preparation(proxy_dic)
        if not ret:
            logger.error('FAILED IN SET PROXY')
            exit(1)

        logger.info('enable ssh key')
        hosts = config.get(consts.KUBERNETES).get(consts.HOSTS)
        __enable_key_ssh(hosts)
        hostname_map = __get_hostname_map(hosts)
        host_node_type_map = __create_host_nodetype_map(hosts)
        hosts_data_dict = get_sriov_nw_data(config)
        host_port_map = __create_host_port_map(hosts)

        # duplicate ip check start
        networks = config.get(consts.KUBERNETES).get(consts.NETWORKS)
        default_network_items = get_network_item(
            networks, "Default_Network").get("Default_Network")
        multus_network = get_multus_network(networks).get("Multus_network")
        multus_cni = get_multus_network_elements(multus_network, "CNI")
        multus_cni_configuration = get_multus_network_elements(
            multus_network, "CNI_Configuration")
        if multus_cni:
            range_network_list = __get_net_ip_range(
                hostname_map=hostname_map, multus_cni=multus_cni,
                networks=multus_cni_configuration,
                default_network_items=default_network_items)
            ret = __validate_net_ip_range(range_network_list[0],
                                          range_network_list[1],
                                          range_network_list[2])
            if not ret:
                logger.error(
                    'VALIDATION FAILED IN NETWORK CONFIGURATION: '
                    'OVERLAPPING IPS ARE FOUND')
                exit(0)
        # duplicate ip check end

        logger.info("PROVISION_PREPARATION AND DEPLOY METHOD CALLED")
        networks = config.get(consts.KUBERNETES).get(consts.NETWORKS)
        logger.info(networks)

        service_subnet = None
        pod_subnet = None
        networking_plugin = None

        for item1 in networks:
            for key in item1:
                if key == "Default_Network":
                    default_network = item1.get(consts.DEFAULT_NETWORK)
                    if default_network:
                        service_subnet = default_network.get(
                            consts.SERVICE_SUBNET)
                        logger.info("Service subnet = " + service_subnet)
                        pod_subnet = default_network.get(consts.POD_SUBNET)
                        logger.info("pod_subnet = " + pod_subnet)
                        networking_plugin = default_network.get(
                            consts.NETWORKING_PLUGIN)
                        logger.info("networking_plugin= " + networking_plugin)

        enable_istio = config.get(consts.KUBERNETES).get(consts.ENABLE_ISTIO)
        enable_ambassador = config.get(consts.KUBERNETES).get(
            consts.ENABLE_AMBASSADOR)
        ambassador_rbac = config.get(consts.KUBERNETES).get(
            consts.AMBASSADOR_RBAC)
        logger.info(enable_istio)
        docker_repo = config.get(consts.KUBERNETES).get(consts.DOCKER_REPO)
        if docker_repo:
            docker_ip = docker_repo.get(consts.IP)
            docker_user = docker_repo.get(consts.USER)
            docker_pass = docker_repo.get(consts.PASSWORD)
            logger.info("enable ssh key")
            __pushing_key(docker_ip, docker_user, docker_pass)

        hosts = config.get(consts.KUBERNETES).get(consts.HOSTS)
        project_name = config.get(consts.KUBERNETES).get(consts.PROJECT_NAME)
        logger.info('Project Name - %s', project_name)
        git_branch = config.get(consts.KUBERNETES).get(consts.GIT_BRANCH)
        logger.info('Git Branch Name - %s', git_branch)
        ret = aconf.launch_provisioning_kubernetes(
            hostname_map, host_node_type_map, host_port_map, service_subnet,
            pod_subnet, networking_plugin, enable_istio, docker_repo, hosts,
            git_branch, enable_ambassador, ambassador_rbac, project_name)
        if not ret:
            logger.error('FAILED IN DEPLOY')
            exit(1)
        logger.info("cephhost creation")
        ceph_hosts = config.get(consts.KUBERNETES).get(
            consts.PERSISTENT_VOLUME).get(consts.CEPH_VOLUME)
        if ceph_hosts:
            __add_ansible_hosts(ceph_hosts)
            logger.info("enable ssh key for ceph IPs")
            __enable_key_ssh(ceph_hosts)
            ret = aconf.launch_ceph_kubernetes(
                host_node_type_map, hosts, ceph_hosts)
            if not ret:
                logger.error('FAILED IN CEPH DEPLOY')
                exit(1)
        logger.info('Persistent host volume Start')
        persistent_vol = config.get(consts.KUBERNETES).get(
            consts.PERSISTENT_VOLUME).get(consts.HOST_VOL)
        if persistent_vol:
            ret = aconf.launch_persitent_volume_kubernetes(
                host_node_type_map, persistent_vol)
            if not ret:
                logger.error('FAILED IN DEPLOY')
                exit(1)
        logger.info("Additioanl N/W plugins")
        multus_cni_installed = False
        multus_enabled = get_multus_cni_value(config)
        logger.info('multus_enabled: %s', multus_enabled)
        macvlan_cni = get_macvlan_value(config)
        logger.info('macvlan value: %s', macvlan_cni)
        dhcp_cni = get_dhcp_value(config)
        logger.info('dhcp value: %s', dhcp_cni)

        if multus_enabled:
            logger.info('crdNetwork creation')
            time.sleep(10)
            ret = aconf.launch_crd_network(hostname_map, host_node_type_map)
            if not ret:
                logger.error('FAILED IN CRD CREATION')
                exit(1)

            ret = aconf.launch_multus_cni(
                hostname_map, host_node_type_map, networking_plugin)
            if not ret:
                logger.error('FAILED IN MULTUS CONFIGURATION')
                exit(1)
            else:
                logger.info(
                    'MULTUS CONFIGURED SUCCESSFULLY.. NOW CREATING DEFAULT '
                    'PLUGIN NETWORK')
                multus_cni_installed = True
                if "none" != networking_plugin:
                    ret = __create_default_network_multus(
                        config, hostname_map, host_node_type_map,
                        networking_plugin)
                    if not ret:
                        logger.error('FAILED IN CREATING DEFAULT NETWORK')
                    else:
                        logger.info('SUCCESSFULLY CREATED DEFAULT NETWORK')

            networks = config.get(consts.KUBERNETES).get(consts.NETWORKS)
            multus_network = get_multus_network(networks).get("Multus_network")
            multus_cni = get_multus_network_elements(multus_network, "CNI")
            logger.info('multus_cni: %s', multus_cni)
            for cni in multus_cni:
                logger.info('cni: %s', cni)
                if multus_cni_installed:
                    if "sriov" == cni:
                        logger.info('Sriov Network Plugin')
                        project_name = config.get(consts.KUBERNETES).get(
                            consts.PROJECT_NAME)
                        ret = aconf.launch_sriov_cni_configuration(
                            host_node_type_map, hosts_data_dict,
                            project_name)
                        if not ret:
                            logger.error('FAILED IN SRIOV CNI Creation ')

                        ret = aconf.launch_sriov_network_creation(
                            hosts_data_dict, project_name)
                        if not ret:
                            logger.error('FAILED IN SRIOV NW Creation ')

                    elif consts.FLANNEL == cni:
                        logger.info('Flannel Network Plugin')
                        ret = launch_flannel_interface(config, hostname_map,
                                                       host_node_type_map,
                                                       networking_plugin,
                                                       project_name)
                        if not ret:
                            logger.error(
                                'FAILED IN FLANNEL INTERFACE CREATION')
                    elif consts.WEAVE == cni:
                        logger.info('Weave Network Plugin')
                        ret = __launch_weave_interface(config, hostname_map,
                                                       host_node_type_map,
                                                       networking_plugin)
                        if not ret:
                            logger.error('FAILED IN WEAVE INTERFACFE CREATION')
                    elif "macvlan" == cni:
                        logger.info('Macvlan Network Plugin')
                        if multus_cni_installed:
                            if macvlan_cni:
                                logger.info('CONFIGURING MAC-VLAN')
                                __macvlan_installation(config)
                            else:
                                logger.info(
                                    'MAC-VLAN CONFIGURATION  EXIT , '
                                    'REASON--> MACVLAN  IS DISABLED ')
                    elif "dhcp" == cni:
                        logger.info('DHCP Network Plugin')
                        if multus_cni_installed:
                            if dhcp_cni:
                                logger.info('CONFIGURING DHCP')
                                __dhcp_installation(config)
                            else:
                                logger.info(
                                    'DHCP CONFIGURATION  EXIT , '
                                    'REASON--> DHCP  IS DISABLED ')

                else:
                    logger.info('MULTUS CNI INSTALLTION FAILED')
        else:
            logger.info('MULTUS CNI IS DISABLED')

        if multus_cni_installed:
            time.sleep(100)
            ret = aconf.delete_existing_conf_files_after_additional_plugins(
                hostname_map, host_node_type_map, networking_plugin)
            if not ret:
                logger.error('FAILED IN DELETING EXISTING CONF FILE')
                exit(1)
        logger.info('Enabling Authentication')
        basic_authentication = config.get(consts.KUBERNETES).get(
            consts.BASIC_AUTHENTICATION)
        ret = __enabling_basic_authentication(basic_authentication,
                                              project_name)
        if not ret:
            logger.error('FAILED IN DEPLOY')
            exit(1)

        logger.info("etcd changes")
        ret = _modifying_etcd_node(hostname_map, host_node_type_map)
        if not ret:
            logger.error('FAILED IN DEPLOY')
            exit(1)
        logger.info('Metrics Server')

        metrics_server = config.get(consts.KUBERNETES).get(
            consts.METRICS_SERVER)
        if metrics_server:
            logger.info('Metrics server configuration')
            ret = aconf.launch_metrics_server(
                hostname_map, host_node_type_map)

        return ret


def ip_var_args(*argv):
    if len(argv) % 2:
        logger.info("Invalid configuration")
        exit()

    for i in range(len(argv)):
        if i % 2:
            continue

        start_ip = int(netaddr.IPAddress(argv[i]))
        end_ip = int(netaddr.IPAddress(argv[i + 1]))
        for j in range(len(argv)):
            if j % 2:
                continue
            if i == j:
                continue
            if int(netaddr.IPAddress(argv[j])) <= start_ip <= int(
                    netaddr.IPAddress(argv[j + 1])) or int(
                netaddr.IPAddress(argv[j])) <= end_ip <= int(
                netaddr.IPAddress(argv[j + 1])):
                logger.error('Alert ! IPs ranges are intermingled')
                return False
        return True


def __validate_net_ip_range(net_names, range_start_dict, range_end_dict):
    ret = True
    __check_dup_start_end_ip(net_names, range_start_dict)
    __check_dup_start_end_ip(net_names, range_end_dict)
    count = 0
    length_of_elements = len(net_names)
    while count < int(length_of_elements):
        count1 = count + 1
        while count1 < int(length_of_elements):
            if not ip_var_args(
                    range_start_dict.get(net_names[count]),
                    range_end_dict.get(net_names[count]),
                    range_start_dict.get(net_names[count1]),
                    range_end_dict.get(net_names[count1])):
                return False
            count1 = count1 + 1
        count = count + 1
    return ret


def __check_dup_start_end_ip(net_names, range_dict):
    final_list = []
    for network in net_names:
        if range_dict.get(network) not in final_list:
            final_list.append(range_dict.get(network))
        else:
            logger.error("duplicate network name found - %s with ip %s",
                         network, range_dict.get(network))
            return False
    return True


def get_multus_network(networks):
    for network_item in networks:
        for key in network_item:
            if key == "Multus_network":
                return network_item


def get_network_item(networks, network_list_item):
    for network_item in networks:
        for key in network_item:
            if key == network_list_item:
                return network_item


def get_multus_network_elements(multus_network, element):
    for item in multus_network:
        for key in item:
            if key == element:
                return item[key]


def __network_dict(networks, net_type):
    for network in networks:
        for key in network:
            if key == net_type:
                return network.get(net_type)


def __get_net_ip_range(**kargs):
    multus_cni = kargs.get("multus_cni")
    networks = kargs.get("networks")
    default_network_items = kargs.get("default_network_items")
    start_range_dict = {}
    end_range_dict = {}
    network_name_list = []
    default_cni_plugin = default_network_items.get("networking_plugin")

    if default_cni_plugin is None:
        start_range_dict = {}
        end_range_dict = {}
        network_name_list = []
    for cni in multus_cni:
        if cni == "sriov":
            for host in __network_dict(networks, "Sriov"):
                for key in host:
                    for network_item in host.get(key).get('networks'):
                        if network_item.get("type") == "host-local":
                            start_range_dict[network_item.get(
                                "network_name")] = network_item.get(
                                "rangeStart")
                            end_range_dict[network_item.get(
                                "network_name")] = network_item.get("rangeEnd")
                            network_name_list.append(
                                network_item.get("network_name"))
        elif cni == "macvlan":
            for macvlan_network in __network_dict(networks, "Macvlan"):
                if macvlan_network.get("macvlan_networks").get(
                        "type") == "host-local":
                    start_range_dict[
                        macvlan_network.get("macvlan_networks").get(
                            "network_name")] = macvlan_network.get(
                        "macvlan_networks").get("rangeStart")
                    end_range_dict[macvlan_network.get("macvlan_networks").get(
                        "network_name")] = macvlan_network.get(
                        "macvlan_networks").get("rangeEnd")
                    network_name_list.append(
                        macvlan_network.get("macvlan_networks").get(
                            "network_name"))
    return network_name_list, start_range_dict, end_range_dict


def clean_k8(config):
    """
    This method is used for cleanup of kubernetes cluster
    :param config :input configuration file
    :return ret :t/f
    """
    if config:
        hosts = config.get(consts.KUBERNETES).get(consts.HOSTS)

        logger.info('Host entries - %s', hosts)
        __add_ansible_hosts(hosts)
        __enable_key_ssh(hosts)
        hostname_map = __get_hostname_map(hosts)
        host_node_type_map = __create_host_nodetype_map(hosts)
        enable_istio = config.get(consts.KUBERNETES).get(consts.ENABLE_ISTIO)
        enable_ambassador = config.get(consts.KUBERNETES).get(
            consts.ENABLE_AMBASSADOR)
        ambassador_rbac = config.get(consts.KUBERNETES).get(
            consts.AMBASSADOR_RBAC)
        git_branch = config.get(consts.KUBERNETES).get(consts.GIT_BRANCH)
        logger.info('Git Branch Name - %s', git_branch)
        project_name = config.get(consts.KUBERNETES).get(consts.PROJECT_NAME)
        logger.info('Project Name - %s', project_name)

        networks = config.get(consts.KUBERNETES).get(consts.NETWORKS)
        networking_plugin = None
        for item1 in networks:
            for key in item1:
                if key == "Default_Network":
                    default_network = item1.get(consts.DEFAULT_NETWORK)
                    if default_network:
                        service_subnet = default_network.get(
                            consts.SERVICE_SUBNET)
                        logger.info("Service subnet = " + service_subnet)
                        pod_subnet = default_network.get(consts.POD_SUBNET)
                        logger.info("pod_subnet = " + pod_subnet)
                        networking_plugin = default_network.get(
                            consts.NETWORKING_PLUGIN)
                        logger.info("networking_plugin= " + networking_plugin)
                    else:
                        logger.info(
                            'error: Default network configurations are not '
                            'defined')

        ret = clean_up_flannel(hostname_map, host_node_type_map,
                               networking_plugin, config, project_name)
        if not ret:
            logger.error('FAILED IN FLANNEL CLEANUP')

        ret = clean_up_weave(hostname_map, host_node_type_map,
                             networking_plugin, config, project_name)
        if not ret:
            logger.error('FAILED IN WEAVE CLEANUP')

        logger.info('MACVLAN REMOVAL FOR CLUSTER')
        ret = macvlan_cleanup(config)
        if ret:
            logger.info('MACVLAN REMOVED SUCCESSFULLY')
        else:
            logger.info('MACVLAN NOT REMOVED')
        metrics_server = config.get(consts.KUBERNETES).get(
            consts.METRICS_SERVER)
        logger.info("metrics_server flag in kube8 deployment file is " + str(
            metrics_server))
        aconf.clean_up_k8_addons(hostname_map=hostname_map,
                                 host_node_type_map=host_node_type_map,
                                 metrics_server=metrics_server)
        ret = aconf.clean_up_k8(
            enable_istio, git_branch, enable_ambassador, ambassador_rbac,
            project_name)
        if not ret:
            logger.error('FAILED IN CLEANUP')
            exit(1)

        return ret


def dynamic_node_add_and_del(config, operation):
    """
    This method is used for deploy nodes of kubernetes cluster
    :param config: input configuration file
    :param operation: the operation
    :return ret :t/f
    """
    ret = False
    if config:

        logger.info('dynamic host entries in /etc/ansible/host file')
        hosts = config.get(consts.KUBERNETES).get(consts.HOSTS)
        __add_ansible_hosts(hosts)
        logger.info('enable ssh on dynamic host')
        __enable_key_ssh(hosts)
        logger.info('dynamic host name map list')
        dynamic_hostname_map = __get_hostname_map(hosts)
        logger.info("Dynamic hostname and IP map")
        logger.info(dynamic_hostname_map)
        dynamic_host_node_type_map = __create_host_nodetype_map(hosts)
        logger.info('Dynamic hostname and node type map - %s',
                    dynamic_host_node_type_map)
        hostnamelist = __hostname_list(hosts)
        logger.info('Dynamic hostname list - %s', hostnamelist)
        project_name = config.get(consts.KUBERNETES).get(consts.PROJECT_NAME)
        host_port_map = __create_host_port_map(hosts)
        master_ip = get_master_ip(project_name)

        if operation is "dynamic_deploy_k8":
            logger.info('Deploy dynamic node')
            ret = aconf.deploy_k8_nodes(hostnamelist,
                                        dynamic_hostname_map,
                                        dynamic_host_node_type_map,
                                        host_port_map, hosts,
                                        project_name,
                                        master_ip)
            if not ret:
                logger.error('FAILED IN DEPLOY NODES')
                exit(1)

            multus_cni_installed = False
            multus_enabled = get_multus_cni_value(config)
            logger.info('multus_enabled: %s', multus_enabled)
            macvlan_cni = get_macvlan_value(config)
            logger.info('macvlan value: %s', macvlan_cni)
            dhcp_cni = get_dhcp_value(config)
            logger.info('dhcp value for dynamic added node: %s', dhcp_cni)

            networks = config.get(consts.KUBERNETES).get(consts.NETWORKS)
            multus_network = get_multus_network(networks).get("Multus_network")
            multus_cni = get_multus_network_elements(multus_network, "CNI")
            if multus_enabled:
                ret = aconf.launch_multus_cni_dynamic_node(
                    dynamic_hostname_map, master_ip, project_name)
                if not ret:
                    logger.error('FAILED IN MULTUS CONFIGURATION')
                    exit(1)
                else:
                    logger.info('MULTUS CONFIGURED SUCCESSFULLY')
                    multus_cni_installed = True

                cni = None
                if multus_cni_installed:
                    for cni in multus_cni:
                        if consts.FLANNEL == cni:
                            logger.info(
                                'FLANNEL PLUGIN IS ONLY SUPPORTED AT INIT '
                                'TIME')
                        elif consts.WEAVE == cni:
                            logger.info(
                                'WEAVE PLUGIN IS ONLY SUPPORTED AT INIT TIME')
                        elif "sriov" == cni:
                            logger.info('SRIOV CONFIGURATION ON DYNAMIC NODES')
                            hosts_data_dict = get_sriov_nw_data(config)
                            project_name = config.get(consts.KUBERNETES).get(
                                consts.PROJECT_NAME)
                            aconf.launch_sriov_cni_configuration(
                                dynamic_host_node_type_map, hosts_data_dict,
                                project_name)
                            ret = aconf.launch_sriov_network_creation(
                                hosts_data_dict, project_name)
                            if not ret:
                                logger.error(
                                    'SRIOV CONFIGURATION FAILED IN DYNAMIC '
                                    'NODES')

                        elif "macvlan" == cni:
                            logger.info(
                                'MACVLAN INSTALLATION ON DYNAMICALLY ADDED '
                                'NODES')
                            ret = macvlan_creation_node(config,
                                                        multus_cni_installed)
                            if ret:
                                logger.info('Macvlan installed for node')
                            else:
                                logger.info('Macvlan not installed on nodes')

                time.sleep(100)
                ret = aconf.delete_existing_conf_files(
                    dynamic_hostname_map, project_name)
                if not ret:
                    logger.error('FAILED IN DELETING EXISTING CONF FILE')
                    exit(1)

                elif "dhcp" == cni:
                    logger.info('DHCP Network Plugin dynamic added node')
                    if multus_cni_installed:
                        if dhcp_cni:
                            logger.info('CONFIGURING DHCP')
                            ret = __dhcp_installation(config)
                        else:
                            logger.info(
                                'DHCP CONFIGURATION  EXIT , REASON--> DHCP '
                                'IS DISABLED ')
                            ret = False
        elif operation is "dynamic_clean_k8":
            logger.info('MACVLAN CLEANUP FOR DYNAMICALLY ADDED NODES')
            macvlan_cni = get_macvlan_value(config)
            logger.info('macvlan value : %s', macvlan_cni)
            if macvlan_cni:
                ret = macvlan_removal_node(config)
                if ret:
                    logger.info('MACVLAN REMOVED FOR DYNAMICALLY ADDED NODES')
                else:
                    logger.info(
                        'MACVLAN NOT REMOVED FOR DYNAMICALLY ADDED NODES')
            else:
                logger.info(
                    'MAC-VLAN CONFIGURATION  EXIT , REASON--> MACVLAN  IS '
                    'DISABLED')

            logger.info("FLANNEL CLEANUP FOR DYNAMICALLY ADDED NODES")
            ret = aconf.clean_up_flannel_dynamic_node(dynamic_hostname_map)
            if not ret:
                logger.error("FLANNEL NOT REMOVED FOR DYNAMICALLY ADDED NODES")

            ret = aconf.clean_up_weave_dynamic_node(dynamic_hostname_map)
            if not ret:
                logger.error("WEAVE NOT REMOVED FOR DYNAMICALLY ADDED NODES")

            logger.info("Clean dynamic node")
            ret = aconf.clean_up_k8_nodes(
                dynamic_hostname_map, project_name)
            if not ret:
                logger.error('FAILED IN CLEAN NODES')
                exit(1)

        return ret


def __pushing_key(host_ip, user_name, password):
    """Pushing key to host"""
    logger.info('PUSHING KEY TO HOSTS')
    command = "sshpass -p %s ssh-copy-id -o StrictHostKeyChecking=no %s@%s" % (
        password, user_name, host_ip)
    res = subprocess.call(command, shell=True)
    if not res:
        logger.info(
            'ERROR IN PUSHING KEY:Probaly the key is already present in '
            'remote host')
    logger.info('SSH KEY BASED AUTH ENABLED')


def __enable_key_ssh(hosts):
    """Enable SSH key function"""
    push_key_cmd = "{} {}".format(
        "sed -i '/#host_key_checking/c\host_key_checking = False'",
        consts.ANSIBLE_CONF)
    subprocess.call(push_key_cmd, shell=True)

    command_time = "{} {}".format(
        "sed -i '/#timeout = 10/c\\timeout = 50'", consts.ANSIBLE_CONF)
    subprocess.call(command_time, shell=True)
    for i in range(len(hosts)):
        user_name = hosts[i].get(consts.HOST).get(consts.USER)
        if user_name != 'root':
            logger.info('USER MUST BE ROOT')
            exit(0)
        password = hosts[i].get(consts.HOST).get(consts.PASSWORD)
        check_dir = os.path.isdir(consts.SSH_PATH)
        keygen_command = "{} {}".format(
            'echo -e y|ssh-keygen -b 2048 -t',
            'rsa -f /root/.ssh/id_rsa -q -N ""')
        if not check_dir:
            os.makedirs(consts.SSH_PATH)
            logger.info('GENERATING SSH KEY')
            subprocess.call(keygen_command, shell=True)
        check_dir = os.path.isdir(consts.SSH_PATH)
        if check_dir:
            id_rsa_pub = Path("/root/.ssh/id_rsa.pub")
            id_rsa = Path("/root/.ssh/id_rsa")
            if not id_rsa.is_file():
                if id_rsa_pub.is_file():
                    os.remove("/root/.ssh/id_rsa.pub")
                logger.info('GENERATING SSH KEY')
                subprocess.call(keygen_command, shell=True)
            if not id_rsa_pub.is_file():
                if id_rsa.is_file():
                    os.remove("/root/.ssh/id_rsa")
                logger.info('GENERATING SSH KEY')
                subprocess.call(keygen_command, shell=True)
            ip = hosts[i].get(consts.HOST).get(consts.IP)
            host_ip = ip

            logger.info('PUSHING KEY TO HOSTS')
            push_key_cmd = "sshpass -p '%s' ssh-copy-id -o StrictHostKeyChecking=no %s@%s" % (
                password, user_name, host_ip)
            logger.info(push_key_cmd)
            res = subprocess.call(push_key_cmd, shell=True)
            if not res:
                logger.info(
                    'ERROR IN PUSHING KEY:Probaly the key is already present '
                    'in remote host')
            logger.info('SSH KEY BASED AUTH ENABLED')
    return True


def __hostname_list(hosts):
    """Creating Host name list function"""
    logger.info("Creating host name list")
    out_list = []
    for i in range(len(hosts)):
        name = hosts[i].get(consts.HOST).get(consts.HOSTNAME)
        if name:
            host_name = name
            out_list.append(host_name)

    return out_list


def __create_proxy_dic(config):
    """Creating proxy dictionary function"""
    logger.info("Creating Proxy dictionary")
    proxy_dic = {}
    http_proxy = config.get(consts.KUBERNETES).get(consts.PROXIES).get(
        consts.HTTP_PROXY)
    https_proxy = config.get(consts.KUBERNETES).get(consts.PROXIES).get(
        consts.HTTPS_PROXY)
    ftp_proxy = config.get(consts.KUBERNETES).get(consts.PROXIES).get(
        consts.FTP_PROXY)
    no_proxy = config.get(consts.KUBERNETES).get(consts.PROXIES).get(
        consts.NO_PROXY)

    if http_proxy:
        proxy_dic['http_proxy'] = "\"" + http_proxy + "\""
    else:
        proxy_dic['http_proxy'] = ''
    if https_proxy:
        proxy_dic['https_proxy'] = "\"" + https_proxy + "\""
    else:
        proxy_dic['https_proxy'] = ''
    if ftp_proxy:
        proxy_dic['ftp_proxy'] = "\"" + ftp_proxy + "\""
    else:
        proxy_dic['ftp_proxy'] = ''
    if no_proxy:
        proxy_dic['no_proxy'] = "\"" + no_proxy + "\""
    else:
        proxy_dic['no_proxy'] = ''
    logger.info("Done with proxies")
    return proxy_dic


def get_sriov_nw_data(config):
    num_net = config.get(consts.KUBERNETES).get(consts.NETWORKS)
    cni_configuration = None
    for item1 in num_net:
        for key1 in item1:
            if key1 == "Multus_network":
                multus_network = item1.get("Multus_network")
                for item2 in multus_network:
                    for key2 in item2:
                        if key2 == "CNI_Configuration":
                            cni_configuration = item2.get("CNI_Configuration")

    return cni_configuration


def __get_credentials(config):
    credential_dic = {}
    hosts = config.get(consts.KUBERNETES).get(consts.HOSTS)
    for i in range(len(hosts)):
        user = hosts[i].get(consts.HOST).get(consts.USER)
        password = hosts[i].get(consts.HOST).get(consts.PASSWORD)
        credential_dic['user'] = user
        credential_dic['password'] = password
    return credential_dic


def __get_hostname_map(hosts):
    hostname_map = {}
    if hosts:
        for i in range(len(hosts)):
            hostname = hosts[i].get(consts.HOST).get('hostname')
            host_ip = ""
            ip = hosts[i].get(consts.HOST).get(consts.IP)
            if ip:
                host_ip = ip
            hostname_map[hostname] = host_ip
    return hostname_map


def __enabling_basic_authentication(basic_authentication, project_name):
    for i in range(len(basic_authentication)):
        user_name = basic_authentication[i].get(consts.USER).get(
            consts.USER_NAME)
        user_password = basic_authentication[i].get(consts.USER).get(
            consts.USER_PASSWORD)
        user_id = basic_authentication[i].get(consts.USER).get(consts.USER_ID)
        ret = aconf.modify_user_list(user_name, user_password, user_id)
        if not ret:
            logger.error('FAILED IN DEPLOY')
            exit(1)

    master_host_name = aconf.get_host_master_name(project_name)
    logger.info('UPDATE KUBE API MANIFEST FILE')
    ret = aconf.update_kube_api_manifest_file(master_host_name)
    if not ret:
        logger.error('FAILED TO UPDATE KUBE API FILE')
        exit(1)
    time.sleep(5)

    return ret


def _modifying_etcd_node(hostname_map, host_node_type_map):
    master_host_name = None
    master_ip = None
    for host_name, node_type in host_node_type_map.items():
        if node_type == "master":
            master_host_name = host_name
    for host_name, ip in hostname_map.items():
        if host_name == master_host_name:
            master_ip = ip
    logger.info('master ip - %s, master host name - %s',
                master_ip, master_host_name)
    logger.info('EXECUTING ETCD Changes')
    ret_hosts = apbl.etcd_changes(
        consts.ETCD_CHANGES, master_host_name, master_ip,
        consts.INVENTORY_SOURCE_FOLDER, consts.VARIABLE_FILE)
    if not ret_hosts:
        logger.error('FAILED SET HOSTS PLAY')
        exit(1)
    return ret_hosts


def __create_host_nodetype_map(hosts):
    hostnode_map = {}
    if hosts:
        for i in range(len(hosts)):
            node_type = hosts[i].get(consts.HOST).get(consts.NODE_TYPE)
            hostname = hosts[i].get(consts.HOST).get('hostname')
            hostnode_map[hostname] = node_type
    return hostnode_map


def __create_host_port_map(hosts):
    hostport_map = {}
    if hosts:
        for i in range(len(hosts)):
            registry_port = hosts[i].get(consts.HOST).get('registry_port')
            hostname = hosts[i].get(consts.HOST).get('hostname')
            hostport_map[hostname] = registry_port
    return hostport_map


def __add_ansible_hosts(hosts):
    """
    This will add the ansible hosts into the ansible hosts file placed at
    /etc/ansible/hosts
    """
    if hosts:
        host_str = ""
        ansible_host_str = ""

        ansible_host_file = open(consts.ANSIBLE_HOSTS_FILE, "r+")
        host_file = open(consts.HOSTS_FILE, "r+")
        ansible_file_content = ""
        file_content = ""
        for line in ansible_host_file:
            ansible_file_content = ansible_file_content + line
        for line in host_file:
            file_content = file_content + line
        for i in range(len(hosts)):
            host_ip = hosts[i].get(consts.HOST).get(consts.IP)
            host_ip = host_ip + " "
            host_name = hosts[i].get(consts.HOST).get(consts.HOSTNAME)
            host_name = host_name + " "
            if (host_ip in ansible_file_content
                    and host_name in ansible_file_content):
                logger.info("")
            else:
                ansible_host_str = "\n{}\n{}\n{}".format(
                    host_name, host_ip, ansible_host_str)
            if host_ip in file_content and host_name in file_content:
                logger.info("")
            else:
                host_str = "\n{} {}\n{}".format(host_ip, host_name, host_str)
        logger.info(host_str)
        logger.info("Host entries in hosts file - %s", host_str)
        host_file.write(host_str)
        logger.info("Host entries in ansible hosts file - %s",
                    ansible_host_str)
        ansible_host_file.write(ansible_host_str)
        host_file.close()


def __get_weave_net_list(config):
    """Creating weaveNetwork list function"""
    logger.info("Creating noOfNetworksInWeave list")
    hosts_data_dict = get_flannel_nw_data(config)
    weave_networks = None
    for item1 in hosts_data_dict:
        for key1 in item1:
            if key1 == "Multus_network":
                multus_network = item1.get("Multus_network")
                for item2 in multus_network:
                    for key2 in item2:
                        if key2 == "CNI_Configuration":
                            weave_networks = item2.get("CNI_Configuration")
    return weave_networks


def configure_macvlan_networks(config, macvlan_master_hostname):
    """
    This method is used for create macvlan network after multus
    :param config :input configuration file
    :param macvlan_master_hostname : the macvlan host
    :return ret :t/f
    """
    ret = False
    if config:
        logger.info('configure_mac_vlan networks')
        macvlan_nets = config.get(consts.KUBERNETES).get(
            consts.NETWORK_CREATION_IN_MACVLAN)
        for item1 in macvlan_nets:
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
                                        if key3 == "Macvlan":
                                            macvlan_network1 = item3.get(
                                                "Macvlan")
                                            for macvlan_networks in macvlan_network1:
                                                iface_dict = macvlan_networks.get(
                                                    "macvlan_networks")
                                                macvlan_gateway = iface_dict.get(
                                                    "gateway")
                                                macvlan_master = iface_dict.get(
                                                    "master")
                                                macvlan_masterplugin = iface_dict.get(
                                                    "masterplugin")
                                                macvlan_network_name = iface_dict.get(
                                                    "network_name")
                                                macvlan_range_start = iface_dict.get(
                                                    "rangeStart")
                                                macvlan_range_end = iface_dict.get(
                                                    "rangeEnd")
                                                macvlan_routes_dst = iface_dict.get(
                                                    "routes_dst")
                                                macvlan_subnet = iface_dict.get(
                                                    "subnet")
                                                macvlan_type = iface_dict.get(
                                                    "type")
                                                if macvlan_masterplugin:
                                                    if macvlan_type == "host-local":
                                                        logger.info(
                                                            'Master plugin is true && type is host-local')
                                                        ret = apbl.network_creation(
                                                            consts.K8_MACVLAN_MASTER_NETWORK_PATH,
                                                            macvlan_master_hostname,
                                                            macvlan_network_name,
                                                            macvlan_master,
                                                            macvlan_subnet,
                                                            macvlan_range_start,
                                                            macvlan_range_end,
                                                            macvlan_routes_dst,
                                                            macvlan_gateway)
                                                        if not ret:
                                                            logger.error(
                                                                'FAILED IN MACVLAN network creation_master1')
                                                    if macvlan_type == "dhcp":
                                                        logger.info(
                                                            'Master plugin is true && type is dhcp')
                                                        ret = apbl.network_dhcp_creation(
                                                            consts.K8_MACVLAN_MASTER_NETWORK_DHCP_PATH,
                                                            macvlan_master_hostname,
                                                            macvlan_network_name,
                                                            macvlan_master)
                                                        if not ret:
                                                            logger.error(
                                                                'FAILED IN MACVLAN network creation_master2')

                                                if macvlan_masterplugin == False:
                                                    if macvlan_type == "host-local":
                                                        logger.info(
                                                            'Master plugin is false && type is host-local')
                                                        ret = apbl.network_creation(
                                                            consts.K8_MACVLAN_NETWORK_PATH,
                                                            macvlan_master_hostname,
                                                            macvlan_network_name,
                                                            macvlan_master,
                                                            macvlan_subnet,
                                                            macvlan_range_start,
                                                            macvlan_range_end,
                                                            macvlan_routes_dst,
                                                            macvlan_gateway)
                                                        if not ret:
                                                            logger.error(
                                                                'FAILED IN MACVLAN network creation1')
                                                    if macvlan_type == "dhcp":
                                                        logger.info(
                                                            'Master plugin is false && type is dhcp')
                                                        ret = apbl.network_dhcp_creation(
                                                            consts.K8_MACVLAN_NETWORK_DHCP_PATH,
                                                            macvlan_master_hostname,
                                                            macvlan_network_name,
                                                            macvlan_master)
                                                        if not ret:
                                                            logger.error(
                                                                'FAILED IN MACVLAN network creation2')

    return ret


def remove_macvlan_networks(config, macvlan_master_hostname):
    """
    This method is used for create macvlan network after multus
    :param config :input configuration file
    :param macvlan_master_hostname : master host for mac vlan
    :return ret :t/f
    """
    ret = False
    if config:
        logger.info('Removal_mac_vlan networks')
        mac_vlan_nets = config.get(consts.KUBERNETES).get(
            consts.NETWORK_CREATION_IN_MACVLAN)
        for item1 in mac_vlan_nets:
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
                                        if key3 == "Macvlan":
                                            macvlan_network1 = item3.get(
                                                "Macvlan")
                                            for macvlan_networks in macvlan_network1:
                                                inetfaceDict = macvlan_networks.get(
                                                    "macvlan_networks")
                                                macvlan_network_name = inetfaceDict.get(
                                                    "network_name")
                                                macvlan_type = inetfaceDict.get(
                                                    "type")
                                                macvlan_node_hostname = inetfaceDict.get(
                                                    "hostname")

                                                ret = apbl.network_removal(
                                                    consts.K8_MACVLAN_NETWORK_REMOVAL_PATH,
                                                    macvlan_master_hostname,
                                                    macvlan_network_name)
                                                if not ret:
                                                    logger.error(
                                                        'FAILED IN MACVLAN network removal_master')

                                                if macvlan_type == "dhcp":
                                                    logger.info(
                                                        'DHCP DAEMON REMOVING')
                                                    ret = apbl.dhcp_daemon_removal(
                                                        consts.K8_DHCP_REMOVAL_PATH,
                                                        macvlan_node_hostname)
                                                    if not ret:
                                                        logger.error(
                                                            'FAILED IN DHCP REMOVAL')

    return ret


def configure_macvlan_interface(config):
    """
    This method is used for create macvlan network after multus
    :param config :input configuration file
    :return ret :t/f
    """
    ret = False
    if config:
        logger.info('configure_mac_vlan interfaces')
        nets_in_mac_vlan = config.get(consts.KUBERNETES).get(
            consts.NETWORK_CREATION_IN_MACVLAN)
        for item1 in nets_in_mac_vlan:
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
                                        if key3 == "Macvlan":
                                            macvlan_network1 = item3.get(
                                                "Macvlan")
                                            for macvlan_networks in macvlan_network1:
                                                inetfaceDict = macvlan_networks.get(
                                                    "macvlan_networks")
                                                macvlan_parent_interface = inetfaceDict.get(
                                                    "parent_interface")
                                                macvlan_vlanid = inetfaceDict.get(
                                                    "vlanid")
                                                macvlan_ip = inetfaceDict.get(
                                                    "ip")
                                                macvlan_node_hostname = inetfaceDict.get(
                                                    "hostname")

                                                ret = apbl.vlantag_interface(
                                                    consts.K8_VLAN_INTERFACE_PATH,
                                                    macvlan_node_hostname,
                                                    macvlan_parent_interface,
                                                    macvlan_vlanid, macvlan_ip)
                                                if not ret:
                                                    logger.error(
                                                        'FAILED IN MACVLAN interface creation')

    return ret


def removal_macvlan_interface(config):
    """
    function for mac-vlan interface removal
    :param config :input configuration file
    :return ret :t/f
    """
    ret = False
    if config:
        logger.info('Removal_mac_vlan interfaces')
        nets_in_mac_vlan = config.get(consts.KUBERNETES).get(
            consts.NETWORK_CREATION_IN_MACVLAN)
        for item1 in nets_in_mac_vlan:
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
                                        if key3 == "Macvlan":
                                            macvlan_network1 = item3.get(
                                                "Macvlan")
                                            for macvlan_networks in macvlan_network1:
                                                inetface_dict = macvlan_networks.get(
                                                    "macvlan_networks")
                                                macvlan_parent_interface = inetface_dict.get(
                                                    "parent_interface")
                                                macvlan_vlanid = inetface_dict.get(
                                                    "vlanid")
                                                macvlan_node_hostname = inetface_dict.get(
                                                    "hostname")
                                                ret = apbl.vlantag_interface_removal(
                                                    consts.K8_VLAN_INTERFACE_REMOVAL_PATH,
                                                    macvlan_node_hostname,
                                                    macvlan_parent_interface,
                                                    macvlan_vlanid)
                                                if not ret:
                                                    logger.error(
                                                        'FAILED IN MACVLAN interface removal')
                                                    exit(1)

        return ret


def macvlan_cleanup(config):
    logger.info('MACVLAN PLUGIN REMOVAL')
    macvlan_cni = get_macvlan_value(config)
    logger.info('macvlan value n macvlan_cleanup function: %s', macvlan_cni)
    if macvlan_cni:
        logger.info('REMOVING MACVLAN')
        ret = removal_macvlan_interface(config)
        network_hosts = config.get(consts.KUBERNETES).get(
            "node_configuration")
        for macvlan_host_fornetwork in network_hosts:
            if macvlan_host_fornetwork:
                iface_dict = macvlan_host_fornetwork.get("host")
                hostname = iface_dict.get("hostname")
                node_type = iface_dict.get("node_type")
                if node_type == "master":
                    logger.info("inside master for cleanup")
                    ret = remove_macvlan_networks(config, hostname)

    else:
        logger.info(
            'MAC-VLAN CONFIGURATION  EXIT , REASON--> MACVLAN  IS DISABLED ')
        ret = False
    return ret


def macvlan_removal_node(config):
    logger.info('MACVLAN PLUGIN REMOVAL')

    logger.info('Additioanl N/W plugins')
    macvlan_cni = get_macvlan_value(config)
    logger.info(
        'macvlan value n macvlan_removal node function: %s', macvlan_cni)
    if macvlan_cni:
        logger.info('REMOVING MACVLAN')
        ret = removal_macvlan_interface(config)
        project_name = config.get(consts.KUBERNETES).get(consts.PROJECT_NAME)
        master_node_macvlan = aconf.get_host_master_name(
            project_name)
        ret = remove_macvlan_networks(config, master_node_macvlan)

    else:
        logger.info(
            'MAC-VLAN CONFIGURATION  EXIT , REASON--> MACVLAN  IS DISABLED')
        ret = False
    return ret


def macvlan_creation_node(config, multus_cni_installed):
    logger.info('MACVLAN FOR DYNAMIC NODE ADDITION')
    logger.info("multus_cni_installed - %s", multus_cni_installed)
    macvlan_cni = get_macvlan_value(config)
    logger.info('macvlan value n macvlan creation node function: %s',
                macvlan_cni)
    if multus_cni_installed:
        if macvlan_cni:
            logger.info('CONFIGURING MAC-VLAN')
            project_name = config.get(consts.KUBERNETES).get(
                consts.PROJECT_NAME)
            master_node_macvlan = aconf.get_host_master_name(
                project_name)
            ret = configure_macvlan_interface(config)
            ret = configure_macvlan_networks(config, master_node_macvlan)

        else:
            logger.info(
                'MAC-VLAN CONFIGURATION EXIT, REASON--> MACVLAN IS DISABLED')
            ret = False
        return ret


def __macvlan_installation(config):
    logger.info('CONFIGURING MAC-VLAN')
    ret = configure_macvlan_interface(config)
    num_net_hosts = config.get(consts.KUBERNETES).get(consts.HOSTS)
    for macvlan_host_fornetwork in num_net_hosts:
        if macvlan_host_fornetwork:
            net_iface_dict = macvlan_host_fornetwork.get("host")
            net_host = net_iface_dict.get("hostname")
            node_type_fornetwork = net_iface_dict.get("node_type")
            if node_type_fornetwork == "master":
                ret = configure_macvlan_networks(config, net_host)
    return ret


def __dhcp_installation(config):
    logger.info('CONFIGURING DHCP')
    net_hosts = config.get(consts.KUBERNETES).get(consts.HOSTS)
    ret = False
    for dhcp_host_for_net in net_hosts:
        if dhcp_host_for_net:
            net_intf_dict = dhcp_host_for_net.get("host")
            net_host = net_intf_dict.get("hostname")
            node_type = net_intf_dict.get("node_type")
            if node_type == "minion":
                logger.info("DHCP DAEMON RUNNING")
                ret = apbl.dhcp_daemon_creation(
                    consts.K8_DHCP_PATH, net_host)
                if not ret:
                    logger.error('FAILED IN DHCP DAEMON installation')
    return ret


def get_master_ip(project_name):
    config = file_utils.read_yaml(consts.VARIABLE_FILE)
    project_path = config.get(consts.PROJECT_PATH)
    inventory_file_path = project_path + project_name + "/inventory.cfg"
    logger.info('Inventory file in get_master_ip function - %s',
                inventory_file_path)

    master_hostname = None
    with open(inventory_file_path) as f:
        for line in f:
            if re.match("\[kube-master\]", line):
                master_hostname1 = f.next()
                master_hostname = master_hostname1.strip(' \t\n\r')
                logger.info('master host name - %s', master_hostname)

    master_ip = None
    with open(inventory_file_path) as f:
        for line in f:
            if "ansible_ssh_host=" in line:
                host_ip1 = line.split("ansible_ssh_host=", 1)[1]
                host_ip = host_ip1.strip(' \t\n\r')
                hostnamestringlist = line.split(" ")
                host_name = hostnamestringlist[0]
                host_name = host_name.strip(' \t\n\r')
                if host_ip:
                    if host_name == master_hostname:
                        master_ip = host_ip
    return master_ip


def clean_up_flannel(hostname_map, host_node_type_map, networking_plugin,
                     config, project_name):
    """
    This function is used to clean the flannel additional plugin
    """
    ret = False
    if config:
        if networking_plugin != "flannel":
            networks = config.get(consts.KUBERNETES).get(consts.NETWORKS)
            multus_network = get_multus_network(networks).get("Multus_network")
            multus_cni = get_multus_network_elements(multus_network, "CNI")
            if multus_cni:
                logger.info('multus_cni and additional plugins clean up')
                hosts_data_dict = get_flannel_nw_data(config)
                for cni in multus_cni:
                    if consts.FLANNEL == cni:
                        ret = aconf.delete_flannel_interfaces(
                            hostname_map, host_node_type_map, hosts_data_dict,
                            project_name)
                        if not ret:
                            logger.error(
                                'FAILED IN FLANNEL INTERFACE DELETION')
            else:
                ret = True
        else:
            logger.info('FLANNEL IS DEFAULT PLUGIN')
            ret = True

        return ret


def get_flannel_nw_data(config):
    """
    This function is used for get the flannel network info
    """
    hosts_data_dict = config.get(consts.KUBERNETES).get(consts.NETWORKS)
    return hosts_data_dict


def get_multus_cni_value(config):
    """
    This function is used to get multus cni value
    """
    ret = False
    sriov_cni = False
    flannel_cni = False
    weave_cni = False
    macvlan_cni = False
    num_nets = config.get(consts.KUBERNETES).get(consts.NETWORKS)
    for item1 in num_nets:
        for key1 in item1:
            if key1 == "Multus_network":
                multus_network = item1.get("Multus_network")
                for item2 in multus_network:
                    for key2 in item2:
                        if key2 == "CNI":
                            multus_cni = item2.get("CNI")
                            if multus_cni:
                                for cni in multus_cni:
                                    if "sriov" == cni:
                                        sriov_cni = True
                                    elif consts.FLANNEL == cni:
                                        flannel_cni = True
                                    elif consts.WEAVE == cni:
                                        weave_cni = True
                                    elif "macvlan" == cni:
                                        macvlan_cni = True

        ret = sriov_cni or flannel_cni or weave_cni or macvlan_cni

    return ret


def __create_default_network_multus(config, hostname_map, host_node_type_map,
                                    networking_plugin):
    """
    This function is used to create default network
    """
    ret = False
    networks = config.get(consts.KUBERNETES).get(consts.NETWORKS)
    if networking_plugin == "weave" or networking_plugin == "flannel":
        for item1 in networks:
            for key in item1:
                if key == "Default_Network":
                    default_network = item1.get(consts.DEFAULT_NETWORK)
                    if default_network:
                        ret = aconf.create_default_network(
                            hostname_map, host_node_type_map,
                            networking_plugin, default_network)

    return ret


def launch_flannel_interface(config, hostname_map, host_node_type_map,
                             networking_plugin, project_name):
    """
    This function is used to create flannel interface
    """
    ret = False
    if networking_plugin != "flannel":
        hosts_data_dict = get_flannel_nw_data(config)
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
                                            ret = aconf.create_flannel_interface(
                                                hostname_map,
                                                host_node_type_map,
                                                project_name, hosts_data_dict)
    else:
        logger.info('FLANNEL IS ALREADY CONFIGURED')

    return ret


def __launch_weave_interface(config, hostname_map, host_node_type_map,
                             networking_plugin):
    """
    This function is used to create weave interface
    """
    ret = False
    if networking_plugin != "weave":
        weave_network_list_map = __get_weave_net_list(config)
        for item in weave_network_list_map:
            for key in item:
                if consts.WEAVE_NETWORK == key:
                    weave_network = item.get(consts.WEAVE_NETWORK)
                    for item1 in weave_network:
                        ret = aconf.create_weave_interface(
                            hostname_map, host_node_type_map,
                            networking_plugin, item1)
    else:
        logger.info('WEAVE IS ALREADY CONFIGURED')

    return ret


def get_macvlan_value(config):
    """
    This function is used to get multus cni value
    """
    ret = False
    num_nets = config.get(consts.KUBERNETES).get(consts.NETWORKS)
    for item1 in num_nets:
        for key1 in item1:
            if key1 == "Multus_network":
                multus_network = item1.get("Multus_network")
                for item2 in multus_network:
                    for key2 in item2:
                        if key2 == "CNI":
                            multus_cni = item2.get("CNI")
                            if multus_cni:
                                for cni in multus_cni:
                                    if "macvlan" == cni:
                                        ret = True

    return ret


def get_dhcp_value(config):
    """
    This function is used to get multus cni value
    """
    ret = False
    num_nets = config.get(consts.KUBERNETES).get(consts.NETWORKS)
    for item1 in num_nets:
        for key1 in item1:
            if key1 == "Multus_network":
                multus_network = item1.get("Multus_network")
                for item2 in multus_network:
                    for key2 in item2:
                        if key2 == "CNI":
                            multus_cni = item2.get("CNI")
                            if multus_cni:
                                for cni in multus_cni:
                                    ret = "dhcp" == cni

    return ret


def get_flannel_value(config):
    """
    This function is used to get multus cni value
    """
    ret = False
    num_nets = config.get(consts.KUBERNETES).get(consts.NETWORKS)
    for item1 in num_nets:
        for key1 in item1:
            if key1 == "Multus_network":
                multus_network = item1.get("Multus_network")
                for item2 in multus_network:
                    for key2 in item2:
                        if key2 == "CNI":
                            multus_cni = item2.get("CNI")
                            if multus_cni:
                                for cni in multus_cni:
                                    ret = "flannel" == cni
    return ret


def clean_up_weave(hostname_map, host_node_type_map, networking_plugin, config,
                   project_name):
    """
    This function is used to clean the weave additional plugin
    """
    ret = False
    if config:
        if networking_plugin != "weave":
            networks = config.get(consts.KUBERNETES).get(consts.NETWORKS)
            hosts_data_dict = get_weave_nw_data(config)
            multus_network = get_multus_network(networks).get("Multus_network")
            multus_cni = get_multus_network_elements(multus_network, "CNI")
            if multus_cni:
                logger.info('multus_cni and additional plugins clean up')
                for cni in multus_cni:
                    if consts.WEAVE == cni:
                        ret = aconf.delete_weave_interface(
                            hostname_map, host_node_type_map, hosts_data_dict,
                            project_name)
                        if not ret:
                            logger.error('FAILED IN WEAVE INTERFACE DELETION')
            else:
                ret = True
        else:
            logger.info('WEAVE IS DEFAULT PLUGIN')
            hosts_data_dict = get_weave_nw_data(config)
            ret = aconf.delete_default_weave_interface(
                hostname_map, host_node_type_map, hosts_data_dict,
                project_name)
            if not ret:
                logger.error('FAILED IN WEAVE INTERFACE DELETION')

        return ret


def get_weave_nw_data(config):
    """
    This function is used for get the weave network info
    """
    hosts_data_dict = config.get(consts.KUBERNETES).get(consts.NETWORKS)
    return hosts_data_dict
