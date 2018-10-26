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
import subprocess
import time
# noinspection PyCompatibility
from pathlib import Path

import netaddr
import os
from shutil import copyfile

import snaps_k8s.ansible_p.ansible_utils.ansible_configuration as aconf
import snaps_k8s.ansible_p.ansible_utils.ansible_playbook_launcher as apbl
from snaps_k8s.common.consts import consts
from snaps_k8s.common.utils import file_utils

logger = logging.getLogger('k8_utils')


def execute(k8s_conf, deploy_file):
    if k8s_conf:
        logger.info('host entries')
        proxy_dic = __create_proxy_dic(k8s_conf)
        logger.info('PROXY - %s', proxy_dic)

        # TODO/FIXME - change the addition of proxy settings from file based
        # TODO/FIXME - to API values passed into the playbook
        aconf.provision_preparation(proxy_dic)

        logger.info('enable ssh key')
        hosts = k8s_conf.get(consts.K8S_KEY).get(consts.NODE_CONF_KEY)
        __enable_key_ssh(hosts)
        hostname_map = __get_hostname_map(hosts)
        host_node_type_map = __create_host_nodetype_map(hosts)

        # duplicate ip check start
        networks = k8s_conf.get(consts.K8S_KEY).get(consts.NETWORKS_KEY)
        default_network_items = __get_network_item(
            networks, "Default_Network").get("Default_Network")
        multus_network = __get_multus_network(networks).get("Multus_network")
        multus_cni = __get_multus_network_elements(multus_network, "CNI")
        multus_cni_configuration = __get_multus_network_elements(
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
        service_subnet = None
        pod_subnet = None
        networking_plugin = None

        for network in networks:
            for key in network:
                if key == "Default_Network":
                    default_network = network.get(consts.DFLT_NET_KEY)
                    if default_network:
                        service_subnet = default_network.get(
                            consts.SRVC_SUB_KEY)
                        logger.info("Service subnet = " + service_subnet)
                        pod_subnet = default_network.get(consts.POD_SUB_KEY)
                        logger.info("pod_subnet = " + pod_subnet)
                        networking_plugin = default_network.get(
                            consts.NET_PLUGIN_KEY)
                        logger.info("networking_plugin= " + networking_plugin)

        docker_repo = k8s_conf.get(consts.K8S_KEY).get(consts.DOCKER_REPO_KEY)
        if docker_repo:
            docker_ip = docker_repo.get(consts.IP_KEY)
            docker_user = docker_repo.get(consts.USER_KEY)
            docker_pass = docker_repo.get(consts.PASSWORD_KEY)
            logger.info("enable ssh key")
            __pushing_key(docker_ip, docker_user, docker_pass)

        hosts = k8s_conf.get(consts.K8S_KEY).get(consts.NODE_CONF_KEY)
        project_name = k8s_conf.get(consts.K8S_KEY).get(
            consts.PROJECT_NAME_KEY)
        logger.info('Project Name - %s', project_name)
        git_branch = k8s_conf.get(consts.K8S_KEY).get(consts.GIT_BRANCH_KEY)
        logger.info('Git Branch Name - %s', git_branch)
        host_port_map = __create_host_port_map(hosts)
        aconf.launch_provisioning_kubernetes(
            hostname_map, host_node_type_map, host_port_map, service_subnet,
            pod_subnet, networking_plugin, docker_repo, hosts, git_branch,
            project_name, k8s_conf, False)
        ret = __create_backup_deploy_conf(k8s_conf, deploy_file)
        if not ret:
            logger.error('FAILED IN CREATING DEPLOY BACKUP')
            exit(1)
        logger.info("cephhost creation")
        ceph_hosts = k8s_conf.get(consts.K8S_KEY).get(
            consts.PERSIS_VOL_KEY).get(consts.CEPH_VOLUME_KEY)
        if ceph_hosts:
            logger.info("enable ssh key for ceph IPs")
            __enable_key_ssh(ceph_hosts)
            ret = aconf.launch_ceph_kubernetes(
                host_node_type_map, hosts, ceph_hosts)
            if not ret:
                logger.error('FAILED IN CEPH DEPLOY')
                exit(1)
        logger.info('Persistent host volume Start')
        persistent_vol = k8s_conf.get(consts.K8S_KEY).get(
            consts.PERSIS_VOL_KEY).get(consts.HOST_VOL_KEY)
        if persistent_vol:
            ret = aconf.launch_persitent_volume_kubernetes(
                host_node_type_map, persistent_vol)
            if not ret:
                logger.error('FAILED IN DEPLOY')
                exit(1)
        logger.info("Additional N/W plugins multus_cni installation")
        multus_cni_installed = False
        multus_enabled = __get_multus_cni_value(k8s_conf)
        logger.info('multus_enabled: %s', multus_enabled)
        macvlan_cni = __get_macvlan_value(k8s_conf)
        logger.info('macvlan value: %s', macvlan_cni)
        dhcp_cni = __get_dhcp_value(k8s_conf)
        logger.info('dhcp value: %s', dhcp_cni)

        if multus_enabled:
            logger.info('crdNetwork creation')
            time.sleep(10)
            aconf.launch_crd_network(hostname_map, host_node_type_map)

            ret = aconf.launch_multus_cni(
                hostname_map, host_node_type_map, networking_plugin)
            if not ret:
                logger.error('FAILED IN MULTUS CONFIGURATION')
                exit(1)

            logger.info('MULTUS CONFIGURED SUCCESSFULLY.. NOW CREATING '
                        'DEFAULT PLUGIN NETWORK')
            multus_cni_installed = True
            if networking_plugin != "none":
                ret = __create_default_network_multus(
                    k8s_conf, hostname_map, host_node_type_map,
                    networking_plugin)
                if not ret:
                    logger.error('FAILED IN CREATING DEFAULT NETWORK')
                else:
                    logger.info('SUCCESSFULLY CREATED DEFAULT NETWORK')

        multus_cni = __get_multus_network_elements(multus_network, "CNI")
        logger.info('multus_cni: %s', multus_cni)
        for cni in multus_cni:
            logger.info('multus_cni_installed: %s', multus_cni_installed)
            logger.info('cni: %s', cni)
            if multus_cni_installed:
                if "dhcp" == cni:
                    logger.info('DHCP Network Plugin')
                    if multus_cni_installed:
                        if dhcp_cni:
                            logger.info('CONFIGURING DHCP')
                            __dhcp_installation(k8s_conf)
                        else:
                            logger.info(
                                'DHCP CONFIGURATION  EXIT , '
                                'REASON--> DHCP  IS DISABLED ')
                elif "sriov" == cni:
                    logger.info('Sriov Network Plugin')
                    project_name = k8s_conf.get(consts.K8S_KEY).get(
                        consts.PROJECT_NAME_KEY)
                    hosts_data_dict = __get_sriov_nw_data(k8s_conf)
                    if hosts_data_dict is not None:
                        aconf.launch_sriov_cni_configuration(
                            host_node_type_map,
                            hosts_data_dict,
                            project_name)
                        ret = aconf.launch_sriov_network_creation(
                            k8s_conf, host_node_type_map, hosts_data_dict)
                        if not ret:
                            logger.error('FAILED IN SRIOV NW Creation')
                    else:
                        logger.info(
                            'Config data for SRIOV network is incomplete ')
                elif consts.FLANNEL_TYPE == cni:
                    logger.info('Flannel Network Plugin')
                    ret = __launch_flannel_interface(k8s_conf, hostname_map,
                                                     host_node_type_map,
                                                     networking_plugin)
                    if not ret:
                        logger.error(
                            'FAILED IN FLANNEL INTERFACE CREATION')
                elif consts.WEAVE_TYPE == cni:
                    logger.info('Weave Network Plugin')
                    ret = __launch_weave_interface(k8s_conf, hostname_map,
                                                   host_node_type_map,
                                                   networking_plugin)
                    if not ret:
                        logger.error('FAILED IN WEAVE INTERFACFE CREATION')
                elif "macvlan" == cni:
                    logger.info('Macvlan Network Plugin')
                    if multus_cni_installed:
                        if macvlan_cni:
                            logger.info('CONFIGURING MAC-VLAN')
                            __macvlan_installation(k8s_conf)
                        else:
                            logger.info(
                                'MAC-VLAN CONFIGURATION  EXIT , '
                                'REASON--> MACVLAN  IS DISABLED ')

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
        basic_authentication = k8s_conf.get(consts.K8S_KEY).get(
            consts.BASIC_AUTH_KEY)
        __enabling_basic_authentication(basic_authentication, k8s_conf)

        logger.info("etcd changes")
        ret = _modifying_etcd_node(hostname_map, host_node_type_map)
        if not ret:
            logger.error('FAILED IN DEPLOY')
            exit(1)

        logger.info('Metrics Server')

        metrics_server = k8s_conf.get(consts.K8S_KEY).get(
            consts.METRICS_SERVER_KEY)
        if metrics_server:
            logger.info('Metrics server configuration')
            ret = aconf.launch_metrics_server(
                hostname_map, host_node_type_map)

        return ret


def __ip_var_args(*argv):
    if len(argv) % 2:
        logger.error("Invalid configuration")
        exit(1)

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
                logger.info('Exit')
                return False

        return True


def __get_network_item(networks, network_list_item):
    for network_item in networks:
        for key in network_item:
            if key == network_list_item:
                logger.info('Exit')
                return network_item
    logger.info('Exit')


def __validate_net_ip_range(net_names, range_start_dict, range_end_dict):
    ret = True
    __check_dup_start_end_ip(net_names, range_start_dict)
    __check_dup_start_end_ip(net_names, range_end_dict)
    count = 0
    length_of_elements = len(net_names)
    while count < int(length_of_elements):
        count1 = count + 1
        while count1 < int(length_of_elements):
            if not __ip_var_args(
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
            logger.info('Exit')
            return False
    return True


def __get_multus_network(networks):
    for network_item in networks:
        for key in network_item:
            if key == "Multus_network":

                return network_item
    logger.info('Exit')


def __get_multus_network_elements(multus_network, element):
    for item in multus_network:
        for key in item:
            if key == element:
                logger.info('Exit')
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
                    network_name_list.append(macvlan_network.get(
                        "macvlan_networks").get("network_name"))

        return network_name_list, start_range_dict, end_range_dict


def clean_k8(k8s_conf):
    """
    This method is used for cleanup of kubernetes cluster
    :param k8s_conf :input configuration file
    :return ret :t/f
    """
    ret = False
    if k8s_conf:
        logger.info("Host entries in /etc/ansible/host file")
        hosts = k8s_conf.get(consts.K8S_KEY).get(consts.NODE_CONF_KEY)
        __enable_key_ssh(hosts)
        hostname_map = __get_hostname_map(hosts)
        host_node_type_map = __create_host_nodetype_map(hosts)
        git_branch = k8s_conf.get(consts.K8S_KEY).get(consts.GIT_BRANCH_KEY)
        logger.info('Git Branch Name is %s', git_branch)
        project_name = k8s_conf.get(consts.K8S_KEY).get(
            consts.PROJECT_NAME_KEY)
        logger.info('Project Name is %s', project_name)
        variable_file = consts.VARIABLE_FILE
        src_package_path = consts.SRC_PKG_FLDR
        multus_enabled = __get_multus_cni_value_for_dynamic_node(k8s_conf)
        logger.info('multus_enabled :%s', multus_enabled)

        logger.info("Set kubelet context")
        ret = aconf.set_kubectl_context(
            project_name, variable_file, src_package_path)
        if not ret:
            logger.error('FAILED IN SETTING CONTEXT IN KUBECTL')

        networks = k8s_conf.get(consts.K8S_KEY).get(consts.NETWORKS_KEY)
        networking_plugin = None
        logger.info(networks)

        for item1 in networks:
            for key in item1:
                if key == "Default_Network":
                    default_network = item1.get(consts.DFLT_NET_KEY)
                    if default_network:
                        service_subnet = default_network.get(
                            consts.SRVC_SUB_KEY)
                        logger.info("Service subnet = %s", service_subnet)
                        pod_subnet = default_network.get(consts.POD_SUB_KEY)
                        logger.info("pod_subnet = %s", pod_subnet)
                        networking_plugin = default_network.get(
                            consts.NET_PLUGIN_KEY)
                        logger.info("networking_plugin= %s", networking_plugin)
                    else:
                        logger.info(
                            'error: Default network configurations are not '
                            'defined')

        ret = __clean_up_flannel(
            hostname_map, host_node_type_map, networking_plugin, k8s_conf,
            project_name)
        if not ret:
            logger.error('FAILED IN FLANNEL CLEANUP')

        logger.info('MACVLAN REMOVAL FOR CLUSTER')
        ret = __macvlan_cleanup(k8s_conf)
        if ret:
            logger.info('MACVLAN REMOVED SUCCESSFULLY')
        else:
            logger.info('MACVLAN NOT REMOVED')

        logger.info('DHCP REMOVAL FOR CLUSTER')
        dhcp_cni = __get_dhcp_value(k8s_conf)
        logger.info('dhcp value is %s', dhcp_cni)
        if dhcp_cni:
            ret = __dhcp_cleanup(k8s_conf)
            if ret:
                logger.info('DHCP REMOVED SUCCESSFULLY')
            else:
                logger.info('DHCP NOT REMOVED')
        else:
            logger.info('DHCP REMOVAL  EXIT , REASON--> DHCP  IS DISABLED ')

        ret = __clean_up_weave(
            hostname_map, host_node_type_map, networking_plugin,
            k8s_conf, project_name)
        if not ret:
            logger.error('FAILED IN WEAVE CLEANUP')
        metrics_server = k8s_conf.get(consts.K8S_KEY).get(
            consts.METRICS_SERVER_KEY)
        logger.info("metrics_server flag in kube8 deployment file is %s",
                    str(metrics_server))
        aconf.clean_up_k8_addons(hostname_map=hostname_map,
                                 host_node_type_map=host_node_type_map,
                                 metrics_server=metrics_server)
        aconf.clean_up_k8(git_branch, project_name, multus_enabled)
    logger.info('Exit')
    return ret


def __pushing_key(host_ip, user_name, password):
    logger.info('PUSHING KEY TO HOSTS')
    command = "sshpass -p %s ssh-copy-id -o StrictHostKeyChecking=no %s@%s" \
              % (password, user_name, host_ip)
    res = subprocess.call(command, shell=True)
    if not res:
        logger.info(
            'ERROR IN PUSHING KEY:Probaly the key is already present in '
            'remote host')
    logger.info('SSH KEY BASED AUTH ENABLED')


def __enable_key_ssh(hosts):
    """Enable SSH key function"""
    command_time = "{} {}".format(
        "sed -i '/#timeout = 10/c\\timeout = 50'", consts.ANSIBLE_CONF)
    subprocess.call(command_time, shell=True)
    for i in range(len(hosts)):
        user_name = hosts[i].get(consts.HOST_KEY).get(consts.USER_KEY)
        if user_name != 'root':
            logger.info('USER MUST BE ROOT')
            exit(0)
        password = hosts[i].get(consts.HOST_KEY).get(consts.PASSWORD_KEY)
        ip = hosts[i].get(consts.HOST_KEY).get(consts.IP_KEY)
        host_ip = ip
        check_dir = os.path.isdir(consts.SSH_PATH)
        keygen_command = "{} {}".format(
            'echo -e y|ssh-keygen -b 2048 -t',
            'rsa -f /root/.ssh/id_rsa -q -N ""')
        if not check_dir:
            os.makedirs(consts.SSH_PATH)
            logger.info('Host ip is %s', host_ip)
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
            ip = hosts[i].get(consts.HOST_KEY).get(consts.IP_KEY)
            host_ip = ip

            logger.info('PUSHING KEY TO HOSTS')
            push_key_cmd = "sshpass -p '%s' ssh-copy-id -o " \
                           "StrictHostKeyChecking=no %s@%s" % (password,
                                                               user_name,
                                                               host_ip)
            logger.info(push_key_cmd)
            res = subprocess.call(push_key_cmd, shell=True)
            if res:
                logger.info('ERROR IN PUSHING KEY:Probably the key is '
                            'already present in remote host')
            logger.info('SSH KEY BASED AUTH ENABLED')
    return True


def __create_proxy_dic(config):
    """Creating proxy dictionary function"""
    logger.info("Creating Proxy dictionary")
    proxy_dic = {}
    http_proxy = config.get(consts.K8S_KEY).get(consts.PROXIES_KEY).get(
        consts.HTTP_PROXY_KEY)
    https_proxy = config.get(consts.K8S_KEY).get(consts.PROXIES_KEY).get(
        consts.HTTPS_PROXY_KEY)
    ftp_proxy = config.get(consts.K8S_KEY).get(consts.PROXIES_KEY).get(
        consts.FTP_PROXY_KEY)
    no_proxy = config.get(consts.K8S_KEY).get(consts.PROXIES_KEY).get(
        consts.NO_PROXY_KEY)

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


def __get_sriov_nw_data(config):
    num_net = config.get(consts.K8S_KEY).get(consts.NETWORKS_KEY)
    cni_configuration = None
    for item1 in num_net:
        for key1 in item1:
            if key1 == "Multus_network":
                multus_network = item1.get("Multus_network")
                for item2 in multus_network:
                    for key2 in item2:
                        if key2 == "CNI_Configuration":
                            cni_configuration = item2.get("CNI_Configuration")
                        else:
                            logger.info(
                                'CNI_Configuration tag not found in '
                                'config data')
            else:
                logger.info('Multus_network tag not found in config data')

    return cni_configuration


def __get_hostname_map(hosts):
    """Get hostname map function"""
    hostname_map = {}
    if hosts:
        for i in range(len(hosts)):
            hostname = hosts[i].get(consts.HOST_KEY).get('hostname')
            host_ip = ""
            ip = hosts[i].get(consts.HOST_KEY).get(consts.IP_KEY)
            if ip:
                host_ip = ip
            hostname_map[hostname] = host_ip

    return hostname_map


def __enabling_basic_authentication(basic_authentication, k8s_conf):
    """Basic Authentication function"""
    for i in range(len(basic_authentication)):
        user_name = basic_authentication[i].get(
            consts.USER_KEY).get(consts.USER_NAME_KEY)
        user_password = basic_authentication[i].get(
            consts.USER_KEY).get(consts.USER_PASS_KEY)
        user_id = basic_authentication[i].get(
            consts.USER_KEY).get(consts.USER_ID_KEY)
        aconf.modify_user_list(user_name, user_password, user_id)

    master_host_name = aconf.get_host_master_name(k8s_conf)
    logger.info('UPDATE KUBE API MANIFEST FILE')
    aconf.update_kube_api_manifest_file(master_host_name)
    time.sleep(5)


def _modifying_etcd_node(hostname_map, host_node_type_map):
    """etcd modification changes"""
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
        consts.SRC_PKG_FLDR, consts.VARIABLE_FILE)
    if not ret_hosts:
        logger.error('FAILED SET HOSTS PLAY')
        exit(1)
    return ret_hosts


def __create_host_nodetype_map(hosts):
    """Get Node types function"""
    hostnode_map = {}
    if hosts:
        for i in range(len(hosts)):
            node_type = hosts[i].get(consts.HOST_KEY).get(consts.NODE_TYPE_KEY)
            hostname = hosts[i].get(consts.HOST_KEY).get('hostname')
            hostnode_map[hostname] = node_type
    return hostnode_map


def __create_host_port_map(hosts):
    hostport_map = {}
    if hosts:
        for i in range(len(hosts)):
            registry_port = hosts[i].get(consts.HOST_KEY).get('registry_port')
            hostname = hosts[i].get(consts.HOST_KEY).get('hostname')
            hostport_map[hostname] = registry_port
    return hostport_map


def __nbr_net_in_weave_list(config):
    """Creating weaveNetwork list function"""
    logger.info("Creating noOfNetworksInWeave list")
    hosts_data_dict = __get_flannel_nw_data(config)
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


def __remove_macvlan_networks(config, macvlan_master_hostname):
    """
    This method is used for remove macvlan network after multus
    :param config: input configuration file
    :param macvlan_master_hostname:
    :return ret :t/f
    """
    ret = False
    if config:
        logger.info('Removal_mac_vlan networks')
        macvlan_nets = config.get(consts.K8S_KEY).get(
            consts.NET_IN_MACVLAN_KEY)
        for item1 in macvlan_nets:
            for key1 in item1:
                if key1 == "Multus_network":
                    multus_network = item1.get("Multus_network")
                    for item2 in multus_network:
                        for key2 in item2:
                            if key2 == "CNI_Configuration":
                                cni_conf = item2.get(
                                    "CNI_Configuration")
                                ret = __remove_macvlan_networks_cni(
                                    cni_conf, macvlan_master_hostname)

    return ret


def __remove_macvlan_networks_cni(cni_conf, macvlan_master_hostname):
    ret = False

    for item3 in cni_conf:
        for key3 in item3:
            if key3 == "Macvlan":
                macvlan_network1 = item3.get(
                    "Macvlan")
                for macvlan_networks in macvlan_network1:
                    iface_dict = macvlan_networks.get(
                        "macvlan_networks")
                    macvlan_network_name = iface_dict.get(
                        "network_name")
                    logger.info(
                        'macvlan_master_hostname is %s',
                        macvlan_master_hostname)
                    logger.info(
                        'macvlan_network_name is %s',
                        macvlan_network_name)

                    ret = apbl.network_removal(
                        consts.K8_MACVLAN_NETWORK_REMOVAL_PATH,
                        macvlan_master_hostname,
                        macvlan_network_name,
                        consts.PROXY_DATA_FILE)
                    if not ret:
                        logger.error(
                            'FAILED '
                            'IN MACVLAN network '
                            'removal_master')
    return ret


def __removal_macvlan_interface(config):
    """
    This method is used for create macvlan network after multus
    :param config :input configuration file
    :return ret :t/f
    """
    ret = False
    if config:
        logger.info('Removal_mac_vlan interfaces')
        nets_in_mac_vlan = config.get(consts.K8S_KEY).get(
            consts.NET_IN_MACVLAN_KEY)
        for item1 in nets_in_mac_vlan:
            for key1 in item1:
                if key1 == "Multus_network":
                    multus_network = item1.get("Multus_network")
                    for item2 in multus_network:
                        for key2 in item2:
                            if key2 == "CNI_Configuration":
                                cni_conf = item2.get(
                                    "CNI_Configuration")
                                ret = __removal_macvlan_interface_cni(cni_conf)

    return ret


def __removal_macvlan_interface_cni(cni_conf):
    ret = False

    for item3 in cni_conf:
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
                    logger.info(
                        'macvlan_node_hostname is %s',
                        macvlan_node_hostname)
                    logger.info(
                        'macvlan_parent_interface is %s',
                        macvlan_parent_interface)
                    logger.info(
                        'macvlan_vlanid is %s',
                        macvlan_vlanid)
                    ret = apbl.vlantag_interface_removal(
                        consts.K8_VLAN_INTERFACE_REMOVAL_PATH,
                        macvlan_node_hostname,
                        macvlan_parent_interface,
                        macvlan_vlanid)
                    if not ret:
                        logger.error(
                            'FAILED IN MACVLAN '
                            'interface removal')
    return ret


def __macvlan_cleanup(k8s_conf):
    logger.info("MACVLAN PLUGIN REMOVAL")
    macvlan_cni = __get_macvlan_value(k8s_conf)
    logger.info('macvlan value n __macvlan_cleanup function:%s', macvlan_cni)
    if macvlan_cni:
        logger.info('REMOVING MACVLAN')
        __removal_macvlan_interface(k8s_conf)
        master_node_macvlan = aconf.get_host_master_name(k8s_conf)
        ret = __remove_macvlan_networks(k8s_conf, master_node_macvlan)
    else:
        logger.info(
            'MAC-VLAN CONFIGURATION  EXIT , REASON--> MACVLAN  IS DISABLED ')
        ret = False
    return ret


def __macvlan_installation(k8s_conf):
    logger.info('CONFIGURING MAC-VLAN')
    __config_macvlan_intf(k8s_conf)
    master_node_macvlan = aconf.get_host_master_name(k8s_conf)
    ret = __config_macvlan_networks(k8s_conf, master_node_macvlan)

    return ret


def __get_macvlan_value(config):
    """
    This function is used to get multus cni value
    """
    ret = False
    nbr_networks = config.get(consts.K8S_KEY).get(consts.NETWORKS_KEY)
    for item1 in nbr_networks:
        for key1 in item1:
            if key1 == "Multus_network":
                multus_network = item1.get("Multus_network")
                for item2 in multus_network:
                    for key2 in item2:
                        if key2 == "CNI":
                            multus_cni = item2.get("CNI")
                            if multus_cni:
                                for cni in multus_cni:
                                    if cni == "macvlan":
                                        ret = True

    return ret


def __dhcp_cleanup(config):
    logger.info('REMOVING DHCP')
    nbr_hosts_network = config.get(consts.K8S_KEY).get(consts.NODE_CONF_KEY)
    ret = False
    for dhcp_host_fornetwork in nbr_hosts_network:
        if dhcp_host_fornetwork is not None:
            inetfacedict_fornetwork = dhcp_host_fornetwork.get("host")
            hostname_fornetwork = inetfacedict_fornetwork.get("hostname")
            node_type_fornetwork = inetfacedict_fornetwork.get("node_type")
            if node_type_fornetwork == "minion":
                dhcp_daemon_removal_playbook = consts.K8_DHCP_REMOVAL_PATH
                logger.info('DHCP DAEMON REMOVING')
                ret = apbl.dhcp_daemon_removal(dhcp_daemon_removal_playbook,
                                               hostname_fornetwork)
                if not ret:
                    logger.error('FAILED IN DHCP REMOVAL---------------')

    return ret


def __get_flannel_nw_data(config):
    """
    This function is used for get the flannel network info
    """
    hosts_data_dict = config.get(consts.K8S_KEY).get(consts.NETWORKS_KEY)
    logger.info('Exit')
    return hosts_data_dict


def __get_multus_cni_value(config):
    """
    This function is used to get multus cni value
    """
    ret = False
    sriov_cni = False
    flannel_cni = False
    weave_cni = False
    macvlan_cni = False
    num_nets = config.get(consts.K8S_KEY).get(consts.NETWORKS_KEY)
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
                                    elif consts.FLANNEL_TYPE == cni:
                                        flannel_cni = True
                                    elif consts.WEAVE_TYPE == cni:
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
    networks = config.get(consts.K8S_KEY).get(consts.NETWORKS_KEY)
    if networking_plugin == "weave" or networking_plugin == "flannel":
        for item1 in networks:
            for key1 in item1:
                if key1 == "Default_Network":
                    default_network = item1.get(consts.DFLT_NET_KEY)
                    if default_network:
                        ret = aconf.create_default_network(
                            hostname_map, host_node_type_map,
                            networking_plugin, default_network)
    else:
        logger.info('Cannot create default network as default networking ' +
                    'plugin is other than flannel/weave')

    return ret


def __launch_flannel_interface(k8s_conf, hostname_map, host_node_type_map,
                               networking_plugin):
    """
    This function is used to create flannel interface
    """
    ret = False
    if networking_plugin != "flannel":
        hosts_data_dict = __get_flannel_nw_data(k8s_conf)
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
                                            aconf.create_flannel_interface(
                                                k8s_conf, hostname_map,
                                                host_node_type_map,
                                                hosts_data_dict)
    else:
        logger.error(
            'FLANNEL IS ALREADY CONFIGURED AS DEFAULT NETWORKING PLUGIN, ' +
            'PLEASE PROVIDE MULTUS PLUGIN OTHER THAN FLANNEL')
        exit(1)

    return ret


def __launch_weave_interface(config, hostname_map, host_node_type_map,
                             networking_plugin):
    """
    This function is used to create weave interface
    """
    ret = False
    if networking_plugin != "weave":
        weave_network_list_map = __nbr_net_in_weave_list(config)
        logger.info('weaveNetworkList_map is %s', str(weave_network_list_map))
        for item in weave_network_list_map:
            for key in item:
                if consts.WEAVE_NET_TYPE == key:
                    weave_network = item.get(consts.WEAVE_NET_TYPE)
                    for item1 in weave_network:
                        ret = aconf.create_weave_interface(
                            hostname_map, host_node_type_map,
                            networking_plugin, item1)
    else:
        logger.error('WEAVE IS ALREADY CONFIGURED AS DEFAULT NETWORKING '
                     'PLUGIN, PLEASE PROVIDE MULTUS PLUGIN OTHER THAN WEAVE')
        exit(1)

    return ret


def __get_dhcp_value(config):
    """
    This function is used to get multus cni value
    """
    ret = False
    num_nets = config.get(consts.K8S_KEY).get(consts.NETWORKS_KEY)
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
                                    if cni == "dhcp":
                                        ret = True

    return ret


def __get_flannel_value(config):
    """
    This function is used to get multus cni value
    """
    ret = False
    num_nets = config.get(consts.K8S_KEY).get(consts.NETWORKS_KEY)
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
                                    if cni == "flannel":
                                        ret = True

    return ret


def __get_weave_nw_data(config):
    """
    This function is used for get the weave network info
    """
    hosts_data_dict = config.get(consts.K8S_KEY).get(consts.NETWORKS_KEY)
    logger.info('Exit')
    return hosts_data_dict


def __create_backup_deploy_conf(config, deploy_file):
    """
    This function is used to create backup file for deployment configuration
    """
    ret = True

    project_name = config.get(consts.K8S_KEY).get(consts.PROJECT_NAME_KEY)
    cwd = os.getcwd()
    src = deploy_file
    if not src.startswith('/'):
        src = cwd + '/' + src

    dst = "{}/{}/{}".format(
        consts.PROJECT_PATH, project_name, consts.BKUP_DEPLOYMENT_FILE)
    logger.info(src)
    logger.info(dst)
    copyfile(src, dst)

    logger.info('Exit')
    return ret


def __get_multus_cni_value_for_dynamic_node(k8s_conf):
    """
    This function is used to get multus cni value for dynamic node
    """
    ret = __check_multus_cni_deploy_config(k8s_conf)
    if ret:
        logger.info("Setting multus_cni to true, as flannel/weave was "
                    "enabled as additional plugin at cluster creation")

    logger.info('Exit')
    return ret


def __check_multus_cni_deploy_config(k8s_conf):
    """
    This function is used to get multus cni value configured at
    cluster creation
    """
    flannel_cni = False
    weave_cni = False
    logger.info("Function __check_multus_cni_deploy_config")
    project_name = k8s_conf.get(consts.K8S_KEY).get(consts.PROJECT_NAME_KEY)
    current_dir = consts.CWD
    src = "{}/{}/{}".format(
        consts.PROJECT_PATH, project_name, consts.BKUP_DEPLOYMENT_FILE)
    dst = current_dir + consts.BKUP_DEPLOYMENT_FILE
    logger.info('Deployment file path, src is ' + src + ' and dst is ' + dst)
    copyfile(src, dst)
    config1 = file_utils.read_yaml(dst)
    nbr_networks = config1.get(consts.K8S_KEY).get(consts.NETWORKS_KEY)
    if config1:
        for item1 in nbr_networks:
            for key in item1:
                if key == "Multus_network":
                    multus_network = item1.get("Multus_network")
                    for item2 in multus_network:
                        for key2 in item2:
                            if key2 == "CNI":
                                multus_cni = item2.get("CNI")
                                if multus_cni:
                                    for cni in multus_cni:
                                        if cni == "flannel":
                                            flannel_cni = True
                                        elif cni == "weave":
                                            weave_cni = True
        os.remove(dst)
    return flannel_cni or weave_cni


def __get_weave_value(config):
    """
    This function is used to get multus cni value
    """
    ret = False
    nbr_networks = config.get(consts.K8S_KEY).get(consts.NETWORKS_KEY)
    for item1 in nbr_networks:
        for key in item1:
            if key == "Multus_network":
                multus_network = item1.get("Multus_network")
                for item2 in multus_network:
                    for key2 in item2:
                        if key2 == "CNI":
                            multus_cni = item2.get("CNI")
                            if multus_cni:
                                for cni in multus_cni:
                                    if cni == "weave":
                                        ret = True
    return ret


def __clean_up_flannel(hostname_map, host_node_type_map,
                       networking_plugin, config, project_name):
    """
    This function is used to clean the flannel additional plugin
    """
    ret = False
    if config:
        if networking_plugin != "flannel":
            flannel_cni = __get_flannel_value(config)
            hosts_data_dict = __get_flannel_nw_data(config)
            if flannel_cni:
                ret = aconf.delete_flannel_interfaces(
                    hostname_map, host_node_type_map, hosts_data_dict,
                    project_name)
                if not ret:
                    logger.error('FAILED IN FLANNEL INTERFACE DELETION')
        else:
            ret = True
    else:
        logger.info('FLANNEL IS DEFAULT PLUGIN')
        ret = True

    logger.info('Exit')
    return ret


def __clean_up_weave(hostname_map, host_node_type_map,
                     networking_plugin, config, project_name):
    """
    This function is used to clean the weave additional plugin
    """
    ret = False
    if config:
        if networking_plugin != "weave":
            logger.info(
                'DEFAULT NETWOKRING PLUGUN IS NOT WEAVE.. '
                'CHECK MULTUS CNI PLUGINS')
            weave_cni = __get_weave_value(config)
            hosts_data_dict = __get_weave_nw_data(config)
            if weave_cni:
                ret = aconf.delete_weave_interface(
                    hostname_map, host_node_type_map,
                    hosts_data_dict, project_name)
                if not ret:
                    logger.error('FAILED IN WEAVE INTERFACE DELETION')
            else:
                ret = True
        else:
            logger.info('WEAVE IS DEFAULT PLUGIN')
            hosts_data_dict = __get_weave_nw_data(config)
            ret = aconf.delete_default_weave_interface(
                hostname_map, host_node_type_map, hosts_data_dict,
                project_name)
            if not ret:
                logger.error('FAILED IN WEAVE INTERFACE DELETION')
    return ret


def __config_macvlan_networks(config, macvlan_master_hostname):
    """
    This method is used for create macvlan network after multus
    :param config: input configuration file
    :param macvlan_master_hostname:
    :return ret :t/f
    """
    ret = False
    if config:
        logger.info('configure_mac_vlan networks')
        macvlan_nets = config.get(consts.K8S_KEY).get(
            consts.NET_IN_MACVLAN_KEY)
        for item1 in macvlan_nets:
            for key in item1:
                if key == "Multus_network":
                    multus_network = item1.get("Multus_network")
                    for item2 in multus_network:
                        for key2 in item2:
                            if key2 == "CNI_Configuration":
                                cni_conf = item2.get(
                                    "CNI_Configuration")
                                ret = __configure_macvlan_networks(
                                    cni_conf, macvlan_master_hostname)

    logger.info('Completed macvlan network config')
    return ret


def __configure_macvlan_networks(cni_conf, macvlan_master_hostname):
    ret = False
    for item3 in cni_conf:
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
                        consts.MASTER_PLUGIN_KEY)
                    macvlan_network_name = iface_dict.get(
                        "network_name")
                    macvlan_rangestart = iface_dict.get(
                        "rangeStart")
                    macvlan_rangeend = iface_dict.get(
                        "rangeEnd")
                    macvlan_routes_dst = iface_dict.get(
                        "routes_dst")
                    macvlan_subnet = iface_dict.get(
                        "subnet")
                    macvlan_type = iface_dict.get(
                        "type")
                    macvlan_node_hostname = iface_dict.get(
                        "hostname")
                    logger.info(
                        'macvlan_node_hostname is %s',
                        macvlan_node_hostname)
                    logger.info(
                        'macvlan_gateway is %s',
                        macvlan_gateway)
                    logger.info(
                        'macvlan_master_hostname is %s',
                        macvlan_master_hostname)
                    logger.info(
                        'macvlan_master is %s',
                        macvlan_master)
                    logger.info(
                        'macvlan_masterplugin is %s',
                        macvlan_masterplugin)
                    logger.info(
                        'macvlan_network_name is %s',
                        macvlan_network_name)
                    logger.info(
                        'macvlan_rangeStart is %s',
                        macvlan_rangestart)
                    logger.info(
                        'macvlan_rangeEnd is %s',
                        macvlan_rangeend)
                    logger.info(
                        'macvlan_routes_dst is %s',
                        macvlan_routes_dst)
                    logger.info(
                        'macvlan_subnet is %s',
                        macvlan_subnet)
                    logger.info(
                        'macvlan_type is %s',
                        macvlan_type)

                    if macvlan_masterplugin == "true":
                        if macvlan_type == "host-local":
                            logger.info(
                                'Master plugin is true && type is host-local')
                            ret = apbl.network_creation(
                                consts.K8_MACVLAN_MASTER_NETWORK_PATH,
                                macvlan_master_hostname,
                                macvlan_network_name,
                                macvlan_master,
                                macvlan_subnet,
                                macvlan_rangestart,
                                macvlan_rangeend,
                                macvlan_routes_dst,
                                macvlan_gateway,
                                consts.PROXY_DATA_FILE)
                            if not ret:
                                logger.error(
                                    'FAILED IN MACVLAN network '
                                    'creation_master1')
                        if macvlan_type == "dhcp":
                            logger.info(
                                'Master plugin is true && type is dhcp')
                            ret = apbl.network_dhcp_creation(
                                consts.K8_MACVLAN_MASTER_NETWORK_DHCP_PATH,
                                macvlan_master_hostname,
                                macvlan_network_name,
                                macvlan_master,
                                consts.PROXY_DATA_FILE)
                            if not ret:
                                logger.error(
                                    'FAILED IN MACVLAN network '
                                    'creation_master2')

                    if macvlan_masterplugin == "false":
                        if macvlan_type == "host-local":
                            logger.info(
                                'Master plugin is false && type is host-local')
                            ret = apbl.network_creation(
                                consts.K8_MACVLAN_NETWORK_PATH,
                                macvlan_master_hostname,
                                macvlan_network_name,
                                macvlan_master,
                                macvlan_subnet,
                                macvlan_rangestart,
                                macvlan_rangeend,
                                macvlan_routes_dst,
                                macvlan_gateway,
                                consts.PROXY_DATA_FILE)
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
                                macvlan_master,
                                consts.PROXY_DATA_FILE)
                            if not ret:
                                logger.error(
                                    'FAILED IN MACVLAN network creation2')

    return ret


def __config_macvlan_intf(config):
    """
    This method is used for create macvlan interface list after multus
    :param config :input configuration file
    :return ret :t/f
    """
    ret = False
    if config:
        logger.info('configure_mac_vlan interfaces')
        macvlan_nets = config.get(consts.K8S_KEY).get(
            consts.NET_IN_MACVLAN_KEY)
        for item1 in macvlan_nets:
            for key in item1:
                if key == "Multus_network":
                    multus_network = item1.get("Multus_network")
                    for item2 in multus_network:
                        for key2 in item2:
                            if key2 == "CNI_Configuration":
                                cni_conf = item2.get(
                                    "CNI_Configuration")
                                ret = __config_macvlan_intf_cni(cni_conf)

    logger.info('Exit')
    return ret


def __config_macvlan_intf_cni(cni_conf):
    ret = False
    for item3 in cni_conf:
        for key3 in item3:
            if key3 == "Macvlan":
                macvlan_network1 = item3.get(
                    "Macvlan")
                for macvlan_networks in macvlan_network1:
                    iface_dict = macvlan_networks.get(
                        "macvlan_networks")
                    macvlan_parent_interface = iface_dict.get(
                        "parent_interface")
                    macvlan_vlanid = iface_dict.get(
                        "vlanid")
                    macvlan_ip = iface_dict.get(
                        "ip")
                    macvlan_node_hostname = iface_dict.get(
                        "hostname")
                    logger.info(
                        'macvlan_node_hostname is %s',
                        macvlan_node_hostname)
                    logger.info(
                        'macvlan_parent_interface is %s',
                        macvlan_parent_interface)
                    logger.info(
                        'macvlan_vlanid is %s',
                        macvlan_vlanid)
                    logger.info(
                        'macvlan_ip is %s',
                        macvlan_ip)

                    ret = apbl.vlantag_interface(
                        consts.K8_VLAN_INTERFACE_PATH,
                        macvlan_node_hostname,
                        macvlan_parent_interface,
                        macvlan_vlanid,
                        macvlan_ip)
                    if not ret:
                        logger.error(
                            'FAILED IN MACVLAN'
                            'interface '
                            'creation')
    return ret


def __dhcp_installation(config):
    logger.info('CONFIGURING DHCP')
    nbr_hosts_network = config.get(consts.K8S_KEY).get(consts.NODE_CONF_KEY)
    ret = False

    for dhcp_host_fornetwork in nbr_hosts_network:
        if dhcp_host_fornetwork is not None:
            inetfacedict_fornetwork = dhcp_host_fornetwork.get("host")
            hostname_fornetwork = inetfacedict_fornetwork.get("hostname")
            node_type_fornetwork = inetfacedict_fornetwork.get("node_type")
            if node_type_fornetwork == "minion":
                macvlan_dhcp_daemon_playbook = consts.K8_DHCP_PATH
                logger.info('DHCP DAEMON RUNNING')
                ret = apbl.dhcp_daemon_creation(
                    macvlan_dhcp_daemon_playbook, hostname_fornetwork)
                if not ret:
                    logger.error('FAILED IN DHCP DAEMON installation')

    logger.info('Exit')
    return ret
