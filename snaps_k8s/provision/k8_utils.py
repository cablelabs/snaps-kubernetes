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
"""
Purpose : kubernetes Provisioning
Date :27/12/2017
Created By :Aricent
"""
import logging
import subprocess
# noinspection PyCompatibility
from pathlib import Path

import netaddr
import os

from snaps_common.ansible_snaps import ansible_utils

import snaps_k8s.ansible_p.ansible_utils.ansible_configuration as aconf
from snaps_k8s.common.consts import consts
from snaps_k8s.common.utils import config_utils

logger = logging.getLogger('k8_utils')


def execute(k8s_conf):
    if k8s_conf:
        aconf.provision_preparation(k8s_conf)
        __install_k8s(k8s_conf)
        __create_ceph_host(k8s_conf)
        __create_persist_vol(k8s_conf)
        __create_crd_net(k8s_conf)
        __create_multus_cni(k8s_conf)
        __enabling_basic_authentication(k8s_conf)
        __modifying_etcd_node(k8s_conf)
        __metrics_server(k8s_conf)


def __install_k8s(k8s_conf):
    node_confs = config_utils.get_node_configs(k8s_conf)
    __enable_key_ssh(node_confs)
    hostname_map = __get_hostname_map(k8s_conf)

    # duplicate ip check start
    default_network_items = config_utils.get_default_network(k8s_conf)
    multus_cni = config_utils.get_multus_net_elems(k8s_conf)
    if multus_cni:
        multus_cni_cfg = config_utils.get_multus_cni_cfg(k8s_conf)
        range_network_list = __get_net_ip_range(
            hostname_map=hostname_map, multus_cni=multus_cni,
            networks=multus_cni_cfg,
            default_network_items=default_network_items)
        ret = __validate_net_ip_range(range_network_list[0],
                                      range_network_list[1],
                                      range_network_list[2])
        if not ret:
            raise Exception(
                'VALIDATION FAILED IN NETWORK CONFIGURATION: '
                'OVERLAPPING IPS ARE FOUND')

    logger.info("PROVISION_PREPARATION AND DEPLOY METHOD CALLED")
    default_network = config_utils.get_default_network(k8s_conf)

    docker_repo = config_utils.get_docker_repo(k8s_conf)
    if docker_repo:
        docker_ip = docker_repo.get(consts.IP_KEY)
        docker_user = docker_repo.get(consts.USER_KEY)
        docker_pass = docker_repo.get(consts.PASSWORD_KEY)
        logger.info("Enable ssh key for Docker repository")
        __pushing_key(docker_ip, docker_user, docker_pass)

    project_name = config_utils.get_project_name(k8s_conf)
    host_node_type_map = __create_host_nodetype_map(k8s_conf)
    git_branch = k8s_conf.get(consts.K8S_KEY).get(consts.GIT_BRANCH_KEY)
    host_port_map = __create_host_port_map(node_confs)
    pod_subnet = default_network.get(consts.POD_SUB_KEY)
    networking_plugin = config_utils.get_networking_plugin(k8s_conf)
    service_subnet = config_utils.get_service_subnet(k8s_conf)
    aconf.start_k8s_install(
        hostname_map, host_node_type_map, host_port_map, service_subnet,
        pod_subnet, networking_plugin, docker_repo, node_confs, git_branch,
        project_name, k8s_conf, False)


def __create_ceph_host(k8s_conf):
    logger.info("cephhost creation")
    node_confs = config_utils.get_node_configs(k8s_conf)
    ceph_hosts = k8s_conf.get(consts.K8S_KEY).get(
        consts.PERSIS_VOL_KEY).get(consts.CEPH_VOLUME_KEY)
    if ceph_hosts:
        logger.info("enable ssh key for ceph IPs")
        __enable_key_ssh(ceph_hosts)
        aconf.launch_ceph_kubernetes(k8s_conf, node_confs, ceph_hosts)


def __create_persist_vol(k8s_conf):
    logger.info('Persistent host volume Start')
    host_node_type_map = __create_host_nodetype_map(k8s_conf)
    persistent_vol = k8s_conf.get(consts.K8S_KEY).get(
        consts.PERSIS_VOL_KEY).get(consts.HOST_VOL_KEY)
    if persistent_vol:
        aconf.launch_persitent_volume_kubernetes(
            k8s_conf, host_node_type_map, persistent_vol)


def __create_crd_net(k8s_conf):
    logger.info("Additional N/W plugins multus_cni installation")
    host_node_type_map = __create_host_nodetype_map(k8s_conf)
    networking_plugin = config_utils.get_networking_plugin(k8s_conf)
    hostname_map = __get_hostname_map(k8s_conf)
    multus_enabled = __get_multus_cni_value(k8s_conf)

    if multus_enabled:
        aconf.launch_crd_network(k8s_conf, hostname_map, host_node_type_map)

        aconf.launch_multus_cni(
            k8s_conf, hostname_map, host_node_type_map, networking_plugin)

        logger.info('MULTUS CONFIGURED SUCCESSFULLY.. NOW CREATING '
                    'DEFAULT PLUGIN NETWORK')
        if networking_plugin != "none":
            __create_default_network_multus(
                k8s_conf, hostname_map, host_node_type_map, networking_plugin)


def __create_multus_cni(k8s_conf):
    multus_network = config_utils.get_multus_network(k8s_conf)
    if multus_network:
        multus_cni = __get_multus_network_elements(multus_network, "CNI")
        multus_enabled = __get_multus_cni_value(k8s_conf)
        host_node_type_map = __create_host_nodetype_map(k8s_conf)
        dhcp_cni = __get_dhcp_value(k8s_conf)
        hostname_map = __get_hostname_map(k8s_conf)
        networking_plugin = config_utils.get_networking_plugin(k8s_conf)

        for cni in multus_cni:
            logger.info('multus_enabled: %s', multus_enabled)
            logger.info('cni: %s', cni)
            if multus_enabled:
                if "dhcp" == cni:
                    logger.info('DHCP Network Plugin')
                    if multus_enabled:
                        if dhcp_cni:
                            logger.info('CONFIGURING DHCP')
                            __dhcp_installation(k8s_conf)
                        else:
                            logger.info(
                                'DHCP CONFIGURATION  EXIT , '
                                'REASON--> DHCP  IS DISABLED ')
                elif "sriov" == cni:
                    logger.info('Sriov Network Plugin')
                    project_name = config_utils.get_project_name(k8s_conf)
                    hosts_data_dict = __get_sriov_nw_data(k8s_conf)
                    if hosts_data_dict is not None:
                        aconf.launch_sriov_cni_configuration(
                            k8s_conf, host_node_type_map, hosts_data_dict,
                            project_name)
                        aconf.launch_sriov_network_creation(
                            k8s_conf, host_node_type_map, hosts_data_dict)
                    else:
                        logger.info(
                            'Config data for SRIOV network is incomplete ')
                elif consts.FLANNEL_TYPE == cni:
                    logger.info('Flannel Network Plugin')
                    __launch_flannel_interface(
                        k8s_conf, hostname_map, host_node_type_map,
                        networking_plugin)
                elif consts.WEAVE_TYPE == cni:
                    logger.info('Weave Network Plugin')
                    __launch_weave_interface(k8s_conf)
                elif "macvlan" == cni:
                    logger.info('Macvlan Network Plugin')
                    if multus_enabled:
                        macvlan_cni = __get_macvlan_value(k8s_conf)
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

        if multus_enabled:
            aconf.delete_existing_conf_files_after_additional_plugins(
                hostname_map, host_node_type_map, networking_plugin)


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
                return False

        return True


def __get_network_item(networks, network_list_item):
    for network_item in networks:
        for key in network_item:
            if key == network_list_item:
                return network_item


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
            return False
    return True


def __get_multus_network(networks):
    for network_item in networks:
        for key in network_item:
            if key == "Multus_network":

                return network_item


def __get_multus_network_elements(multus_network, element):
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
    start_dict = {}
    end_dict = {}
    network_name_list = []
    default_cni_plugin = default_network_items.get("networking_plugin")

    if default_cni_plugin is None:
        start_dict = {}
        end_dict = {}
        network_name_list = []

    for cni in multus_cni:
        if cni == "sriov":
            for host in __network_dict(networks, "Sriov"):
                for key in host:
                    for network_item in host.get(key).get('networks'):
                        if network_item.get("type") == "host-local":
                            start_dict[network_item.get(
                                consts.NETWORK_NAME_KEY)] = network_item.get(
                                    "rangeStart")
                            end_dict[network_item.get(
                                consts.NETWORK_NAME_KEY)] = network_item.get(
                                "rangeEnd")
                            network_name_list.append(
                                network_item.get(consts.NETWORK_NAME_KEY))
        elif cni == "macvlan":
            for macvlan_network in __network_dict(networks, "Macvlan"):
                if macvlan_network.get("macvlan_networks").get(
                        "type") == "host-local":
                    start_dict[
                        macvlan_network.get("macvlan_networks").get(
                            "network_name")] = macvlan_network.get(
                                "macvlan_networks").get("rangeStart")
                    end_dict[macvlan_network.get("macvlan_networks").get(
                        "network_name")] = macvlan_network.get(
                            "macvlan_networks").get("rangeEnd")
                    network_name_list.append(macvlan_network.get(
                        "macvlan_networks").get("network_name"))

        return network_name_list, start_dict, end_dict


def clean_k8(k8s_conf):
    """
    This method is used for cleanup of kubernetes cluster
    :param k8s_conf :input configuration file
    """
    if k8s_conf:
        hosts = config_utils.get_node_configs(k8s_conf)
        __enable_key_ssh(hosts)
        hostname_map = __get_hostname_map(k8s_conf)
        host_node_type_map = __create_host_nodetype_map(k8s_conf)
        project_name = config_utils.get_project_name(k8s_conf)
        multus_enabled = __get_multus_cni_value_for_dynamic_node(k8s_conf)

        ansible_utils.apply_playbook(consts.K8_ENABLE_KUBECTL_CONTEXT,
                                     variables={'Project_name': project_name})

        networking_plugin = config_utils.get_networking_plugin(k8s_conf)

        __clean_up_flannel(
            hostname_map, host_node_type_map, networking_plugin, k8s_conf)
        __macvlan_cleanup(k8s_conf)

        logger.info('DHCP REMOVAL FOR CLUSTER')
        dhcp_cni = __get_dhcp_value(k8s_conf)
        if dhcp_cni:
            __dhcp_cleanup(k8s_conf)

        __clean_up_weave(
            hostname_map, host_node_type_map, networking_plugin,
            k8s_conf, project_name)

        metrics_server = config_utils.get_metrics_server(k8s_conf)
        logger.info("metrics_server flag in kube8 deployment file is %s",
                    str(metrics_server))
        aconf.clean_up_k8_addons(k8s_conf, hostname_map=hostname_map,
                                 host_node_type_map=host_node_type_map,
                                 metrics_server=metrics_server)
        aconf.clean_up_k8(k8s_conf, multus_enabled)


def __pushing_key(host_ip, user_name, password):
    # TODO/FIXME - remove or migrate to an ansible playbook
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
    # TODO/FIXME - remove or migrate function to a ansible playbook(s)
    command_time = "{} {}".format(
        "sed -i '/#timeout = 10/c\\timeout = 50'", consts.ANSIBLE_CONF)
    subprocess.call(command_time, shell=True)
    for i in range(len(hosts)):
        # TODO/FIXME - work towards getting rid of this requirement
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

        # TODO/FIXME - this needs to change before a user doesn't have to be
        # root
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

            # TODO/FIXME - Move this operation to a playbook
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


def __get_sriov_nw_data(config):
    num_net = config.get(consts.K8S_KEY).get(consts.NETWORKS_KEY)
    cni_configuration = None
    for item1 in num_net:
        for key1 in item1:
            if key1 == consts.MULTUS_NET_KEY:
                multus_network = item1.get(consts.MULTUS_NET_KEY)
                for item2 in multus_network:
                    for key2 in item2:
                        if key2 == consts.MULTUS_CNI_CONFIG_KEY:
                            cni_configuration = item2.get(consts.MULTUS_CNI_CONFIG_KEY)
                        else:
                            logger.info(
                                'CNI_Configuration tag not found in '
                                'config data')
            else:
                logger.info('Multus_network tag not found in config data')

    return cni_configuration


def __get_hostname_map(k8s_conf):
    """Get hostname map function"""
    node_confs = config_utils.get_node_configs(k8s_conf)
    hostname_map = {}
    for node_conf in node_confs:
        hostname = node_conf[consts.HOST_KEY].get(consts.HOSTNAME_KEY)
        host_ip = ""
        ip = node_conf[consts.HOST_KEY].get(consts.IP_KEY)
        if ip:
            host_ip = ip
        hostname_map[hostname] = host_ip

    return hostname_map


def __enabling_basic_authentication(k8s_conf):
    basic_authentication = config_utils.get_basic_auth(k8s_conf)
    """Basic Authentication function"""
    for i in range(len(basic_authentication)):
        user_name = basic_authentication[i].get(
            consts.USER_KEY).get(consts.USER_NAME_KEY)
        user_password = basic_authentication[i].get(
            consts.USER_KEY).get(consts.USER_PASS_KEY)
        user_id = basic_authentication[i].get(
            consts.USER_KEY).get(consts.USER_ID_KEY)
        pb_vars = {
            'user_name': user_name,
            'user_password': user_password,
            'user_id': user_id,
            'SRC_PACKAGE_PATH': consts.SRC_PKG_FLDR,
        }
        ansible_utils.apply_playbook(consts.KUBERNETES_USER_LIST,
                                     variables=pb_vars)

    master_host_name = aconf.get_host_master_name(k8s_conf)
    pb_vars = {
        'SRC_PACKAGE_PATH': consts.SRC_PKG_FLDR,
        'KUBERNETES_PATH': consts.KUBERNETES_PATH,
    }
    ansible_utils.apply_playbook(
        consts.KUBERNETES_AUTHENTICATION, [master_host_name],
        variables=pb_vars)


def __modifying_etcd_node(k8s_conf):
    """etcd modification changes"""
    host_node_type_map = __create_host_nodetype_map(k8s_conf)
    hostname_map = __get_hostname_map(k8s_conf)
    master_host_name = None
    master_ip = None
    for host_name, node_type in host_node_type_map.items():
        if node_type == "master":
            master_host_name = host_name
    for host_name, ip in hostname_map.items():
        if host_name == master_host_name:
            master_ip = ip

    ansible_utils.apply_playbook(consts.ETCD_CHANGES, [master_ip],
                                 variables={'ip': master_ip})


def __metrics_server(k8s_conf):
    metrics_server = config_utils.get_metrics_server(k8s_conf)
    if metrics_server:
        host_node_type_map = __create_host_nodetype_map(k8s_conf)
        aconf.launch_metrics_server(k8s_conf, host_node_type_map)


def __create_host_nodetype_map(k8s_conf):
    """Get Node types function"""
    node_confs = config_utils.get_node_configs(k8s_conf)
    hostnode_map = {}
    for node_conf in node_confs:
        node_type = node_conf[consts.HOST_KEY].get(consts.NODE_TYPE_KEY)
        hostname = node_conf[consts.HOST_KEY].get(consts.HOSTNAME_KEY)
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


def __remove_macvlan_networks(config):
    """
    This method is used for remove macvlan network after multus
    :param config: input configuration file
    """
    if config:
        logger.info('Removal_mac_vlan networks')
        macvlan_nets = config.get(consts.K8S_KEY).get(
            consts.NET_IN_MACVLAN_KEY)
        for item1 in macvlan_nets:
            for key1 in item1:
                if key1 == consts.MULTUS_NET_KEY:
                    multus_network = item1.get(consts.MULTUS_NET_KEY)
                    for item2 in multus_network:
                        for key2 in item2:
                            if key2 == consts.MULTUS_CNI_CONFIG_KEY:
                                cni_conf = item2.get(
                                    consts.MULTUS_CNI_CONFIG_KEY)
                                __remove_macvlan_networks_cni(cni_conf)


def __remove_macvlan_networks_cni(cni_conf):
    for item3 in cni_conf:
        for key3 in item3:
            if key3 == "Macvlan":
                macvlan_network1 = item3.get(
                    "Macvlan")
                for macvlan_networks in macvlan_network1:
                    iface_dict = macvlan_networks.get("macvlan_networks")
                    network_name = iface_dict.get(consts.NETWORK_NAME_KEY)
                    ansible_utils.apply_playbook(
                        consts.K8_MACVLAN_NETWORK_REMOVAL_PATH,
                        variables={'network_name': network_name})


def __removal_macvlan_interface(k8s_conf):
    """
    This method is used for create macvlan network after multus
    :param k8s_conf :input configuration file
    """
    if k8s_conf:
        logger.info('Removal_mac_vlan interfaces')
        nets_in_mac_vlan = config_utils.get_macvlan_nets(k8s_conf)
        for item1 in nets_in_mac_vlan:
            for key1 in item1:
                if key1 == consts.MULTUS_NET_KEY:
                    multus_network = item1.get(consts.MULTUS_NET_KEY)
                    for item2 in multus_network:
                        for key2 in item2:
                            if key2 == consts.MULTUS_CNI_CONFIG_KEY:
                                cni_conf = item2.get(
                                    consts.MULTUS_CNI_CONFIG_KEY)
                                __removal_macvlan_interface_cni(cni_conf)


def __removal_macvlan_interface_cni(cni_conf):
    for item3 in cni_conf:
        for key3 in item3:
            if key3 == "Macvlan":
                macvlan_network1 = item3.get("Macvlan")
                for mvlan_nets in macvlan_network1:
                    iface_dict = mvlan_nets.get("macvlan_networks")
                    mvlan_parent_intf = iface_dict.get("parent_interface")
                    mvlan_id = iface_dict.get("vlanid")
                    mvlan_node_host = iface_dict.get("hostname")
                    pb_vars = {
                        'parentInterface': mvlan_parent_intf,
                        'vlanId': str(mvlan_id),
                    }
                    ansible_utils.apply_playbook(
                        consts.K8_VLAN_INTERFACE_REMOVAL_PATH,
                        [mvlan_node_host], variables=pb_vars)


def __macvlan_cleanup(k8s_conf):
    logger.info("MACVLAN PLUGIN REMOVAL")
    macvlan_cni = __get_macvlan_value(k8s_conf)
    logger.info('macvlan value n __macvlan_cleanup function:%s', macvlan_cni)
    if macvlan_cni:
        logger.info('REMOVING MACVLAN')
        __removal_macvlan_interface(k8s_conf)
        __remove_macvlan_networks(k8s_conf)
    else:
        logger.info(
            'MAC-VLAN CONFIGURATION  EXIT , REASON--> MACVLAN  IS DISABLED ')


def __macvlan_installation(k8s_conf):
    logger.info('CONFIGURING MAC-VLAN')
    __config_macvlan_intf(k8s_conf)
    master_node_macvlan = aconf.get_host_master_name(k8s_conf)
    __config_macvlan_networks(k8s_conf, master_node_macvlan)


def __get_macvlan_value(config):
    """
    This function is used to get multus cni value
    """
    ret = False
    nbr_networks = config.get(consts.K8S_KEY).get(consts.NETWORKS_KEY)
    for item1 in nbr_networks:
        for key1 in item1:
            if key1 == consts.MULTUS_NET_KEY:
                multus_network = item1.get(consts.MULTUS_NET_KEY)
                for item2 in multus_network:
                    for key2 in item2:
                        if key2 == "CNI":
                            multus_cni = item2.get("CNI")
                            if multus_cni:
                                for cni in multus_cni:
                                    if cni == "macvlan":
                                        ret = True

    return ret


def __dhcp_cleanup(k8s_conf):
    logger.info('REMOVING DHCP')
    node_confs = config_utils.get_node_configs(k8s_conf)
    hosts = list()
    for node_conf in node_confs:
        host = node_conf.get(consts.HOST_KEY)
        hostname = host.get(consts.HOSTNAME_KEY)
        node_type = host.get(consts.NODE_TYPE_KEY)
        if node_type == "minion":
            hosts.append(hostname)

    if len(hosts) > 0:
        ansible_utils.apply_playbook(consts.K8_DHCP_REMOVAL_PATH, hosts)


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
            if key1 == consts.MULTUS_NET_KEY:
                multus_network = item1.get(consts.MULTUS_NET_KEY)
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


def __create_default_network_multus(k8s_conf, hostname_map, host_node_type_map,
                                    networking_plugin):
    """
    This function is used to create default network
    """
    default_network = config_utils.get_default_network(k8s_conf)
    if (networking_plugin == consts.WEAVE_TYPE
            or networking_plugin == consts.FLANNEL_TYPE
            and default_network):
        aconf.create_default_network(
            k8s_conf, hostname_map, host_node_type_map, networking_plugin,
            default_network)
    else:
        logger.info('Cannot create default network as default networking ' +
                    'plugin is other than flannel/weave')


def __launch_flannel_interface(k8s_conf, hostname_map, host_node_type_map,
                               networking_plugin):
    """
    This function is used to create flannel interface
    """
    if networking_plugin != consts.FLANNEL_TYPE:
        networks = config_utils.get_networks(k8s_conf)
        for item1 in networks:
            for key1 in item1:
                if key1 == consts.MULTUS_NET_KEY:
                    multus_network = item1.get(consts.MULTUS_NET_KEY)
                    for item2 in multus_network:
                        for key2 in item2:
                            if key2 == consts.MULTUS_CNI_CONFIG_KEY:
                                cni_configuration = item2.get(
                                    consts.MULTUS_CNI_CONFIG_KEY)
                                for item3 in cni_configuration:
                                    for key3 in item3:
                                        if consts.FLANNEL_NET_TYPE == key3:
                                            aconf.create_flannel_interface(
                                                k8s_conf, hostname_map,
                                                host_node_type_map,
                                                networks,
                                                config_utils.get_proxy_dict(
                                                    k8s_conf))
    else:
        raise Exception(
            'FLANNEL IS ALREADY CONFIGURED AS DEFAULT NETWORKING PLUGIN, ' +
            'PLEASE PROVIDE MULTUS PLUGIN OTHER THAN FLANNEL')


def __launch_weave_interface(k8s_conf):
    """
    This function is used to create weave interface
    """
    weave_details = config_utils.get_multus_weave_details(k8s_conf)
    if weave_details:
        hostname_map = __get_hostname_map(k8s_conf)
        host_node_type_map = __create_host_nodetype_map(k8s_conf)
        weave_network_list_map = config_utils.get_multus_cni_cfg(k8s_conf)
        networking_plugin = config_utils.get_networking_plugin(k8s_conf)
        for item in weave_network_list_map:
            for key in item:
                if consts.WEAVE_NET_TYPE == key:
                    weave_network = item.get(consts.WEAVE_NET_TYPE)
                    for item1 in weave_network:
                        aconf.create_weave_interface(
                            k8s_conf, hostname_map, host_node_type_map,
                            networking_plugin, item1)
    else:
        raise Exception('WEAVE IS ALREADY CONFIGURED AS DEFAULT NETWORKING '
                        'PLUGIN, PLEASE PROVIDE ANOTHER MULTUS PLUGIN')


def __get_dhcp_value(k8s_conf):
    """
    This function is used to get multus cni value
    """
    num_nets = config_utils.get_networks(k8s_conf)
    for item1 in num_nets:
        for key1 in item1:
            if key1 == consts.MULTUS_NET_KEY:
                multus_network = item1.get(consts.MULTUS_NET_KEY)
                for item2 in multus_network:
                    for key2 in item2:
                        if key2 == "CNI":
                            multus_cni = item2.get("CNI")
                            if multus_cni:
                                for cni in multus_cni:
                                    if cni == "dhcp":
                                        return True
    return False


def __get_flannel_value(k8s_conf):
    """
    This function is used to get multus cni value
    """
    ret = False
    num_nets = config_utils.get_networks(k8s_conf)
    for item1 in num_nets:
        for key1 in item1:
            if key1 == consts.MULTUS_NET_KEY:
                multus_network = item1.get(consts.MULTUS_NET_KEY)
                for item2 in multus_network:
                    for key2 in item2:
                        if key2 == "CNI":
                            multus_cni = item2.get("CNI")
                            if multus_cni:
                                for cni in multus_cni:
                                    if cni == consts.FLANNEL_TYPE:
                                        ret = True

    return ret


def __get_weave_nw_data(config):
    """
    This function is used for get the weave network info
    """
    hosts_data_dict = config.get(consts.K8S_KEY).get(consts.NETWORKS_KEY)
    return hosts_data_dict


def __get_multus_cni_value_for_dynamic_node(k8s_conf):
    """
    This function is used to get multus cni value for dynamic node
    """
    ret = __check_multus_cni_deploy_config(k8s_conf)
    if ret:
        logger.info("Setting multus_cni to true, as flannel/weave was "
                    "enabled as additional plugin at cluster creation")
    return ret


def __check_multus_cni_deploy_config(k8s_conf):
    """
    This function is used to get multus cni value configured at
    cluster creation
    """
    flannel_cni = False
    weave_cni = False
    logger.info("Function __check_multus_cni_deploy_config")
    nbr_networks = config_utils.get_networks(k8s_conf)
    for item1 in nbr_networks:
        for key in item1:
            if key == consts.MULTUS_NET_KEY:
                multus_network = item1.get(consts.MULTUS_NET_KEY)
                for item2 in multus_network:
                    for key2 in item2:
                        if key2 == "CNI":
                            multus_cni = item2.get("CNI")
                            if multus_cni:
                                for cni in multus_cni:
                                    if cni == consts.FLANNEL_TYPE:
                                        flannel_cni = True
                                    elif cni == consts.WEAVE_TYPE:
                                        weave_cni = True
    return flannel_cni or weave_cni


def __get_weave_value(k8s_conf):
    """
    This function is used to get multus cni value
    """
    ret = False
    nbr_networks = config_utils.get_networks(k8s_conf)
    for item1 in nbr_networks:
        for key in item1:
            if key == consts.MULTUS_NET_KEY:
                multus_network = item1.get(consts.MULTUS_NET_KEY)
                for item2 in multus_network:
                    for key2 in item2:
                        if key2 == "CNI":
                            multus_cni = item2.get("CNI")
                            if multus_cni:
                                for cni in multus_cni:
                                    if cni == consts.WEAVE_TYPE:
                                        ret = True
    return ret


def __clean_up_flannel(hostname_map, host_node_type_map,
                       networking_plugin, k8s_conf):
    """
    This function is used to clean the flannel additional plugin
    """
    if k8s_conf:
        if networking_plugin != consts.FLANNEL_TYPE:
            flannel_cni = __get_flannel_value(k8s_conf)
            networks = config_utils.get_networks(k8s_conf)
            if flannel_cni:
                aconf.delete_flannel_interfaces(
                    hostname_map, host_node_type_map, networks,
                    k8s_conf)


def __clean_up_weave(hostname_map, host_node_type_map,
                     networking_plugin, k8s_conf, project_name):
    """
    This function is used to clean the weave additional plugin
    """
    if k8s_conf:
        if networking_plugin != "weave":
            logger.info(
                'DEFAULT NETWOKRING PLUGUN IS NOT WEAVE.. '
                'CHECK MULTUS CNI PLUGINS')
            weave_cni = __get_weave_value(k8s_conf)
            hosts_data_dict = __get_weave_nw_data(k8s_conf)
            if weave_cni:
                aconf.delete_weave_interface(
                    hostname_map, host_node_type_map,
                    hosts_data_dict, k8s_conf)
        else:
            logger.info('WEAVE IS DEFAULT PLUGIN')
            hosts_data_dict = __get_weave_nw_data(k8s_conf)
            aconf.delete_default_weave_interface(
                hostname_map, host_node_type_map, hosts_data_dict,
                k8s_conf)


def __config_macvlan_networks(k8s_conf, macvlan_master_hostname):
    """
    This method is used for create macvlan network after multus
    :param k8s_conf: input configuration file
    :param macvlan_master_hostname:
    """
    if k8s_conf:
        logger.info('configure_mac_vlan networks')
        macvlan_nets = config_utils.get_macvlan_nets(k8s_conf)
        for item1 in macvlan_nets:
            for key in item1:
                if key == consts.MULTUS_NET_KEY:
                    multus_network = item1.get(consts.MULTUS_NET_KEY)
                    for item2 in multus_network:
                        for key2 in item2:
                            if key2 == consts.MULTUS_CNI_CONFIG_KEY:
                                cni_conf = item2.get(
                                    consts.MULTUS_CNI_CONFIG_KEY)
                                __configure_macvlan_networks(
                                    k8s_conf, cni_conf,
                                    macvlan_master_hostname)


def __configure_macvlan_networks(k8s_conf, cni_conf, macvlan_master_hostname):
    for item3 in cni_conf:
        for key3 in item3:
            if key3 == "Macvlan":
                macvlan_network1 = item3.get("Macvlan")
                for macvlan_networks in macvlan_network1:
                    iface_dict = macvlan_networks.get("macvlan_networks")
                    macvlan_gateway = iface_dict.get("gateway")
                    macvlan_master = iface_dict.get("master")
                    macvlan_masterplugin = iface_dict.get(
                        consts.MASTER_PLUGIN_KEY)
                    macvlan_network_name = iface_dict.get(
                        consts.NETWORK_NAME_KEY)
                    macvlan_rangestart = iface_dict.get("rangeStart")
                    macvlan_rangeend = iface_dict.get("rangeEnd")
                    macvlan_routes_dst = iface_dict.get("routes_dst")
                    macvlan_subnet = iface_dict.get(consts.SUBNET_KEY)
                    macvlan_type = iface_dict['type']
                    pb_vars = {
                        'network_name': macvlan_network_name,
                        'interface_node': macvlan_master,
                        'subnet': macvlan_subnet,
                        'rangeStart': macvlan_rangestart,
                        'rangeEnd': macvlan_rangeend,
                        'dst': macvlan_routes_dst,
                        'gateway': macvlan_gateway,
                    }
                    pb_vars.update(config_utils.get_proxy_dict(k8s_conf))
                    if macvlan_masterplugin == "true":
                        if macvlan_type == "host-local":
                            ansible_utils.apply_playbook(
                                consts.K8_MACVLAN_MASTER_NETWORK_PATH,
                                [macvlan_master_hostname],
                                variables=pb_vars)
                        elif macvlan_type == "dhcp":
                            ansible_utils.apply_playbook(
                                consts.K8_MACVLAN_MASTER_NETWORK_DHCP_PATH,
                                [macvlan_master_hostname],
                                variables=pb_vars)
                    elif macvlan_masterplugin == "false":
                        if macvlan_type == "host-local":
                            ansible_utils.apply_playbook(
                                consts.K8_MACVLAN_NETWORK_PATH,
                                [macvlan_master_hostname],
                                variables=pb_vars)
                        elif macvlan_type == "dhcp":
                            ansible_utils.apply_playbook(
                                consts.K8_MACVLAN_NETWORK_DHCP_PATH,
                                [macvlan_master_hostname],
                                variables=pb_vars)


def __config_macvlan_intf(k8s_conf):
    """
    This method is used for create macvlan interface list after multus
    :param k8s_conf :input configuration file
    """
    if k8s_conf:
        logger.info('configure_mac_vlan interfaces')
        macvlan_nets = config_utils.get_macvlan_nets(k8s_conf)
        for item1 in macvlan_nets:
            for key in item1:
                if key == consts.MULTUS_NET_KEY:
                    multus_network = item1.get(consts.MULTUS_NET_KEY)
                    for item2 in multus_network:
                        for key2 in item2:
                            if key2 == consts.MULTUS_CNI_CONFIG_KEY:
                                cni_conf = item2.get(
                                    consts.MULTUS_CNI_CONFIG_KEY)
                                __config_macvlan_intf_cni(cni_conf)


def __config_macvlan_intf_cni(cni_conf):
    for item3 in cni_conf:
        for key3 in item3:
            if key3 == "Macvlan":
                macvlan_network1 = item3.get("Macvlan")
                for macvlan_networks in macvlan_network1:
                    iface_dict = macvlan_networks.get("macvlan_networks")
                    macvlan_node_hostname = iface_dict.get(consts.HOSTNAME_KEY)
                    macvlan_ip = iface_dict.get(consts.IP_KEY)
                    pb_vars = {
                        'parentInterface': iface_dict.get("parent_interface"),
                        'vlanId': str(iface_dict['vlanid']),
                        'ip': macvlan_ip,
                    }
                    ansible_utils.apply_playbook(
                        consts.K8_VLAN_INTERFACE_PATH, [macvlan_node_hostname],
                        variables=pb_vars)


def __dhcp_installation(k8s_conf):
    logger.info('CONFIGURING DHCP')
    node_confs = config_utils.get_node_configs(k8s_conf)
    for node_conf in node_confs:
        if node_conf is not None:
            net_ifaces = node_conf.get(consts.HOST_KEY)
            hostname = net_ifaces.get(consts.HOSTNAME_KEY)
            node_type = net_ifaces.get(consts.NODE_TYPE_KEY)
            if node_type == "minion":
                ansible_utils.apply_playbook(consts.K8_DHCP_PATH,
                                             [hostname])
