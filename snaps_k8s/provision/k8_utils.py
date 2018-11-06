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

import netaddr

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
    aconf.start_k8s_install(k8s_conf)


def __create_ceph_host(k8s_conf):
    logger.info("Ceph host creation")
    ceph_hosts = config_utils.get_ceph_vol(k8s_conf)
    if ceph_hosts:
        aconf.launch_ceph_kubernetes(k8s_conf)


def __create_persist_vol(k8s_conf):
    logger.info('Persistent host volume Start')
    aconf.launch_persitent_volume_kubernetes(k8s_conf)


def __create_crd_net(k8s_conf):
    logger.info("Additional N/W plugins multus_cni installation")
    multus_enabled = __is_multus_cni_enabled(k8s_conf)

    if multus_enabled:
        aconf.launch_crd_network(k8s_conf)
        aconf.launch_multus_cni(k8s_conf)
        __create_default_network_multus(k8s_conf)


def __create_multus_cni(k8s_conf):
    multus_enabled = __is_multus_cni_enabled(k8s_conf)
    if multus_enabled:
        multus_elems = config_utils.get_multus_net_elems(k8s_conf)
        if consts.DHCP_TYPE in multus_elems:
            __dhcp_installation(k8s_conf)

        if consts.SRIOV_TYPE in multus_elems:
            aconf.launch_sriov_cni_configuration(k8s_conf)
            aconf.launch_sriov_network_creation(k8s_conf)

        if consts.FLANNEL_TYPE in multus_elems:
            aconf.create_flannel_interface(k8s_conf)

        if consts.WEAVE_TYPE in multus_elems:
            __launch_weave_interface(k8s_conf)

        if consts.MACVLAN_TYPE in multus_elems:
            __macvlan_installation(k8s_conf)

        ips = config_utils.get_minion_node_ips(k8s_conf)
        networking_plugin = config_utils.get_networking_plugin(k8s_conf)
        ansible_utils.apply_playbook(
            consts.K8_CONF_FILES_DELETION_AFTER_MULTUS, ips, consts.NODE_USER,
            variables={
                'networking_plugin': networking_plugin,
                'PROJECT_PATH': consts.PROJECT_PATH,
                'Project_name': config_utils.get_project_name(k8s_conf),
            })
    else:
        logger.info('MULTUS CNI IS DISABLED')


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


def clean_k8(k8s_conf):
    """
    This method is used for cleanup of kubernetes cluster
    :param k8s_conf :input configuration file
    """
    if k8s_conf:
        ansible_utils.apply_playbook(
            consts.K8_ENABLE_KUBECTL_CONTEXT,
            variables={
                'Project_name': config_utils.get_project_name(k8s_conf),
                'PROJECT_PATH': consts.PROJECT_PATH,
            })

        __clean_up_flannel(k8s_conf)
        __macvlan_cleanup(k8s_conf)

        logger.info('DHCP REMOVAL FOR CLUSTER')
        __dhcp_cleanup(k8s_conf)

        __clean_up_weave(k8s_conf)

        aconf.clean_up_metrics_server(k8s_conf)

        multus_enabled = __get_multus_cni_value_for_dynamic_node(k8s_conf)
        aconf.clean_up_k8(k8s_conf, multus_enabled)


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
        consts.KUBERNETES_AUTHENTICATION, [master_host_name], consts.NODE_USER,
        variables=pb_vars)


def __modifying_etcd_node(k8s_conf):
    """etcd modification changes"""
    master_host_name, master_ip = config_utils.get_first_master_host(k8s_conf)
    ansible_utils.apply_playbook(
        consts.ETCD_CHANGES, [master_ip], consts.NODE_USER,
        variables={'ip': master_ip})


def __metrics_server(k8s_conf):
    logger.info("launch metrics_server")
    master_nodes_tuple_3 = config_utils.get_master_nodes_ip_name_type(k8s_conf)
    pb_vars = {
        'PROJECT_PATH': consts.PROJECT_PATH,
        'Project_name': config_utils.get_project_name(k8s_conf),
    }
    pb_vars.update(config_utils.get_proxy_dict(k8s_conf))
    for host_name, ip, node_type in master_nodes_tuple_3:
        ansible_utils.apply_playbook(
            consts.K8_METRICS_SERVER, [host_name], consts.NODE_USER,
            variables=pb_vars)
        break


def __remove_macvlan_networks(k8s_conf):
    """
    This method is used for remove macvlan network after multus
    :param k8s_conf: input configuration file
    """
    mvlan_cfgs = config_utils.get_multus_cni_macvlan_cfgs(k8s_conf)
    for mvlan_cfg in mvlan_cfgs:
        iface_dict = mvlan_cfg[consts.MACVLAN_NET_DTLS_KEY]
        ansible_utils.apply_playbook(
            consts.K8_MACVLAN_NETWORK_REMOVAL_PATH,
            variables={
                'network_name': iface_dict[consts.NETWORK_NAME_KEY],
                'PROJECT_PATH': consts.PROJECT_PATH,
                'Project_name': config_utils.get_project_name(k8s_conf),
            })


def __removal_macvlan_interface(k8s_conf):
    """
    This method is used for create macvlan network after multus
    :param k8s_conf :input configuration file
    """
    mac_vlans = config_utils.get_multus_cni_macvlan_cfgs(k8s_conf)
    for mac_vlan in mac_vlans:
        iface_dict = mac_vlan[consts.MACVLAN_NET_DTLS_KEY]
        pb_vars = {
            'parentInterface': iface_dict.get("parent_interface"),
            'vlanId': str(iface_dict.get("vlanid")),
        }
        ansible_utils.apply_playbook(
            consts.K8_VLAN_INTERFACE_REMOVAL_PATH,
            [iface_dict.get("hostname")], consts.NODE_USER, variables=pb_vars)


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
    __config_macvlan_networks(k8s_conf)


def __get_macvlan_value(k8s_conf):
    """
    This function is used to get multus cni value
    """
    multus_cnis = config_utils.get_multus_net_elems(k8s_conf)
    return consts.MACVLAN_TYPE in multus_cnis


def __dhcp_cleanup(k8s_conf):
    logger.info('REMOVING DHCP')
    multus_elems = config_utils.get_multus_net_elems(k8s_conf)
    if consts.DHCP_TYPE in multus_elems:
        ips = config_utils.get_minion_node_ips(k8s_conf)
        ansible_utils.apply_playbook(
            consts.K8_DHCP_REMOVAL_PATH, ips, consts.NODE_USER)


def __is_multus_cni_enabled(k8s_conf):
    """
    This function is used to get multus cni value
    """
    sriov_cni = False
    flannel_cni = False
    weave_cni = False
    macvlan_cni = False
    multus_cni = config_utils.get_multus_net_elems(k8s_conf)
    for cni in multus_cni:
        if consts.SRIOV_TYPE == cni:
            sriov_cni = True
        elif consts.FLANNEL_TYPE == cni:
            flannel_cni = True
        elif consts.WEAVE_TYPE == cni:
            weave_cni = True
        elif consts.MACVLAN_TYPE == cni:
            macvlan_cni = True
    return sriov_cni or flannel_cni or weave_cni or macvlan_cni


def __create_default_network_multus(k8s_conf):
    """
    This function is used to create default network
    """
    networking_plugin = config_utils.get_networking_plugin(k8s_conf)
    if networking_plugin != "none":
        default_network = config_utils.get_default_network(k8s_conf)
        if (networking_plugin == consts.WEAVE_TYPE
                or networking_plugin == consts.FLANNEL_TYPE
                and default_network):
            aconf.create_default_network(k8s_conf)
        else:
            logger.info('Cannot create default network as default networking '
                        'plugin is other than flannel/weave')


def __launch_weave_interface(k8s_conf):
    """
    This function is used to create weave interface
    """
    weave_details = config_utils.get_multus_cni_weave_cfgs(k8s_conf)
    for weave_detail in weave_details:
        aconf.create_weave_interface(k8s_conf, weave_detail)


def __get_multus_cni_value_for_dynamic_node(k8s_conf):
    """
    This function is used to get multus cni value for dynamic node
    """
    multus_cni_elems = config_utils.get_multus_net_elems(k8s_conf)
    for multus_cni_elem in multus_cni_elems:
        if multus_cni_elem == consts.FLANNEL_TYPE:
            return True
        if multus_cni_elem == consts.WEAVE_TYPE:
            return True
    return False


def __clean_up_flannel(k8s_conf):
    """
    This function is used to clean the flannel additional plugin
    """
    networking_plugin = config_utils.get_networking_plugin(k8s_conf)
    mult_elems = config_utils.get_multus_net_elems(k8s_conf)
    if (networking_plugin != consts.FLANNEL_TYPE
            and consts.FLANNEL_TYPE in mult_elems):
        aconf.delete_flannel_interfaces(k8s_conf)


def __clean_up_weave(k8s_conf):
    """
    This function is used to clean the weave additional plugin
    """
    networking_plugin = config_utils.get_networking_plugin(k8s_conf)
    if networking_plugin != consts.WEAVE_TYPE:
        logger.info(
            'DEFAULT NETWOKRING PLUGUN IS NOT WEAVE.. '
            'CHECK MULTUS CNI PLUGINS')
        if (consts.MULTUS_NET_KEY
                in config_utils.get_multus_net_elems(k8s_conf)):
            aconf.delete_weave_interface(k8s_conf)
    else:
        logger.info('WEAVE IS DEFAULT PLUGIN')
        aconf.delete_default_weave_interface(k8s_conf)


def __config_macvlan_networks(k8s_conf):
    """
    This method is used for create macvlan network after multus
    :param k8s_conf: input configuration file
    """
    macvlan_master_hostname = aconf.get_host_master_name(k8s_conf)
    macvlan_nets = config_utils.get_multus_cni_macvlan_cfgs(k8s_conf)
    for mvlan_net in macvlan_nets:
        iface_dict = mvlan_net.get(consts.MACVLAN_NET_DTLS_KEY)
        macvlan_masterplugin = iface_dict.get(consts.MASTER_PLUGIN_KEY)
        macvlan_type = iface_dict['type']
        pb_vars = {
            'network_name': iface_dict.get(consts.NETWORK_NAME_KEY),
            'interface_node': iface_dict.get("master"),
            'subnet': iface_dict.get(consts.SUBNET_KEY),
            'rangeStart': iface_dict.get("rangeStart"),
            'rangeEnd': iface_dict.get("rangeEnd"),
            'dst': iface_dict.get("routes_dst"),
            'gateway': iface_dict.get("gateway"),
            'PROJECT_PATH': consts.PROJECT_PATH,
            'Project_name': config_utils.get_project_name(k8s_conf),
        }
        pb_vars.update(config_utils.get_proxy_dict(k8s_conf))
        if macvlan_masterplugin == "true":
            if macvlan_type == "host-local":
                ansible_utils.apply_playbook(
                    consts.K8_MACVLAN_MASTER_NETWORK_PATH,
                    [macvlan_master_hostname], consts.NODE_USER,
                    variables=pb_vars)
            elif macvlan_type == consts.DHCP_TYPE:
                ansible_utils.apply_playbook(
                    consts.K8_MACVLAN_MASTER_NETWORK_DHCP_PATH,
                    [macvlan_master_hostname], consts.NODE_USER,
                    variables=pb_vars)
        elif macvlan_masterplugin == "false":
            if macvlan_type == "host-local":
                ansible_utils.apply_playbook(
                    consts.K8_MACVLAN_NETWORK_PATH,
                    [macvlan_master_hostname], consts.NODE_USER,
                    variables=pb_vars)
            elif macvlan_type == consts.DHCP_TYPE:
                ansible_utils.apply_playbook(
                    consts.K8_MACVLAN_NETWORK_DHCP_PATH,
                    [macvlan_master_hostname], consts.NODE_USER,
                    variables=pb_vars)


def __config_macvlan_intf(k8s_conf):
    """
    This method is used for create macvlan interface list after multus
    :param k8s_conf :input configuration file
    """
    macvlan_cfgs = config_utils.get_multus_cni_macvlan_cfgs(k8s_conf)
    for macvlan_networks in macvlan_cfgs:
        iface_dict = macvlan_networks.get("macvlan_networks")
        hostname = iface_dict.get(consts.HOSTNAME_KEY)
        ip = iface_dict.get(consts.IP_KEY)
        pb_vars = {
            'parentInterface': iface_dict.get("parent_interface"),
            'vlanId': str(iface_dict['vlanid']),
            'ip': ip,
        }
        ansible_utils.apply_playbook(
            consts.K8_VLAN_INTERFACE_PATH, [hostname], consts.NODE_USER,
            variables=pb_vars)


def __dhcp_installation(k8s_conf):
    logger.info('CONFIGURING DHCP')
    ips = config_utils.get_minion_node_ips(k8s_conf)
    ansible_utils.apply_playbook(consts.K8_DHCP_PATH, ips, consts.NODE_USER)
