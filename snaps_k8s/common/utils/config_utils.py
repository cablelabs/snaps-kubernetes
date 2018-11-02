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
import logging

from snaps_k8s.common.consts import consts


"""
Utilities for parsing the k8s deployment configuration
"""

logger = logging.getLogger('config_utils')


def get_proxy_dict(k8s_conf):
    return k8s_conf.get(consts.K8S_KEY).get(consts.PROXIES_KEY)


def get_networks(k8s_conf):
    return k8s_conf.get(consts.K8S_KEY).get(consts.NETWORKS_KEY)


def get_multus_network(k8s_conf):
    networks = get_networks(k8s_conf)
    for network in networks:
        if consts.MULTUS_NET_KEY in network:
            return network[consts.MULTUS_NET_KEY]


def get_multus_elems(k8s_conf, key):
    multus_cfgs = get_multus_network(k8s_conf)
    for multus_cfg in multus_cfgs:
        if key in multus_cfg:
            return multus_cfg.get(key)


def get_multus_net_elems(k8s_conf):
    return get_multus_elems(k8s_conf, consts.MULTUS_CNI_KEY)


def get_multus_cni_cfgs(k8s_conf):
    return get_multus_elems(k8s_conf, consts.MULTUS_CNI_CONFIG_KEY)


def get_multus_cni_flannel_cfgs(k8s_conf):
    cni_elems = get_multus_elems(k8s_conf, consts.MULTUS_CNI_CONFIG_KEY)
    for cni_elem in cni_elems:
        if consts.FLANNEL_NET_TYPE in cni_elem:
            return cni_elem[consts.FLANNEL_NET_TYPE]
    return list()


def get_multus_cni_macvlan_cfgs(k8s_conf):
    cni_elems = get_multus_elems(k8s_conf, consts.MULTUS_CNI_CONFIG_KEY)
    for cni_elem in cni_elems:
        if consts.MACVLAN_NET_TYPE in cni_elem:
            return cni_elem[consts.MACVLAN_NET_TYPE]
    return list()


def get_multus_cni_sriov_cfgs(k8s_conf):
    cni_elems = get_multus_elems(k8s_conf, consts.MULTUS_CNI_CONFIG_KEY)
    for cni_elem in cni_elems:
        if consts.SRIOV_NET_TYPE in cni_elem:
            return cni_elem[consts.SRIOV_NET_TYPE]
    return list()


def get_multus_cni_weave_cfgs(k8s_conf):
    cni_elems = get_multus_elems(k8s_conf, consts.MULTUS_CNI_CONFIG_KEY)
    for cni_elem in cni_elems:
        if consts.WEAVE_NET_TYPE in cni_elem:
            return cni_elem[consts.WEAVE_NET_TYPE]
    return list()


def get_default_network(k8s_conf):
    networks = get_networks(k8s_conf)
    for network in networks:
        if consts.DFLT_NET_KEY in network:
                return network[consts.DFLT_NET_KEY]


def get_service_subnet(k8s_conf):
    default_network = get_default_network(k8s_conf)
    if default_network:
        return default_network[consts.SRVC_SUB_KEY]


def get_networking_plugin(k8s_conf):
    default_network = get_default_network(k8s_conf)
    if default_network:
        return default_network[consts.NET_PLUGIN_KEY]


def get_pod_subnet(k8s_conf):
    default_network = get_default_network(k8s_conf)
    if default_network:
        return default_network[consts.POD_SUB_KEY]


def get_version(k8s_conf):
    return k8s_conf[consts.K8S_KEY][consts.K8_VER_KEY]


def get_ha_config(k8s_conf):
    return k8s_conf[consts.K8S_KEY].get(consts.HA_CONFIG_KEY)


def get_node_configs(k8s_conf):
    return k8s_conf[consts.K8S_KEY][consts.NODE_CONF_KEY]


def get_hostname_ips_dict(k8s_conf):
    out = dict()
    node_confs = k8s_conf[consts.K8S_KEY][consts.NODE_CONF_KEY]
    for node_conf in node_confs:
        host_conf = node_conf[consts.HOST_KEY]
        out[host_conf[consts.HOSTNAME_KEY]] = host_conf[consts.IP_KEY]
    return out


def get_host_ips(k8s_conf):
    out = list()
    node_confs = k8s_conf[consts.K8S_KEY][consts.NODE_CONF_KEY]
    for node_conf in node_confs:
        host_conf = node_conf[consts.HOST_KEY]
        out.append(host_conf[consts.IP_KEY])
    return out


def get_hosts(k8s_conf):
    out = list()
    node_confs = k8s_conf[consts.K8S_KEY][consts.NODE_CONF_KEY]
    for node_conf in node_confs:
        host_conf = node_conf[consts.HOST_KEY]
        out.append(host_conf[consts.HOSTNAME_KEY])
    return out


def get_basic_auth(k8s_conf):
    return k8s_conf[consts.K8S_KEY][consts.BASIC_AUTH_KEY]


def get_project_name(k8s_conf):
    return k8s_conf[consts.K8S_KEY][consts.PROJECT_NAME_KEY]


def get_metrics_server(k8s_conf):
    return k8s_conf[consts.K8S_KEY].get(consts.METRICS_SERVER_KEY)


def get_macvlan_nets(k8s_conf):
    return k8s_conf[consts.K8S_KEY].get(consts.NET_IN_MACVLAN_KEY)


def get_docker_repo(k8s_conf):
    return k8s_conf[consts.K8S_KEY].get(consts.DOCKER_REPO_KEY)


def get_git_branch(k8s_conf):
    return k8s_conf[consts.K8S_KEY][consts.GIT_BRANCH_KEY]


def get_persis_vol(k8s_conf):
    return k8s_conf[consts.K8S_KEY][consts.PERSIS_VOL_KEY]


def get_ceph_vol(k8s_conf):
    persist_vol = k8s_conf[consts.K8S_KEY][consts.PERSIS_VOL_KEY]
    return persist_vol.get(consts.CEPH_VOLUME_KEY)


def get_host_vol(k8s_conf):
    persist_vol = k8s_conf[consts.K8S_KEY][consts.PERSIS_VOL_KEY]
    return persist_vol.get(consts.HOST_VOL_KEY)


def get_first_master_host(k8s_conf):
    """
    Returns a tuple 2 where 0 is the hostname and 1 is the IP of the first
    master host found in the config
    # TODO/FIXME - This will probably need to be updated for getting HA working
    :param k8s_conf:
    :return: a tuple 2 hostname, ip of the first master host
    """
    node_confs = get_node_configs(k8s_conf)
    for node_conf in node_confs:
        node = node_conf[consts.HOST_KEY]
        if node[consts.NODE_TYPE_KEY] == 'master':
            return node[consts.HOSTNAME_KEY], node[consts.IP_KEY]


def get_nodes_ip_name_type(k8s_conf):
    """
    Returns a list of tuple 3 where 0 is the hostname and 1 is the IP and 2 is
    the type of all configured hosts
    :param k8s_conf:
    :return: a list of tuple 3 - hostname, ip, type
    """
    out = list()
    node_confs = get_node_configs(k8s_conf)
    for node_conf in node_confs:
        node = node_conf[consts.HOST_KEY]
        out.append((node[consts.HOSTNAME_KEY], node[consts.IP_KEY],
                node[consts.NODE_TYPE_KEY]))
    return out


def get_master_nodes_ip_name_type(k8s_conf):
    """
    Returns a list of tuple 3 where 0 is the hostname and 1 is the IP and 2 is
    the type of all configured master hosts
    :param k8s_conf:
    :return: a list of tuple 3 - hostname, ip, type
    """
    out = list()
    node_tuple_3 = get_nodes_ip_name_type(k8s_conf)
    for hostname, ip, type in node_tuple_3:
        if type == consts.NODE_TYPE_MASTER:
            out.append((hostname, ip, type))
    return out


def get_master_node_ips(k8s_conf):
    """
    Returns a list IP addresses to all configured master hosts
    :param k8s_conf:
    :return: a list IPs
    """
    out = list()
    node_tuple_3 = get_master_nodes_ip_name_type(k8s_conf)
    for hostname, ip, type in node_tuple_3:
        out.append(ip)
    return out


def get_minion_nodes_ip_name_type(k8s_conf):
    """
    Returns a list of tuple 3 where 0 is the hostname and 1 is the IP and 2 is
    the type of all configured minion hosts
    :param k8s_conf:
    :return: a list of tuple 3 - hostname, ip, type
    """
    out = list()
    node_tuple_3 = get_nodes_ip_name_type(k8s_conf)
    for hostname, ip, type in node_tuple_3:
        if type == consts.NODE_TYPE_MINION:
            out.append((hostname, ip, type))
    return out


def get_minion_node_ips(k8s_conf):
    """
    Returns a list IP addresses to all configured minion hosts
    :param k8s_conf:
    :return: a list IPs
    """
    out = list()
    node_tuple_3 = get_minion_nodes_ip_name_type(k8s_conf)
    for hostname, ip, type in node_tuple_3:
        out.append(ip)
    return out
