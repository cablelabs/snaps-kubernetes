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


def get_multus_cni_cfg(k8s_conf):
    return get_multus_elems(k8s_conf, consts.MULTUS_CNI_CONFIG_KEY)


def get_multus_weave_details(k8s_conf):
    multus_elems = get_multus_elems(k8s_conf, consts.MULTUS_CNI_CONFIG_KEY)
    for multus_elem in multus_elems:
        if consts.WEAVE_NET_TYPE in multus_elem:
            return multus_elem[consts.WEAVE_NET_TYPE]


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
