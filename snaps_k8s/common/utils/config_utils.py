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


logger = logging.getLogger('config_utils')


def get_proxy_dict(k8s_conf):
    return k8s_conf.get(consts.K8S_KEY).get(consts.PROXIES_KEY)


def get_default_network(networks):
    for network in networks:
        for key in network:
            if key == "Default_Network":
                default_network = network.get(consts.DFLT_NET_KEY)
                if default_network:
                    return default_network


def get_service_subnet(networks):
    default_network = get_default_network(networks)
    if default_network:
        return default_network.get(consts.SRVC_SUB_KEY)


def get_networking_plugin(networks):
    default_network = get_default_network(networks)
    if default_network:
        return default_network.get(consts.NET_PLUGIN_KEY)


def get_version(k8s_conf):
    return k8s_conf[consts.K8S_KEY][consts.K8_VER_KEY]


def get_ha_config(k8s_conf):
    return k8s_conf[consts.K8S_KEY].get(consts.HA_CONFIG_KEY)