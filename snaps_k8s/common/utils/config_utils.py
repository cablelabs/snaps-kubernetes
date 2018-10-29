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


def get_default_network(networks):
    for network in networks:
        for key in network:
            if key == "Default_Network":
                default_network = network.get(consts.DFLT_NET_KEY)
                if default_network:
                    return default_network
                    service_subnet = default_network.get(
                        consts.SRVC_SUB_KEY)
                    logger.info("Service subnet = " + service_subnet)
                    pod_subnet = default_network.get(consts.POD_SUB_KEY)
                    logger.info("pod_subnet = " + pod_subnet)
                    networking_plugin = default_network.get(
                        consts.NET_PLUGIN_KEY)
                    logger.info("networking_plugin= " + networking_plugin)


def get_service_subnet(networks):
    default_network = get_default_network(networks)
    if default_network:
        return default_network.get(consts.SRVC_SUB_KEY)

def get_networking_plugin(networks):
    default_network = get_default_network(networks)
    if default_network:
        return default_network.get(consts.NET_PLUGIN_KEY)
