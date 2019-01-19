# Copyright (c) 2019 Cable Television Laboratories, Inc. ("CableLabs")
#                    and others.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import logging
from kubernetes import client, config
from snaps_k8s.common.consts import consts
from snaps_k8s.common.utils import config_utils

__author__ = 'spisarski'

logger = logging.getLogger('validate_deployment')


def k8s_client(k8s_conf):
    """
    Retrieves the kubernetes client
    :param k8s_conf: the k8s configuration used to deploy the cluster
    :return:
    """
    config.load_kube_config("{}/node-kubeconfig.yaml".format(
        config_utils.get_project_artifact_dir(k8s_conf)))
    return client.CoreV1Api()


def validate_all(k8s_conf):
    """
    Uses ansible_utils for applying Ansible Playbooks to machines with a
    private key
    :param k8s_conf: the k8s configuration used to deploy the cluster
    """
    config.load_kube_config("{}/node-kubeconfig.yaml".format(
        config_utils.get_project_artifact_dir(k8s_conf)))
    cluster_client = k8s_client(k8s_conf)

    logger.info('Starting K8S Validation')
    validate_nodes(k8s_conf, cluster_client)
    validate_k8s_system(k8s_conf, cluster_client)
    validate_cni(k8s_conf, cluster_client)
    validate_volumes(k8s_conf, cluster_client)


def validate_nodes(k8s_conf, cluster_client):
    """
    Validation of the configured kubernetes nodes
    :param k8s_conf: the k8s configuration used to deploy the cluster
    :param cluster_client: the k8s API client
    :raises Exception
    """
    logger.info('Validate K8 Nodes')

    node_list = cluster_client.list_node()
    node_items = node_list.items

    masters_tuple3 = config_utils.get_master_nodes_ip_name_type(k8s_conf)
    master_names = list()
    for name, ip, node_type in masters_tuple3:
        master_names.append(name)

    minions_tuple3 = config_utils.get_minion_nodes_ip_name_type(k8s_conf)
    minion_names = list()
    for name, ip, node_type in minions_tuple3:
        minion_names.append(name)

    master_count = 0
    minion_count = 0
    for node_item in node_items:
        node_meta = node_item.metadata
        node_status = node_item.status
        node_info = node_status.node_info
        node_kubelet_version = node_info.kubelet_version
        expected_version = config_utils.get_version(k8s_conf)
        assert node_kubelet_version == expected_version
        logger.info('Expected version [%s] == actual [%s]',
                    expected_version, node_kubelet_version)

        node_name = node_meta.name
        node_labels = node_meta.labels
        if node_labels.get('node-role.kubernetes.io/master') is not None:
            assert node_name in master_names
            master_count += 1
            logger.info('Master found with name [%s]', node_name)

        if node_labels.get('node-role.kubernetes.io/node') is not None:
            assert node_name in minion_names
            minion_count += 1
            logger.info('Minion found with name [%s]', node_name)

    assert master_count == len(masters_tuple3)
    logger.info('Number of masters [%s]', master_count)
    assert minion_count == len(minions_tuple3)
    logger.info('Number of minions [%s]', minion_count)


def validate_k8s_system(k8s_conf, cluster_client):
    """
    Validation of the configured kubernetes system
    :param k8s_conf: the k8s configuration used to deploy the cluster
    :param cluster_client: the k8s API client
    :raises Exception
    """
    logger.info('Validate K8s System')

    pod_items = __get_pods_by_namespace(cluster_client, 'kube-system')

    pod_names = __get_pod_names(pod_items)
    logger.info('pod_names - %s', pod_names)

    pod_services = __get_pod_service_list(pod_items)
    logger.info('pod_services - %s', pod_services)
    assert 'dns-autoscaler' in pod_services
    assert 'kube-proxy' in pod_services
    assert 'kubernetes-dashboard' in pod_services
    assert 'coredns' in pod_services

    if config_utils.is_metrics_server_enabled(k8s_conf):
        assert 'metrics-server' in pod_services
    else:
        assert 'metrics-server' not in pod_services


def validate_cni(k8s_conf, cluster_client):
    """
    Validation of the configured kubernetes CNIs and network elements
    :param k8s_conf: the k8s configuration used to deploy the cluster
    :param cluster_client: the k8s API client
    :raises Exception
    """
    logger.info('Validate K8s CNIs')

    pod_items = __get_pods_by_namespace(cluster_client, 'kube-system')
    pod_services = __get_pod_service_list(pod_items)
    net_plugin = config_utils.get_networking_plugin(k8s_conf)
    if net_plugin == consts.WEAVE_TYPE:
        assert 'weave-net' in pod_services
    elif net_plugin == consts.FLANNEL_TYPE:
        assert 'flannel-net' in pod_services
    elif net_plugin == 'contiv':
        assert 'contiv-net' in pod_services
    elif net_plugin == 'calico':
        assert 'calico-net' in pod_services
    elif net_plugin == 'cilium':
        assert 'cilium-net' in pod_services


def validate_volumes(k8s_conf, cluster_client):
    """
    Validation of the configured kubernetes volumes
    :param k8s_conf: the k8s configuration used to deploy the cluster
    :param cluster_client: the k8s API client
    :raises Exception
    """
    logger.info('Validate K8s Volumes')
    pass


def __get_pods_by_namespace(cluster_client, namespace):
    """
    Retrieves the pods for a given namespace
    :param cluster_client: the kubernetes API client
    :param namespace: the namespace of the pod to add into the return list
    :return: list of pod item objects
    """
    out_pods = list()

    pod_list = cluster_client.list_pod_for_all_namespaces()
    pod_items = pod_list.items

    for pod_item in pod_items:
        pod_meta = pod_item.metadata
        # logger.info('metadata - %s', pod_item.metadata)
        if pod_meta.namespace == namespace:
            out_pods.append(pod_item)

    return out_pods


def __get_pod_names(pod_items):
    """
    Returns a list of pod names extracted from the pod_list parameter
    :param pod_items: the list of pod_items from which to extract the name
    :return: list of pod names
    """
    out_names = list()
    for pod_item in pod_items:
        out_names.append(pod_item.metadata.name)
    return out_names


def __get_pod_service_list(pod_items):
    """
    Returns a set of pod service_account names from the pod_list parameter
    :param pod_items: the list of pod_items from which to extract the name
    :return: set of pod names
    """
    out_names = set()
    for pod_item in pod_items:
        if pod_item.spec.service_account:
            out_names.add(pod_item.spec.service_account)
        else:
            logger.info('service_account not found for pod with name - %s',
                        pod_item.metadata.name)
    return out_names
