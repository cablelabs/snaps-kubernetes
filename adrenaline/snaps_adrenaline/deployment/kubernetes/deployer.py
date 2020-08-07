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

from snaps_adrenaline.deployment import config_utils
from snaps_k8s.common.utils import config_utils as k8s_config_utils
from snaps_common.ansible_snaps import ansible_utils
from snaps_k8s.provision import k8_utils

from snaps_adrenaline.playbooks import consts

logger = logging.getLogger('snaps_k8s_deployer')


def deploy(k8s_conf, user):
    """
    Installs and configures a Kubernetes cluster
    :param k8s_conf: the k8s configuration dict
    :param user: the sudo user used to apply the playbook
    :raises: Exception should snaps-kubernetes fail to deploy successfully
    """
    logger.info('Setting up k8s cluster')
    __pre_install(k8s_conf, user)
    k8_utils.execute(k8s_conf)
    __post_install(k8s_conf, user)
    logger.info('Completed setting up k8s')


def __pre_install(k8s_conf, user):
    """
    Temporary fix to ensure apt works on properly as we have encountered issues
    with /etc/resolv.conf DNS setting getting removed after the node has been
    rebooted
    :param k8s_conf: the snaps-kubernetes dict
    :param user: the sudo user used to apply the playbook
    :raises: Exception should the ansible playbook fail to execute successfully
    """
    node_ips = k8s_config_utils.get_minion_node_ips(k8s_conf)
    ansible_utils.apply_playbook(
        consts.TEMP_NODE_SETUP_PB, node_ips, user)


def __post_install(k8s_conf, user):
    """
    Hardware setup Kubernetes cluster
    :param k8s_conf: the snaps-kubernetes dict
    :param user: the sudo user used to apply the playbook
    :raises: Exception should snaps-kubernetes fail to deploy successfully
    """
    logger.debug('Setting up k8s hardware plugins')
    __install_nvidia_docker(k8s_conf, user)
    __install_k8s_hw_specs(k8s_conf, 'fpga')
    __install_k8s_hw_specs(k8s_conf, 'gpu')
    __install_kubevirt(k8s_conf, user)
    __install_ovs_dpdk(k8s_conf, user)
    __install_prometheus(k8s_conf)
    __install_grafana(k8s_conf)
    __install_dcgm_exporter(k8s_conf)

def __install_nvidia_docker(k8s_conf, user):
    """
    Install nvidia-docker so containers can access NVIDIA GPUs
    :param user: the sudo user used to apply the playbook
    :raises: Exception should snaps-kubernetes fail to deploy successfully
    """
    logger.debug('Installing nvidia-docker')
    node_ips = k8s_config_utils.get_minion_node_ips(k8s_conf)
    ansible_utils.apply_playbook(
        consts.SETUP_NVIDIA_DOCKER_PB, node_ips, user,
        variables={'DAEMON_JSON_FILE': consts.NVIDIA_DOCKER_CONF})


def __install_k8s_hw_specs(k8s_conf, hw_type):
    """
    Install nvidia k8s plugin so k8s pods can access NVIDIA GPUs
    :param k8s_conf: the snaps-kubernetes configuration dict
    :param hw_type: the type of HW to install
    :raises: Exception should snaps-kubernetes fail to deploy successfully
    """
    logger.debug('Installing k8s [%s] plugin', hw_type)

    k8s_version = config_utils.get_k8s_version(k8s_conf, True)
    spec_url = None
    if hw_type == 'gpu':
        spec_url = consts.GPU_K8S_SPEC_URL
    elif hw_type == 'fpga':
        spec_url = consts.FPGA_K8S_SPEC_URL

    if spec_url and k8s_version.startswith('1.15'):
        logger.info('Installing k8s hardware plugin')
        pb_vars = {
            'K8S_VERSION': config_utils.get_k8s_version(k8s_conf, True),
            'K8S_PROJ_DIR': k8s_config_utils.get_project_artifact_dir(
                k8s_conf),
            'K8S_SPEC_URL': spec_url,
            'type': hw_type,
            'http_proxy': k8s_config_utils.get_proxy_dict(
                k8s_conf)['http_proxy'],
            'https_proxy': k8s_config_utils.get_proxy_dict(
                k8s_conf)['http_proxy']
        }
        ansible_utils.apply_playbook(
            consts.SETUP_K8S_HW_PLUGIN_PB, variables=pb_vars)
    else:
        logger.info('No reason to install hardware plugins. K8s version %s',
                    k8s_version)


def __install_kubevirt(k8s_conf,user):
    """
    Installs kubevirt in the cluster nodes.
    """
    logger.debug('__install_kubevirt')
    kubevirt = config_utils.get_kubevirt_cfg(k8s_conf)
    if kubevirt == 'true':
        master_ip = config_utils.get_master_ip(k8s_conf)
        pb_vars = {
           'KUBEVIRT_VER': consts.KUBEVIRT_VERSION,
           'KUBEVIRT_URL': consts.KUBEVIRT_URL
        }
        ansible_utils.apply_playbook(consts.SETUP_KUBEVIRT_PB,
                      master_ip, user, variables=pb_vars)
    else:
        logger.info('No reason to Setup Kubevirt')

def __install_ovs_dpdk(k8s_conf,user):
    """
    Installs OVS DPDK
    """
    logger.debug('__install_ovs_dpdk')
    ovs_dpdk = config_utils.get_ovs_dpdk_cfg(k8s_conf)
    if ovs_dpdk == 'true':
        pb_vars = {
           'K8S_PROJ_DIR': k8s_config_utils.get_project_artifact_dir(
                k8s_conf),
           'MULTUS_CNI_FILE': consts.MULTUS_CNI_FILE
        }
        ansible_utils.apply_playbook(consts.SETUP_OVS_DPDK_MULTUS_PB,
                      variables=pb_vars)

        node_ips = k8s_config_utils.get_minion_node_ips(k8s_conf)
        pb_vars = {
           'GO_URL': consts.GO_URL,
           'CNI_URL': consts.CNI_URL
        }
        ansible_utils.apply_playbook(consts.SETUP_OVS_DPDK_USERSPACE_CNI_PB,
                      node_ips, user, variables=pb_vars)

        pb_vars = {
           'K8S_PROJ_DIR': k8s_config_utils.get_project_artifact_dir(
                k8s_conf),
           'USCNI_K8S_ATTACH_FILE': consts.USCNI_K8S_ATTACH_FILE
        }
        ansible_utils.apply_playbook(consts.SETUP_USCNI_K8S_ATTACH_PB,
                      variables=pb_vars)

    else:
        logger.info('No reason to Setup OVS DPDK')


def __install_prometheus(k8s_conf):
    """
    Installs prometheus
    """
    logger.debug('__install_prometheus')
    enable_prometheus = config_utils.get_prometheus_cfg(k8s_conf)
    master_ip = config_utils.get_master_ip(k8s_conf)

    k8s_version = config_utils.get_k8s_version(k8s_conf, True)

    if enable_prometheus == 'true' and k8s_version.startswith('1.15'):
        pb_vars = {
            'K8S_PROJ_DIR': k8s_config_utils.get_project_artifact_dir(
                k8s_conf),
            'PROMETHEUS_K8S_ATTACH_FILE': consts.PROMETHEUS_K8S_ATTACH_FILE
        }
        ansible_utils.apply_playbook(consts.SETUP_PROMETHEUS_PB, master_ip,
                                     variables=pb_vars)
    elif enable_prometheus == 'true' and k8s_version.startswith('1.16'):
        pb_vars = {
            'K8S_PROJ_DIR': k8s_config_utils.get_project_artifact_dir(
                k8s_conf),
            'PROMETHEUS_K8S_ATTACH_FILE': consts.PROMETHEUS_K8S_v_1_16_ATTACH_FILE
        }
        ansible_utils.apply_playbook(consts.SETUP_PROMETHEUS_PB, master_ip,
                                     variables=pb_vars)
    else:
        logger.info('No reason to Setup Prometheus')


def __install_grafana(k8s_conf):
    """
    Installs Grafana
    """
    logger.debug('__install_grafana')
    enable_grafana = config_utils.get_grafana_cfg(k8s_conf)
    master_ip = config_utils.get_master_ip(k8s_conf)
    import yaml
    with open('snaps_adrenaline.playbooks.kubernetes.dcgm_config.yaml', 'rU') as f:
        data = yaml.safe_load(f)

    data['subsets']['addresses']['ip'] = master_ip

    with open('snaps_adrenaline.playbooks.kubernetes.dcgm_config.yaml', 'w') as f:
        yaml.dump(data, f)
    if enable_grafana == 'true':
        pb_vars = {
            'K8S_PROJ_DIR': k8s_config_utils.get_project_artifact_dir(
                k8s_conf),
            'GRAFANA_K8S_ATTACH_FILE': consts.GRAFANA_K8S_ATTACH_FILE
        }
        ansible_utils.apply_playbook(consts.SETUP_GRAFANA_PB, master_ip,
                                     variables=pb_vars)
    else:
        logger.info('No reason to Setup Prometheus')


def __install_dcgm_exporter(k8s_conf):
    """
    Installs dcgm exporter
    """
    logger.debug('__install_dcgm_exporter')
    enable_dcgm = config_utils.get_dcgm_cfg(k8s_conf)
    master_ip = config_utils.get_master_ip(k8s_conf)
    if enable_dcgm == 'true':
        pb_vars = {
            'K8S_PROJ_DIR': k8s_config_utils.get_project_artifact_dir(
                k8s_conf),
            'DCGM_K8S_ATTACH_FILE': consts.DCGM_K8S_ATTACH_FILE,
            'NODE_IP': master_ip
        }
        ansible_utils.apply_playbook(consts.SETUP_DCGM_PB, master_ip,
                                     variables=pb_vars)
    else:
        logger.info('No reason to Setup dcgm exporter')


def undeploy(k8s_conf):
    """
    Cleans up the PXE imaged machines
    :raises: Exception should snaps-kubernetes fail to undeploy successfully
    """
    k8_utils.clean_k8(k8s_conf)
