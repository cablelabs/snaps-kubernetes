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

# This script is responsible for deploying Aricent_Iaas environments and
# Kubernetes Services

"""
Constants.py
"""
import os
import pkg_resources

# Dict keys
PROJECT_NAME_KEY = 'Project_name'
ARTIFACT_DIR_KEY = 'artifact_dir'
GIT_BRANCH_KEY = 'Git_branch'
SRVC_SUB_KEY = 'service_subnet'
POD_SUB_KEY = 'pod_subnet'
NET_PLUGIN_KEY = 'networking_plugin'
HOSTNAME_KEY = 'hostname'
REG_PORT_KEY = 'registry_port'
PROXIES_KEY = 'proxies'
HTTP_PROXY_KEY = 'http_proxy'
HTTPS_PROXY_KEY = 'https_proxy'
FTP_PROXY_KEY = 'ftp_proxy'
NO_PROXY_KEY = 'no_proxy'
NODE_CONF_KEY = 'node_configuration'
CEPH_VOLUME_KEY = 'Ceph_Volume'
NODE_TYPE_KEY = 'node_type'
CEPH_CTRL_TYPE = 'ceph_controller'
CEPH_OSD_TYPE = 'ceph_osd'
PERSIS_VOL_KEY = 'Persistent_Volumes'
HOST_KEY = 'host'
CEPH_CLAIMS_KEY = 'Ceph_claims'
NODE_TYPE_MASTER = 'master'
NODE_TYPE_MINION = 'minion'
STORAGE_TYPE_KEY = 'second_storage'
IP_KEY = 'ip'
USER_KEY = 'user'
PASSWORD_KEY = 'password'
TYPE_KEY = 'type'
GATEWAY_KEY = 'gateway'
RANGE_START_KEY = 'rangeStart'
RANGE_END_KEY = 'rangeEnd'
ROUTES_DST_KEY = 'routes_dst'

DPDK_DRIVER = 'vfio-pci'
DPDK_TOOL = '/etc/cni/scripts/dpdk-devbind.py'

ANSIBLE_CONF = '/etc/ansible/ansible.cfg'
ANSIBLE_PKG = 'snaps_k8s.ansible_p.ansible_utils'

# Dict keys
K8S_KEY = 'kubernetes'
HA_CONFIG_KEY = 'ha_configuration'
HA_API_EXT_LB_KEY = 'api_ext_loadbalancer'
ACCESS_SEC_KEY = 'access_and_security'
AUTH_KEY = 'authentication'
BASIC_AUTH_KEY = 'basic_authentication'
TOKEN_AUTH_KEY = 'token_authentication'
USER_PASS_KEY = 'user_password'
USER_ID_KEY = 'user_id'
USER_NAME_KEY = 'user_name'
DOCKER_REPO_KEY = 'Docker_Repo'
HOST_VOL_KEY = 'Host_Volume'
PORT_KEY = 'port'
STORAGE_KEY = 'storage'
CEPH_STORAGE_KEY = 'storage'
CEPH_CLAIM_NAME_KEY = 'claim_name'
CLAIM_NAME_KEY = 'Claim_name'
CLAIM_PARAMS_KEY = 'claim_parameters'
LBL_VAL_KEY = 'label_value'
LABEL_KEY = 'label_key'

KUBESPRAY_FOLDER_NAME = 'kubespray'
PROJ_DIR_NAME = 'snaps-k8s-projects'

# TODO/FIXME - Use node config users
NODE_USER = 'root'

NODE_APT_CONF_DEST = '/etc/apt/apt.conf'
NODE_APT_ARCH_PATH = '/var/cache/apt/archives'
NODE_K8S_PATH = '/etc/kubernetes'
NODE_DOCKER_DAEMON_FILE = '/etc/docker/daemon.json'
NODE_HTTP_PROXY_DEST = '/etc/systemd/system/docker.service.d'

# Misc constants
FLANNEL_TYPE = 'flannel'
MACVLAN_TYPE = 'macvlan'
SRIOV_TYPE = 'sriov'
WEAVE_TYPE = 'weave'
DHCP_TYPE = 'dhcp'
NET_TYPE_LOCAL_TYPE = 'host-local'

# Dict keys
NETWORK_KEY = 'network'
SUBNET_KEY = 'subnet'
MASTER_PLUGIN_KEY = 'isMaster'
NETWORK_NAME_KEY = 'network_name'
METRICS_SERVER_KEY = 'enable_metrics_server'
ENABLE_LOG_KEY = 'enable_logging'
LOG_LEVEL_KEY = 'log_level'
LOG_FILE_PATH = '/var/log/cluster.*.log'
LOG_PORT_KEY = 'logging_port'
NETWORKS_KEY = 'Networks'
DFLT_NET_KEY = 'Default_Network'
MULTUS_NET_KEY = 'Multus_network'
MULTUS_CNI_KEY = 'CNI'
MULTUS_CNI_CONFIG_KEY = 'CNI_Configuration'
CPU_ALLOC_KEY = 'Exclusive_CPU_alloc_support'
FLANNEL_NET_TYPE = 'Flannel'
FLANNEL_NET_DTLS_KEY = 'flannel_network'
WEAVE_NET_TYPE = 'Weave'
WEAVE_NET_DTLS_KEY = 'weave_network'
MACVLAN_NET_TYPE = 'Macvlan'
MACVLAN_NET_DTLS_KEY = 'macvlan_networks'
MACVLAN_PARENT_INTF_KEY = 'parent_interface'
MACVLAN_VLAN_ID_KEY = 'vlanid'
SRIOV_NET_TYPE = 'Sriov'
SRIOV_NETWORKS_KEY = 'networks'
SRIOV_DPDK_ENABLE_KEY = 'dpdk_enable'
SRIOV_INTF_KEY = 'sriov_intf'
SRIOV_GATEWAY_KEY = 'sriov_gateway'
SRIOV_SUBNET_KEY = 'sriov_subnet'

# Consider making the log directory configurable
CWD = os.getcwd()
K8_INSTALLATION_LOGS = '{}/{}'.format(CWD, 'installation_logs.log')

K8_VER_KEY = 'version'

BUILD_ANSIBLE_PKG = 'snaps_k8s.playbooks.build_setup'
K8_ANSIBLE_PKG = 'snaps_k8s.playbooks.k8'

BUILD_PREREQS = pkg_resources.resource_filename(
    BUILD_ANSIBLE_PKG, 'build_prerequisites.yaml')
SETUP_ETC_HOSTS = pkg_resources.resource_filename(
    BUILD_ANSIBLE_PKG, 'setup_etc_hosts.yaml')
MANAGE_KEYS = pkg_resources.resource_filename(
    BUILD_ANSIBLE_PKG, 'manage_keys.yaml')

K8_CLEAN_UP = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_clean_up.yaml')
K8_CLONE_CODE = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_clone_code.yaml')
K8_CLONE_PACKAGES = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_clone_packages.yaml')
K8_REMOVE_FOLDER = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_remove_project_folder.yaml')
K8_REMOVE_NODE_K8 = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_remove_nodes.yaml')
K8_SET_HOSTNAME = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'set_hostname.yaml')
K8_SET_PACKAGES = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'setup_k8.yaml')
K8_CONFIG_DOCKER = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'configure_docker.yaml')
K8_NODE_LABELING = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_node_label.yaml')
K8_CONF_DOCKER_REPO = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'private_docker.yaml')
K8_PRIVATE_DOCKER = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'create_private_docker.yaml')
KUBERNETES_SET_LAUNCHER = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'launcher_setup.yaml')
KUBERNETES_CREATE_INVENTORY = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'inventory_file.yaml')
KUBERNETES_NEW_INVENTORY = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'new_inventory_file.yaml')
KUBERNETES_WEAVE_SCOPE = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_weave_scope.yaml')
KUBERNETES_KUBE_PROXY = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_kube_proxy.yaml')
KUBERNETES_PERSISTENT_VOL = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'persistent_volume.yaml')
KUBERNETES_AUTHENTICATION = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'Authentication.yaml')
ETCD_CHANGES = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'etcd_changes.yaml')
KUBERNETES_USER_LIST = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'user_list.yaml')



KUBERNETES_CEPH_ADD_HOSTS= pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'ceph_add_hosts.yaml')
KUBERNETES_CEPH_INSTALL = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'ceph_install.yaml')
KUBERNETES_PERSISTENT_VOLUME = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'persistent_volume.yaml')






K8_CREATE_CRD_NETWORK = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'crd_network_k8.yaml')
K8_MULTUS_SET_MASTER = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'multus_master_k8.yaml')
K8_MULTUS_SCP_MULTUS_CNI = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'multus_scp_k8.yaml')
K8_MULTUS_SET_NODE = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'multus_node_k8.yaml')
K8_DELETE_FLANNEL_INTERFACE = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'flannel_interface_deletion.yaml')
K8_CONF_FLANNEL_DAEMON_AT_MASTER = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'flannel_daemon_at_master.yaml')
K8_CONF_FLANNEL_INTF_CREATION_AT_MASTER = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'flannel_interface_creation.yaml')
K8_CONF_WEAVE_NETWORK_CREATION = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'weave_network_creation.yaml')
K8_CONF_FILES_DELETION_AFTER_MULTUS = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'weave_conf_deletion.yaml')
K8_SRIOV_CNI_BUILD = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_sriov_build_cni.yaml')
K8_SRIOV_ENABLE = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_sriov_enable.yaml')
K8_SRIOV_CNI_BIN_INST = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_sriov_cni_bin_inst.yaml')
K8_SRIOV_DPDK_CNI = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_sriov_dpdk_cni.yaml')
K8_SRIOV_DPDK_CNI_BIN_INST = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_sriov_dpdk_cni_bin_inst.yaml')
K8_SRIOV_DPDK_DRIVER_LOAD = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_sriov_dpdk_kernel_load.yaml')
K8_SRIOV_CR_NW = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'sriov_network_creation.yaml')
K8_SRIOV_DPDK_CR_NW = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'sriov_dpdk_network_creation.yaml')
K8_SRIOV_DHCP_CR_NW = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'sriov_dhcp_network_creation.yaml')
K8_SRIOV_CONFIG_SCRIPT = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'sriov_configuration.sh')
K8_VLAN_INTERFACE_PATH = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'vlan_tag_interface_creation.yaml')
K8_VLAN_INTERFACE_REMOVAL_PATH = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'vlan_tag_interface_removal.yaml')
K8_MACVLAN_MASTER_NETWORK_PATH = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'macvlan_master_network_creation.yaml')
K8_MACVLAN_NETWORK_PATH = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'macvlan_network_creation.yaml')
K8_MACVLAN_MASTER_NETWORK_DHCP_PATH = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'macvlan_master_network_dhcp_creation.yaml')
K8_MACVLAN_NETWORK_DHCP_PATH = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'macvlan_network_dhcp_creation.yaml')
K8_MACVLAN_NETWORK_REMOVAL_PATH = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'macvlan_network_removal.yaml')
K8_DHCP_PATH = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'dhcp_daemon.yaml')
K8_DHCP_REMOVAL_PATH = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'dhcp_daemon_removal.yaml')
K8_METRICS_SERVER = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'metrics_server_install.yaml')
K8_METRICS_SERVER_CLEAN = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'metrics_server_clean.yaml')
K8_CREATE_DEFAULT_NETWORK = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_create_default_network.yaml')
K8_CONF_COPY_FLANNEL_CNI = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'flannel_cni_copy.yaml')
K8_CONF_COPY_WEAVE_CNI = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'weave_cni_copy.yaml')
K8_DELETE_WEAVE_INTERFACE = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'weave_interface_deletion.yaml')
K8_CREATE_INVENTORY_FILE = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_create_inventory_file.yaml')
K8_CPU_PINNING_CONFIG = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'Configure_CPU_Management_Policy.yaml')
K8_LOGGING_PLAY = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'logging.yaml')
K8_KUBECTL_INSTALLATION = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'kubectl_installation.yaml')
K8_ENABLE_KUBECTL_CONTEXT = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'enable_kubectl_context.yaml')
K8_DOCKER_CLEAN_UP_ON_NODES = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_docker_clean_up.yaml')
K8_HA_EXT_LB = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_ha_external_load_balancer_install.yaml')
K8_HA_KUBESPRAY_CONFIGURE = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_ha_kubespray_configure.yaml')
K8_HA_EXT_LB_MULTI_CLUSTER = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_ha_multicluster_loadbalancer_configure.yaml')

KUBESPRAY_PB_REL_LOC = 'kubespray/cluster.yml'
