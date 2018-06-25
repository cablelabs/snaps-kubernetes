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
import pkg_resources
from pathlib import Path

p = str(Path(__file__).parents[2])
CWD = "{}/".format(p)
CWD1 = "{}/".format(str(Path(__file__).parents[3]))

ANSIBLE_PATH = CWD + "ansible_p/"
DEPLOYMENT_TYPE = "deployement_type"
PROJECT_NAME = "Project_name"
PROJECT_PATH = "PROJECT_PATH"
GIT_BRANCH = "Git_branch"
SERVICE_SUBNET = "service_subnet"
POD_SUBNET = "pod_subnet"
NETWORKING_PLUGIN = "networking_plugin"
HOSTNAME = "hostname"
PROXIES = "proxies"
HTTP_PROXY = "http_proxy"
HTTPS_PROXY = "https_proxy"
FTP_PROXY = "ftp_proxy"
NO_PROXY = "no_proxy"
HOSTS = "node_configuration"
CEPH_VOLUME = "Ceph_Volume"
PERSISTENT_VOLUME = "Persistent_Volumes"

HOST = "host"
CEPH_CLAIMS = "Ceph_claims"
NODE_TYPE = "node_type"
STORAGE_TYPE = "second_storage"
IP = "ip"
TYPE = "type"
SERVICE_PASSWORD = "service_password"
SERVICE_HOST = "service_host"
HOST_NAME = "hostname"
NAME = "name"
USER = "user"
PASSWORD = "password"
ANSIBLE_HOSTS_FILE = "/etc/ansible/hosts"
HOSTS_FILE = "/etc/hosts"
ANSIBLE_CONF = "/etc/ansible/ansible.cfg"
SSH_PATH = "/root/.ssh"

ANSIBLE_PKG = 'snaps_k8s.ansible_p.ansible_utils'
PROXY_DATA_FILE = pkg_resources.resource_filename(
    ANSIBLE_PKG, 'proxy_data.yaml')
VARIABLE_FILE = pkg_resources.resource_filename(
    ANSIBLE_PKG, 'variable.yaml')

PROXY_PATH = CWD+"ansible_p/ansible_utils/proxy_data.yaml"
COUNT = "count"
KUBERNETES = "kubernetes"
HA_CONFIG = "ha_configuration"
HA_API_EXT_LB = "api_ext_loadbalancer"
BASIC_AUTHENTICATION = "basic_authentication"
ETCD_CHANGES = "etcd_changes"
USER_PASSWORD = "user_password"
USER_ID = "user_id"
USER_NAME = "user_name"
DOCKER_REPO = "Docker_Repo"
HOST_VOL = "Host_Volume"
PORT = "port"
STORAGE = "storage"
CEPH_STORAGE = "storage"
CLAIM_NAME = "Claim_name"
CEPH_CLAIM_NAME = "claim_name"
CLAIM_PARAMETERS = "claim_parameters"
CEPH_NODE_IP = "ceph_node_ip"
KUBESPRAY_PATH = "KUBESPRAY_PATH"
ENABLE_ISTIO = "enable_istio"
ENABLE_AMBASSADOR = "enable_ambassador"
AMBASSADOR_RBAC = "ambassador_rbac"
LABEL_VALUE = "label_value"
LABEL_KEY = "label_key"

""" Folder Paths *****************"""
K8_PACKAGE_PATH = CWD
K8_SOURCE_PATH = CWD + "packages/source/"
INVENTORY_SOURCE_FOLDER = K8_SOURCE_PATH + "inventory/"
APT_ARCHIVES_PATH = "/var/cache/apt/archives/"
MULTUS_CNI = "multus_cni"
ADDITIONAL_NW_PLUGINS = "additionalNetworkPlugins"
FLANNEL = "flannel"
WEAVE = "weave"
CALICO = "calico"
CONTIV = "contiv"
SRIOV_CNI = "sriov_cni"
SRIOV_INTF = "sriov_intf"
SRIOV_MAC = "sriov_mac"
SRIOV_ST_RNG = "sriov_st_rng"
SRIOV_EN_RNG = "sriov_en_rng"
SRIOV_SUBNET = "sriov_subnet"
SRIOV_GETWAY = "sriov_gtwy"
NO_OF_INTF_IN_FLANNEL = "noOfInteracesInFlannel"
FLANNEL_NETWORK = "networkCreationInFlannel"
INTERFACE = "interface"
NETWORK = "network"
SUBNET_LEN = "subnetLen"
SUBNET_MIN = "subnetMin"
SUBNET_MAX = "subnetMax"
VNI = "vni"
MACVLAN = "MACVLAN"
NO_OF_INTERFACES_IN_MACVLAN = "noOfInteracesInMacvlan"
MACVLAN_INTERFACES = "macvlan_interface"
PARENT_INTERFACE = "parent interface"
VLAN_ID = "vlanid"
NETWORK_CREATION_IN_MACVLAN = "Networks"
MACVLAN_NETWORKS = "macvlan_networks"
MASTER = "master"
IP = "ip"
HOSTNAME = "hostname"
SUBNET = "subnet"
RANGE_START = "rangeStart"
RANGE_END = "rangeEnd"
ROUTES_DST = "routes_dst"
GATEWAY = "gateway"
MASTER_PLUGIN = "isMaster"
NETWORK_NAME = "network_name"
METRICS_SERVER = "enable_metrics_server"
ENABLE_LOGGING = "enable_logging"
LOG_LEVEL = "log_level"
LOG_FILE_PATH = "/var/log/cluster.*.log"
LOGGING_PORT = "logging_port"
NETWORKS = "Networks"
DEFAULT_NETWORK = "Default_Network"
NETWORKING_PLUGIN = "networking_plugin"
SERVICE_SUBNET = "service_subnet"
BKUP_DEPLOYMENT_FILE = "deployment_bkup.yaml"
CPU_ALLOCATION_SUPPORT = "Exclusive_CPU_alloc_support"
HTTP_PROXY_SRC = K8_SOURCE_PATH+"http-proxy_bak.conf"
INVENTORY_SRC = K8_SOURCE_PATH+"inventory"
SSH_PATH = "/root/.ssh"
FLANNEL_NETWORK = "Flannel"
FLANNEL_NETWORK_DETAILS = "flannel_network"
WEAVE_NETWORK = "Weave"
WEAVE_NETWORK_DETAILS = "weave_network"
K8_INSTALLATION_LOGS = CWD + "installation_logs.log"

K8_YAML = ANSIBLE_PATH+"commission/kubernetes/playbooks/deploy_mode/k8/"
K8_ANSIBLE_PKG = 'snaps_k8s.ansible_p.commission.kubernetes.playbooks.deploy_mode.k8'

K8_CLEAN_UP = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_clean_up.yaml')
K8_CLONE_CODE = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_clone_code.yaml')
K8_CLONE_PACKAGES = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_clone_packages.yaml')
K8_REMOVE_FOLDER = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_remove_project_folder.yaml')
K8_LAUNCHER_PROXY = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_launcher_proxy.yaml')
K8_REMOVE_NODE_K8 = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_remove_nodes.yaml')
K8_DELETE_NODE = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_delete_node.yaml')
K8_CLEAN_UP_NODES = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_dynamic_clean.yaml')
K8_CLEAN_NODES = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_dynamic_clean_node.yaml')
K8_DEPLOY_NODES = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_dynamic_deploy.yaml')
K8_SET_PACKAGES = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'setup_k8.yaml')
K8_NODE_LABELING = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_node_label.yaml')
K8_CONF_DOCKER_REPO = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'private_docker.yaml')
K8_DYNAMIC_DOCKER_CONF = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'dynamic_docker_conf.yaml')
K8_PRIVATE_DOCKER = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'create_private_docker.yaml')
KUBERNETES_SET_LAUNCHER = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'launcher_setup.yaml')
KUBERNETES_CREATE_INVENTORY = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'inventory_file.yaml')
KUBERNETES_ADD_NODE_INVENTORY = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'add_node_inventory_file.yaml')
KUBERNETES_NEW_INVENTORY = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'new_inventory_file.yaml')
KUBERNETES_NODE_INVENTORY = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'node_inventory_file.yaml')
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
KUBERNETES_CEPH_VOL = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'ceph_volume_final.yaml')
KUBERNETES_CEPH_STORAGE = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'ceph_volume_storage_type_final.yaml')
KUBERNETES_CEPH_VOL2 = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'ceph_volume2_final.yaml')
KUBERNETES_CEPH_VOL_FIRST = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'ceph_volume_final2.yaml')
KUBERNETES_CEPH_DELETE_SECRET = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'ceph_delete_secret.yaml')
UNINSTALL_ISTIO = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'uninstall_istio.yaml')
UNINSTALL_AMBASSADOR = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'uninstall_ambassador.yaml')
SETUP_ISTIO = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'setup_istio.yaml')
CEPH_DEPLOY = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'ceph_deploy.yaml')
CEPH_MDS = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'ceph_mds.yaml')
CEPH_DEPLOY_ADMIN = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'ceph_deploy_admin.yaml')
CEPH_MON = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'ceph_mon.yaml')
SETUP_AMBASSADOR = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'setup_ambassador.yaml')
K8_COPY_KEY = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'copy_key_gen.yaml')
K8_PUSH_KEY = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'push_key_gen.yaml')
K8_CREATE_CRD_NETWORK = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'crd_network_k8.yaml')
K8_MULTUS_SET_MASTER = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'multus_master_k8.yaml')
K8_MULTUS_SCP_MULTUS_CNI = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'multus_scp_k8.yaml')
K8_MULTUS_SET_NODE = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'multus_node_k8.yaml')
K8_MULTUS_SCP_MULTUS_CNI_DYNAMIC_NODE = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'multus_scp_dynamic_node_k8.yaml')
K8_MULTUS_SET_DYNAMIC_NODE = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'multus_dynamic_node_k8.yaml')
K8_CONF_FLANNEL_INTERFACE_AT_MASTER = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'flannel_intf_master.yaml')
K8_CONF_FLANNEL_INTERFACE_AT_NODE = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'flannel_intf_node.yaml')
K8_CONF_FLANNEL_NETWORK_CREATION = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'flannel_network_creation.yaml')
K8_CONF_FLANNEL_INTERFACE_AT_MASTER_FOR_DYNAMIC_NODE = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'flannel_intf_master_dynamic_node.yaml')
K8_CONF_FLANNEL_INTERFACE_AT_DYNAMIC_NODE = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'flannel_intf_dynamic_node.yaml')
K8_DELETE_FLANNEL_INTERFACE = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'flannel_interface_deletion.yaml')
K8_DELETE_FLANNEL_INTERFACE_DYNAMIC_NODE = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'flannel_interface_deletion_dynamic_node.yaml')
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
K8_SRIOV_CONF = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'sriov_conf.yaml')
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
K8_METRRICS_SERVER = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'metrics_server_install.yaml')
K8_METRRICS_SERVER_CLEAN = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'metrics_server_clean.yaml')
K8_CONF_FILES_DELETION_DYNAMIC_CODE = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_delete_conf_files_dynamic_node.yaml')
K8_CREATE_DEFAULT_NETWORK = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_create_default_network.yaml')
K8_SRIOV_CLEAN_RC_LOCAL = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'sriov_rc_local_clean.yaml')
K8_CONF_COPY_FLANNEL_CNI = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'flannel_cni_copy.yaml')
K8_CONF_COPY_WEAVE_CNI = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'weave_cni_copy.yaml')
K8_DELETE_WEAVE_INTERFACE = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'weave_interface_deletion.yaml')
K8_DELETE_WEAVE_INTERFACE_DYNAMIC_NODE = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'weave_interface_deletion_dynamic_node.yaml')
K8_WEAVE_RECLAIM_NODE_IP = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'weave_reclaim_node_ip.yaml')
K8_WEAVE_FORGET_NODE_IP = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'weave_forget_node_ip.yaml')
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
K8_DHCP_DAEMON_INSTALLATION = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'dhcp_daemon_network.yaml')
K8_DHCP_DAEMON_REMOVAL = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'dhcp_daemon_removal_network.yaml')
K8_SRIOV_NETWORK_DELETION = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'sriov_network_deletion.yaml')
K8_DOCKER_CLEAN_UP_ON_NODES = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_docker_clean_up.yaml')
