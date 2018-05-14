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

CWD= p + "/"
print("CWD_IAAS path is exported implicitly")
print(CWD)
DEPLOYMENT_TYPE="deployement_type"
PROJECT_NAME="Project_name"
PROJECT_PATH="PROJECT_PATH"
GIT_BRANCH="Git_branch"
SERVICE_SUBNET="service_subnet"
POD_SUBNET="pod_subnet"
NETWORKING_PLUGIN="networking_plugin"
HOST_NAME="hostname"
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
HOSTNAME = "hostname"
NAME="name"
USER="user"
PASSWORD="password"
ANSIBLE_HOSTS_FILE="/etc/ansible/hosts"
HOSTS_FILE="/etc/hosts"
ANSIBLE_CONF="/etc/ansible/ansible.cfg"
SSH_PATH="/root/.ssh"

ANSIBLE_PKG = 'snaps_k8s.ansible_p.ansible_utils'
PROXY_DATA_FILE = pkg_resources.resource_filename(
    ANSIBLE_PKG, 'proxy_data.yaml')
VARIABLE_FILE = pkg_resources.resource_filename(
    ANSIBLE_PKG, 'variable.yaml')

COUNT="count"
KUBERNETES="kubernetes"
BASIC_AUTHENTICATION="basic_authentication"
ETCD_CHANGES="etcd_changes"
USER_PASSWORD="user_password"
USER_ID="user_id"
USER_NAME="user_name"
DOCKER_REPO="Docker_Repo"
HOST_VOL="Host_Volume"
PORT="port"
STORAGE="storage"
CEPH_STORAGE="storage"
CLAIM_NAME="Claim_name"
CEPH_CLAIM_NAME="claim_name"
CLAIM_PARAMETERS="claim_parameteres"
CEPH_NODE_IP="ceph_node_ip"
KUBESPRAY_PATH="KUBESPRAY_PATH"
ENABLE_ISTIO="enable_istio"
ENABLE_AMBASSADOR="enable_ambassador"
AMBASSADOR_RBAC="ambassador_rbac"
LABEL_VALUE="label_value"
LABEL_KEY="label_key"
""" Folder Paths *****************"""
K8_SOURCE_PATH=CWD+"packages/source/"
INVENTORY_SOURCE_FOLDER=K8_SOURCE_PATH+"inventory/"
APT_ARCHIVES_PATH="/var/cache/apt/archives/"
MULTUS_CNI="multus_cni"
ADDITIONAL_NW_PLUGINS="additionalNetworkPlugins"
FLANNEL="flannel"
WEAVE="weave"
CALICO="calico"
CONTIV="contiv"
SRIOV_CNI="sriov_cni"
SRIOV_INTF="sriov_intf"
SRIOV_MAC="sriov_mac"
SRIOV_ST_RNG="sriov_st_rng"
SRIOV_EN_RNG="sriov_en_rng"
SRIOV_SUBNET="sriov_subnet"
SRIOV_GETWAY="sriov_gtwy"
NO_OF_INTF_IN_FLANNEL="noOfInteracesInFlannel"
FLANNEL_NETWORK="networkCreationInFlannel"
INTERFACE="interface"
NETWORK="network"
SUBNET_LEN="subnetLen"
SUBNET_MIN="subnetMin"
SUBNET_MAX="subnetMax"
VNI="vni"
MACVLAN="MACVLAN"
NO_OF_INTERFACES_IN_MACVLAN="noOfInteracesInMacvlan"
MACVLAN_INTERFACES="macvlan_interface"
PARENT_INTERFACE="parent interface"
VLAN_ID="vlanid"
HOSTNAME="hostname"
IP="ip"
NETWORK_CREATION_IN_MACVLAN="Networks"
MACVLAN_NETWORKS="macvlan_networks"
HOSTNAME="hostname"
MASTER_PLUGIN="masterplugin"
NETWORK_NAME="network name"
MASTER="master"
SUBNET="subnet"
RANGE_START="rangeStart"
RANGE_END="rangeEnd"
ROUTES_DST="routes_dst"
GATEWAY="gateway"
METRICS_SERVER="enable_metrics_server"#added  by yashwant

PROXY_DATA_FILE = pkg_resources.resource_filename(
    ANSIBLE_PKG, 'proxy_data.yaml')
VARIABLE_FILE = pkg_resources.resource_filename(
    ANSIBLE_PKG, 'variable.yaml')

K8_INVENTORY_CFG = pkg_resources.resource_filename(
    'snaps_k8s.packages.source.inventory', 'inventory.cfg'
)

K8_ANSIBLE_PKG = 'snaps_k8s.ansible_p.commission.kubernetes.playbooks.deploy_mode.k8'

K8_CLEAN_UP = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'k8_clean_up.yaml')
K8_REMOVE_FOLDER = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'k8_remove_project_folder.yaml')
K8_LAUNCHER_PROXY = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'k8_launcher_proxy.yaml')
K8_REMOVE_NODE_K8 = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'k8_remove_nodes.yaml')
K8_DELETE_NODE = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'k8_delete_node.yaml')
K8_CLEAN_UP_NODES = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'k8_dynamic_clean.yaml')
K8_CLEAN_NODES = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'k8_dynamic_clean_node.yaml')
K8_DEPLOY_NODES = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'k8_dynamic_deploy.yaml')
K8_SET_PACKAGES = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'setup_k8.yaml')
K8_NODE_LABELING = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'k8_node_label.yaml')
K8_CONF_DOCKER_REPO = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'private_docker.yaml')
K8_DYNAMIC_DOCKER_CONF = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'dynamic_docker_conf.yaml')
K8_PRIVATE_DOCKER = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'create_private_docker.yaml')
KUBERNETES_SET_LAUNCHER = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'launcher_setup.yaml')
KUBERNETES_CREATE_INVENTORY = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'inventory_file.yaml')
KUBERNETES_ADD_NODE_INVENTORY = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'add_node_inventory_file.yaml')
KUBERNETES_NEW_INVENTORY = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'new_inventory_file.yaml')
KUBERNETES_NODE_INVENTORY = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'node_inventory_file.yaml')
KUBERNETES_WEAVE_SCOPE = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'k8_weave_scope.yaml')
KUBERNETES_KUBE_PROXY = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'k8_kube_proxy.yaml')
KUBERNETES_PERSISTENT_VOL = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'persistent_volume.yaml')
KUBERNETES_AUTHENTICATION = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'Authentication.yaml')
ETCD_CHANGES = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'etcd_changes.yaml')
KUBERNETES_USER_LIST = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'user_list.yaml')
KUBERNETES_CEPH_VOL = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'ceph_volume_final.yaml')
KUBERNETES_CEPH_STORAGE = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'ceph_volume_storage_type_final.yaml')
KUBERNETES_CEPH_VOL2 = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'ceph_volume2_final.yaml')
KUBERNETES_CEPH_VOL_FIRST = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'ceph_volume_final2.yaml')
KUBERNETES_CEPH_DELETE_SECRET = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'ceph_delete_secret.yaml')
UNINSTALL_ISTIO = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'uninstall_istio.yaml')
UNINSTALL_AMBASSADOR = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'uninstall_ambassador.yaml')
SETUP_ISTIO = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'setup_istio.yaml')
CEPH_DEPLOY = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'ceph_deploy.yaml')
CEPH_MDS = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'ceph_mds.yaml')
CEPH_DEPLOY_ADMIN = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'ceph_deploy_admin.yaml')
CEPH_MON = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'ceph_mon.yaml')
SETUP_AMBASSADOR = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'setup_ambassador.yaml')
K8_COPY_KEY = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'copy_key_gen.yaml')
K8_PUSH_KEY = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'copy_key_gen.yaml')
K8_CREATE_CRD_NETWORK = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'crd_network_k8.yaml')
K8_MULTUS_SET_MASTER = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'multus_master_k8.yaml')
K8_MULTUS_SCP_MULTUS_CNI = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'multus_scp_k8.yaml')
K8_MULTUS_SET_NODE = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'multus_node_k8.yaml')
K8_MULTUS_SCP_MULTUS_CNI_DYNAMIC_NODE = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'multus_scp_dynamic_node_k8.yaml')
K8_MULTUS_SET_DYNAMIC_NODE = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'multus_dynamic_node_k8.yaml')
K8_CONF_FLANNEL_INTERFACE_AT_MASTER = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'flannel_intf_master.yaml')
K8_CONF_FLANNEL_INTERFACE_AT_NODE = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'flannel_intf_node.yaml')
K8_CONF_FLANNEL_NETWORK_CREATION = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'flannel_network_creation.yaml')
K8_CONF_FLANNEL_INTERFACE_AT_MASTER_FOR_DYNAMIC_NODE = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'flannel_intf_master_dynamic_node.yaml')
K8_CONF_FLANNEL_INTERFACE_AT_DYNAMIC_NODE = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'flannel_intf_dynamic_node.yaml')
K8_DELETE_FLANNEL_INTERFACE = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'flannel_interface_deletion.yaml')
K8_DELETE_FLANNEL_INTERFACE_DYNAMIC_NODE = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'flannel_interface_deletion_dynamic_node.yaml')
K8_CONF_FLANNEL_DAEMON_AT_MASTER = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'flannel_daemon_at_master.yaml')
K8_CONF_FLANNEL_INTF_CREATION_AT_MASTER = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'flannel_interface_creation.yaml')
K8_CONF_WEAVE_NETWORK_CREATION = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'weave_network_creation.yaml')
K8_CONF_FILES_DELETION_AFTER_MULTUS = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'weave_conf_deletion.yaml')
K8_SRIOV_CNI_BUILD = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'k8_sriov_build_cni.yaml')
K8_SRIOV_DPDK_CNI = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'k8_sriov_dpdk_cni.yaml')
K8_SRIOV_ENABLE = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'k8_sriov_enable.yaml')
K8_SRIOV_CNI_BIN_INST = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'k8_sriov_cni_bin_inst.yaml')
K8_SRIOV_DPDK_CNI_BIN_INST = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'k8_sriov_dpdk_cni_bin_inst.yaml')
K8_SRIOV_DPDK_DRIVER_LOAD = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'k8_sriov_dpdk_kernel_load.yaml')
K8_SRIOV_CR_NW = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'sriov_network_creation.yaml')
K8_SRIOV_DPDK_CR_NW = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'sriov_dpdk_network_creation.yaml')
K8_SRIOV_DHCP_CR_NW = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'sriov_dhcp_network_creation.yaml')
K8_SRIOV_CONF = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'sriov_conf.yaml')
K8_SRIOV_CONFIG_SCRIPT = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'sriov_configuration.sh')
K8_VLAN_INTERFACE_PATH = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'vlan_tag_interface_creation.yaml')
K8_VLAN_INTERFACE_REMOVAL_PATH = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'vlan_tag_interface_removal.yaml')
K8_MACVLAN_MASTER_NETWORK_PATH = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'macvlan_master_network_creation.yaml')
K8_MACVLAN_NETWORK_PATH = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'macvlan_network_creation.yaml')
K8_MACVLAN_MASTER_NETWORK_DHCP_PATH = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'macvlan_master_network_dhcp_creation.yaml')
K8_MACVLAN_NETWORK_DHCP_PATH = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'macvlan_network_dhcp_creation.yaml')
K8_MACVLAN_NETWORK_REMOVAL_PATH = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'macvlan_network_removal.yaml')
K8_DHCP_PATH = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'dhcp_daemon.yaml')
K8_DHCP_REMOVAL_PATH = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'dhcp_daemon_removal.yaml')
K8_METRRICS_SERVER = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'metrics_server_install1.yaml')
K8_METRRICS_SERVER_CLEAN = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'metrics_server_clean.yaml')
K8_CONF_FILES_DELETION_DYNAMIC_CODE = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'k8_delete_conf_files_dynamic_node.yaml')
K8_CREATE_DEFAULT_NETWORK = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'k8_create_default_network.yaml')
K8_CREATE_INVENTORY_FILE = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'k8_create_inventory_file.yaml')
K8_DELETE_WEAVE_INTERFACE = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'weave_interface_deletion.yaml')
K8_DELETE_WEAVE_INTERFACE_DYNAMIC_NODE = pkg_resources.resource_filename(K8_ANSIBLE_PKG, 'weave_interface_deletion_dynamic_node.yaml')

NETWORKS="Networks"
DEFAULT_NETWORK="Default_Network"
NETWORKING_PLUGIN="networking_plugin"
SERVICE_SUBNET="service_subnet"
FLANNEL_NETWORK="Flannel"
WEAVE_NETWORK="Weave"
NETWORK_NAME="network_name"
