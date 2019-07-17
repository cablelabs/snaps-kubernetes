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
KUBESPRAY_BRANCH_KEY = 'kubespray_branch'
DFLT_KUBESPRAY_BRANCH = 'f67a24499b0402ae5a591d0ead31c212b29634f4'
KUBESPRAY_URL_KEY = 'kubespray_url'
DFLT_KUBESPRAY_URL = 'https://github.com/kubernetes-sigs/kubespray.git'
DOCKER_VER_KEY = 'docker_version'
DFLT_DOCKER_VER = '18.06'
PROJECT_NAME_KEY = 'Project_name'
ARTIFACT_DIR_KEY = 'artifact_dir'
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
PERSIST_VOL_KEY = 'Persistent_Volumes'
ROOK_VOL_KEY = 'Rook_Volume'
ROOK_VOL_NAME_KEY = 'name'
ROOK_VOL_SIZE_KEY = 'size'
ROOK_VOL_PATH_KEY = 'path'
ROOK_KEY = 'rook'
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

DFLT_NODE_USER = 'root'

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
HELM_ENABLED_KEY = 'enable_helm'
NODE_USER_KEY = 'node_user'
ENABLE_LOG_KEY = 'enable_logging'
LOG_LEVEL_KEY = 'log_level'
SECRETS_KEY = 'secrets'
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
KUBESPRAY_INV_PKG = 'snaps_k8s.kubespray.inventory'
K8_ROOK_TMPLT_PKG = 'snaps_k8s.playbooks.k8.rook'
K8S_STORAGE_CONF_PKG = 'snaps_k8s.kubespray.storage'
K8S_KUBECTL_CONF_PKG = 'snaps_k8s.kubespray.conf'
K8S_CNI_PKG = 'snaps_k8s.kubespray.cni'
K8S_VOLUME_PKG = 'snaps_k8s.kubespray.volume'
K8S_CNI_FLANNEL_PKG = '{}.{}'.format(K8S_CNI_PKG, 'flannel')
K8S_CNI_WEAVE_PKG = '{}.{}'.format(K8S_CNI_PKG, 'weave')

BUILD_PREREQS = pkg_resources.resource_filename(
    BUILD_ANSIBLE_PKG, 'build_prerequisites.yaml')
SETUP_ETC_HOSTS = pkg_resources.resource_filename(
    BUILD_ANSIBLE_PKG, 'setup_etc_hosts.yaml')
MANAGE_KEYS = pkg_resources.resource_filename(
    BUILD_ANSIBLE_PKG, 'manage_keys.yaml')

K8_CLONE_CODE = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_clone_code.yaml')
K8_REMOVE_FOLDER = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_remove_project_folder.yaml')
K8_REMOVE_NODE_K8 = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_remove_nodes.yaml')
K8_SET_HOSTNAME = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'set_hostname.yaml')
K8_NODE_LABELING = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_node_label.yaml')
KUBERNETES_SET_LAUNCHER = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'launcher_setup.yaml')
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
INSTALL_CEPH = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'install_ceph.yaml')
CEPH_STORAGE_NODE = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'ceph_node_vol_final.yaml')
CEPH_STORAGE_HOST = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'ceph_host_vol_final.yaml')
KUBERNETES_CEPH_CLASS = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'ceph_class.yaml')
KUBERNETES_CEPH_CLAIM = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'ceph_claim.yaml')
CEPH_DEPLOY = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'ceph_deploy.yaml')
CEPH_MDS = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'ceph_mds.yaml')
CEPH_DEPLOY_ADMIN = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'ceph_deploy_admin.yaml')
CEPH_MON = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'ceph_mon.yaml')
K8_CREATE_CRD_NETWORK = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'crd_network_k8.yaml')
K8_MULTUS_NODE_BIN = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'multus_node_bin.yaml')
K8_MULTUS_SET_NODE = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'multus_node_k8.yaml')
K8_MULTUS_CLUSTER_ROLE_DEFINE = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'multus_cluster_role_define.yaml')
K8_MULTUS_CLUSTER_ROLE_CREATION = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'multus_cluster_role_creation.yaml')
K8_MULTUS_SET_MASTER = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'multus_master_k8.yaml')
K8_DELETE_FLANNEL_INTERFACE = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'flannel_interface_deletion.yaml')
K8_CONF_FLANNEL_DAEMON_AT_MASTER = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'flannel_daemon_at_master.yaml')
K8_CONF_FLANNEL_RBAC = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'flannel_rbac.yaml')
K8_CONF_FLANNEL_INTF_CREATE = pkg_resources.resource_filename(
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
K8_CREATE_DEFAULT_NETWORK = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_create_default_network.yaml')
K8_FLANNEL_NET_CREATE = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'flannel_cni_net_create.yaml')
K8_DELETE_WEAVE_INTERFACE = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'weave_interface_deletion.yaml')
K8_KUBECTL_INSTALLATION = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'kubectl_installation.yaml')
K8_ENABLE_KUBECTL_CONTEXT = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'enable_kubectl_context.yaml')
K8_DOCKER_CLEAN_UP_ON_NODES = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_docker_clean_up.yaml')
K8_HA_EXT_LB = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'k8_ha_external_load_balancer_install.yaml')
K8_DOCKER_SECRET = pkg_resources.resource_filename(
    K8_ANSIBLE_PKG, 'create_docker_secret.yaml')

KUBESPRAY_INV_J2 = pkg_resources.resource_filename(
    KUBESPRAY_INV_PKG, 'inventory.cfg.j2')
KUBESPRAY_GROUP_ALL_J2 = pkg_resources.resource_filename(
    KUBESPRAY_INV_PKG, 'all.yml.j2')
INSTALL_ROOK_PB = pkg_resources.resource_filename(
    K8_ROOK_TMPLT_PKG, 'install_rook.yaml')
K8S_ROOK_OPERATOR_J2 = pkg_resources.resource_filename(
    K8_ROOK_TMPLT_PKG, 'rook-operator.yaml.j2')
K8S_ROOK_CLUSTER_J2 = pkg_resources.resource_filename(
    K8_ROOK_TMPLT_PKG, 'rook-cluster.yaml.j2')
K8S_ROOK_STO_CLASS_J2 = pkg_resources.resource_filename(
    K8_ROOK_TMPLT_PKG, 'rook-storageclass.yaml.j2')
ROOK_PV_J2 = pkg_resources.resource_filename(
    K8_ROOK_TMPLT_PKG, 'rook-pv.yaml.j2')

KUBESPRAY_PB_REL_LOC = 'kubespray/cluster.yml'
KUBESPRAY_CLUSTER_CONF = pkg_resources.resource_filename(
    KUBESPRAY_INV_PKG, 'k8s-cluster.yml')
KUBESPRAY_ALL_CONF = pkg_resources.resource_filename(
    KUBESPRAY_INV_PKG, 'all.yml.j2')

KUBECTL_CONF_TMPLT = pkg_resources.resource_filename(
    K8S_KUBECTL_CONF_PKG, 'config-demo')
K8S_BASIC_AUTH_CSV = pkg_resources.resource_filename(
    K8S_KUBECTL_CONF_PKG, 'basic_auth.csv')

K8S_CEPH_RDB_J2 = pkg_resources.resource_filename(
    K8S_STORAGE_CONF_PKG, 'ceph-storage-fast_rbd.yml.j2')
K8S_CEPH_VC_J2 = pkg_resources.resource_filename(
    K8S_STORAGE_CONF_PKG, 'ceph-vc.yml.j2')

K8S_CRD_NET_CONF = pkg_resources.resource_filename(
    K8S_CNI_PKG, 'crdNetwork.yaml')
K8S_CNI_CLUSTER_ROLE_CONF = pkg_resources.resource_filename(
    K8S_CNI_PKG, 'cluster_role.yaml')

K8S_VOL_PV_VOL_J2 = pkg_resources.resource_filename(
    K8S_VOLUME_PKG, 'task-pv-volume.yaml.j2')
K8S_VOL_PV_CLAIM_J2 = pkg_resources.resource_filename(
    K8S_VOLUME_PKG, 'task-pv-claim.yaml.j2')

K8S_CNI_FLANNEL_J2 = pkg_resources.resource_filename(
    K8S_CNI_FLANNEL_PKG, 'kube-cni-flannel.yml.j2')
K8S_CNI_FLANNEL_RBAC_YML = pkg_resources.resource_filename(
    K8S_CNI_FLANNEL_PKG, 'kube-cni-flannel-rbac.yml')

K8S_CNI_WEAVE_SCOPE_CONF = pkg_resources.resource_filename(
    K8S_CNI_WEAVE_PKG, 'weave_scope.yaml')

KUBESPRAY_CLUSTER_CREATE_PB = 'cluster.yml'
KUBESPRAY_CLUSTER_RESET_PB = 'reset.yml'
