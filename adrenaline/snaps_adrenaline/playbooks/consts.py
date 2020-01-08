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

"""
File to hold constants for Ansible
"""
import pkg_resources
from drp_python.network_layer.http_session import HttpSession

DFLT_K8S_VERSION = '1.12.5'
DFLT_KUBESPRAY_URL = 'https://github.com/cablelabs/kubespray'
DFLT_KUBESPRAY_BRANCH = 'master'

PLAYBOOK_PKG = 'adrenaline.playbooks'
BOOT_PK_PKG = "{}.{}".format(PLAYBOOK_PKG, 'boot')
K8S_PK_PKG = "{}.{}".format(PLAYBOOK_PKG, 'kubernetes')

REBAR_SESSION = HttpSession(
    'https://localhost:8092', 'rocketskates', 'r0cketsk8ts')

REBOOT_LIBVIRT_VMS = pkg_resources.resource_filename(
    BOOT_PK_PKG, 'reboot_libvirt_vms.yaml')
OVERRIDE_DFLT_MTU_PB = pkg_resources.resource_filename(
    BOOT_PK_PKG, 'override_default_mtu.yaml')
HAS_GPU_BOOT_PB = pkg_resources.resource_filename(
    BOOT_PK_PKG, 'has_gpu.yaml')
SETUP_GPU_BOOT_PB = pkg_resources.resource_filename(
    BOOT_PK_PKG, 'setup_gpu.yaml')
HAS_FPGA_BOOT_PB = pkg_resources.resource_filename(
    BOOT_PK_PKG, 'has_fpga.yaml')
SETUP_FPGA_BOOT_PB = pkg_resources.resource_filename(
    BOOT_PK_PKG, 'setup_fpga.yaml')
REBOOT_NODE = pkg_resources.resource_filename(
    BOOT_PK_PKG, 'reboot_node.yaml')

CONF_K8S_PB = pkg_resources.resource_filename(
    K8S_PK_PKG, 'configure.yaml')
TEMP_NODE_SETUP_PB = pkg_resources.resource_filename(
    K8S_PK_PKG, 'temp_setup_node.yaml')
SETUP_NVIDIA_DOCKER_PB = pkg_resources.resource_filename(
    K8S_PK_PKG, 'setup_gpu_docker.yaml')
NVIDIA_DOCKER_CONF = pkg_resources.resource_filename(
    K8S_PK_PKG, 'daemon.json')
SETUP_K8S_HW_PLUGIN_PB = pkg_resources.resource_filename(
    K8S_PK_PKG, 'setup_k8s_hw_plugin.yaml')
NODEJS_START_SCRIPT = pkg_resources.resource_filename(
    K8S_PK_PKG, 'start_nodejs.sh.j2')

K8S_TMPLT_PKG = 'adrenaline.deployment.kubernetes.config'
K8S_DEPLOY_TMPLT = pkg_resources.resource_filename(
    K8S_TMPLT_PKG, 'deployment.yaml.j2')
K8S_DEPOY_NODE_CONFIG_TMPLT = pkg_resources.resource_filename(
    K8S_TMPLT_PKG, 'node_config.j2')

FPGA_K8S_SPEC_URL = 'https://raw.githubusercontent.com/Xilinx/FPGA_as_a_Service/master/k8s-fpga-device-plugin/trunk/fpga-device-plugin.yml'
GPU_K8S_SPEC_URL = 'https://github.com/NVIDIA/k8s-device-plugin/raw/v{{ K8S_VERSION }}/nvidia-device-plugin.yml'

MASTER_CONFIG_PORT = 2376
MINION_CONFIG_PORT = 4386
