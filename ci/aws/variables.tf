# Copyright (c) 2019 Cable Television Laboratories, Inc.
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

# Required Variables
variable "access_key" {}
variable "secret_key" {}
variable "build_id" {}

# Stub Variables (unused but to remove warnings)
variable "git_user" {}
variable "git_pass" {}

# Optional Variables
variable "public_key_file" {default = "~/.ssh/id_rsa.pub"}
variable "private_key_file" {default = "~/.ssh/id_rsa"}
variable "sudo_user" {default = "ubuntu"}
variable "region" {default = "us-west-2"}
variable "availability_zone" {default = "us-west-2b"}

# Ubuntu 16.04 SSD Volume Type
variable "ami" {default = "ami-0b37e9efc396e4c38"}

variable "instance_type_build" {default = "t2.small"}
variable "instance_type_node" {default = "t2.large"}

# Variables for ansible playbooks
variable "ANSIBLE_CMD" {default = "export ANSIBLE_HOST_KEY_CHECKING=False; ansible-playbook"}
variable "SETUP_K8S_NODE" {default = "../playbooks/setup_k8s_node.yaml"}
variable "DEPLOY_K8S" {default = "../playbooks/deploy_k8.yaml"}
variable "VALIDATE_K8S" {default = "../playbooks/validation.yaml"}
variable "CONFORMANCE" {default = "../playbooks/conformance.yaml"}

variable "branch_name" {default = "master"}
variable "src_copy_dir" {default = "/tmp"}
variable "deployment_yaml_path" {default = "/tmp/deployment.yaml"}
variable "admin_iface" {default = "eth0"}
variable "k8s_version" {default = "1.14.3"}
variable "node_host_pass" {default = "Pa$$w0rd"} // Should probably remove
variable "networking_plugin" {default = "weave"}
variable "deployment_yaml_tmplt" {default = "templates/deployment.yaml.j2"}
