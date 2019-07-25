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

# Outputs

output "pub_ip_build" {
  value = aws_instance.k8s-build.public_ip
}

output "priv_ip_build" {
  value = aws_instance.k8s-build.public_ip
}

output "pub_ip_master" {
  value = aws_instance.k8s-master.public_ip
}

output "priv_ip_master" {
  value = aws_instance.k8s-master.private_ip
}

output "pub_ip_minion" {
  value = aws_instance.k8s-minion.public_ip
}

output "priv_ip_minion" {
  value = aws_instance.k8s-minion.private_ip
}

output "priv_key_file" {
  value = var.private_key_file
}

output "pub_key_file" {
  value = var.public_key_file
}

output "sudo_user" {
  value = var.sudo_user
}
