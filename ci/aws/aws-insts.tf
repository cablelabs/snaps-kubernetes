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
# AWS EC2 Instances
resource "aws_instance" "k8s-build" {
  ami = var.ami
  instance_type = var.instance_type_build
  key_name = aws_key_pair.snaps-k8s-pk.key_name
  availability_zone = var.availability_zone
  subnet_id = aws_subnet.snaps-k8s-primary-subnet.id

  tags = {
    Name = "snaps-k8s-ci-build-${var.build_id}"
    Terraform = "true"
    Environment = "ci"
  }

  security_groups = [aws_security_group.snaps-k8s.id]

  # Used to ensure host is really up before attempting to apply ansible playbooks
  provisioner "remote-exec" {
    inline = [
      "sudo apt install python -y"
    ]
  }

  # Remote connection info for remote-exec
  connection {
    host = self.public_ip
    type     = "ssh"
    user     = var.sudo_user
    private_key = file(var.private_key_file)
  }
}

resource "aws_instance" "k8s-node" {
  count = 2
  ami = var.ami
  instance_type = var.instance_type_node
  key_name = aws_key_pair.snaps-k8s-pk.key_name
  availability_zone = var.availability_zone
  subnet_id = aws_subnet.snaps-k8s-primary-subnet.id

  tags = {
    Name = "snaps-k8s-node-${var.build_id}"
  }

  security_groups = [aws_security_group.snaps-k8s.id]
  associate_public_ip_address = true

  # Used to ensure host is really up before attempting to apply ansible playbooks
  provisioner "remote-exec" {
    inline = [
      "sudo apt install python -y"
    ]
  }

  # Remote connection info for remote-exec
  connection {
    host = self.public_ip
    type     = "ssh"
    user     = var.sudo_user
    private_key = file(var.private_key_file)
  }
}

resource "aws_network_interface" "snaps-k8s-node-secondary-intf" {
  count = 2
  subnet_id = aws_subnet.snaps-k8s-secondary-subnet.id
  attachment {
    instance = aws_instance.k8s-node[count.index].id
    device_index = 1
  }
}
