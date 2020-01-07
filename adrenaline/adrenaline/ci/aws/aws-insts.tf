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
resource "aws_spot_instance_request" "adrenaline-host" {
  ami = var.boot_ami

  # Acceptable values 'one-time'|'persistent'
  spot_type = var.spot_type

  # wait_for_fulfillment needs to be true to obtain instance attributes
  wait_for_fulfillment = var.wait_for_fulfillment

  instance_type = var.instance_type
  key_name = aws_key_pair.adrenaline-pk.key_name
  availability_zone = var.availability_zone

  root_block_device {
    volume_size = var.volume_size
  }

  tags = {
    Name = "adrenaline-ci-build-${var.build_id}"
  }

  security_groups = [aws_security_group.adrenaline.name]
  associate_public_ip_address = true

  # Used to ensure host is really up before attempting to apply ansible playbooks
  provisioner "remote-exec" {
    inline = [
      "echo 'hello ${var.build_id}' /etc/motd"
    ]
  }

  # Remote connection info for remote-exec
  connection {
    host = self.public_ip
    type     = "ssh"
    user     = var.sudo_user
    private_key = file(var.private_key_file)
    timeout = "15m"
  }
}
