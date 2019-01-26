# Copyright (c) 2019 Cable Television Laboratories, Inc. ("CableLabs")
#                    and others.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import argparse
import logging
import sys
from snaps_common.file import file_utils
from snaps_k8s.common.utils import validate_cluster

__author__ = 'spisarski'

logger = logging.getLogger('validate_deployment')


def __run(deploy_file):
    """
    Validates that the cluster has been properly deployed
    """
    k8s_conf = file_utils.read_yaml(deploy_file)
    validate_cluster.validate_all(k8s_conf)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--deploy-file', dest='deploy_file',
                        required=True, help='The k8s config file')
    args = parser.parse_args()

    logging.basicConfig(stream=sys.stdout, level=logging.INFO)

    __run(args.deploy_file)
