###########################################################################
# Copyright 2017 ARICENT HOLDINGS LUXEMBOURG SARL. and
# Cable Television Laboratories, Inc.
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
###########################################################################


import logging
import subprocess
import plugin_loader

logger = logging.getLogger('deployment')

def deploy_infra(conf, flag, deploy_file):
    """
    deploy_infra: This functions triggers deployment
    """
    logger.info("\n Argument List:" + "\n conf:" + str(conf) + "\n flag:" +
                flag + "\n deploy_flag:" + deploy_file)

    result = "successful"
    deploy = plugin_loader.PluginLoader()
    logger.info('flag - %s', flag)
    ret_value = deploy.load(conf, flag, deploy_file)
    if not ret_value:
        result = "not successful"

    if flag == "deploy_k8":
        statement = "Kubernetes deployment is {result}".format(result=result)
    elif flag == "clean_k8":
        statement = "Kubernetes cleanup is {result}".format(result=result)

    logger.info(statement)
    subprocess.call('echo ' + statement, shell=True)

    logger.info('exit')
    return ret_value
