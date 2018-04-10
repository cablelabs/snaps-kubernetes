# This script is responsible for deploying Aricent_Iaas environments and kubernetes
import argparse
import logging
import os
import re
import sys,subprocess
from optparse import OptionParser
sys.path.append("common/utils" )
from provision.kubernetes.deployment import deploy_infra

#configure the launcher node
def __launcher_conf(config):
 import os
 proxy_fname="proxy.txt"
 logger.info('Updating proxy in apt.conf')
 apt_fname="/etc/apt/apt.conf"
 env_fname="/etc/environment"
 http_pattern="\"http:"
 https_pattern="\"https:"
 ftp_pattern="\"ftp:"
 no_pattern="\"127.0.0.1"
 import re
 #os.system("grep -i 'https_proxy:\|http_proxy:\|ftp_proxy:' deployment.yaml|awk '{print $2}' >proxy.txt")
 os.system("grep -i 'https_proxy:\|http_proxy:\|ftp_proxy:\|no_proxy:' "+config+"|awk '{print $2}' >proxy.txt")
 with open(proxy_fname) as f:
    out = open(apt_fname, "w")
    env_file = open(env_fname, "w")
    env_file.write("PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games\"\n")
    for line in f:
        if re.match(http_pattern, line):
            http_line1="Acquire::http::Proxy "+line
            http_line=http_line1.strip('\t\n\r')
            http_line=http_line+";"+"\n"
            out.write(http_line)
            http_line2="export http_proxy="+line
            http_line3=http_line2.strip('\t\n\r')
            http_line3=http_line3+"\n"
  #print http_line
            env_file.write(http_line3)
        elif re.match(https_pattern, line):
            https_line1="Acquire::https::Proxy "+line
            https_line=https_line1.strip('\t\n\r')
            https_line=https_line+";"+"\n"
            out.write(https_line)
            https_line="export https_proxy="+line
            https_line4=https_line.strip('\t\n\r')
            https_line4=https_line4+"\n"
            env_file.write(https_line4)

        elif re.match(ftp_pattern, line):
            ftp_line1="Acquire::ftp::Proxy "+line
            ftp_line=ftp_line1.strip('\t\n\r')
            ftp_line=ftp_line+";"+"\n"
            out.write(ftp_line)
        elif re.match(no_pattern, line):
            https_line="export no_proxy="+line
            https_line4=https_line.strip('\t\n\r')
            https_line4=https_line4+"\n"
            print https_line4
            env_file.write(https_line4)

        #else:
        #    print "check your file"
    out.close()
    f.close()
 os.system("rm proxy.txt")
 logger.info('apt-get update')
 command="apt-get update"
 res=subprocess.call(command ,shell=True)
 if(res!=0):
    logger.info('error in apt-get update')
 logger.info('apt-get install pathlib')
 command="apt-get install -y pathlib*"
 res=subprocess.call(command ,shell=True)
 if(res!=0):
    logger.info('error in apt-get install pathlib')
 from pathlib import Path
 known_hosts = Path("/root/.ssh/known_hosts")
 if known_hosts.is_file():
  logger.info('remove  /root/.ssh/known_hosts')
  os.remove("/root/.ssh/known_hosts")
 logger.info('apt-get install python')
 command="apt-get install -y python"
 res=subprocess.call(command ,shell=True)
 if(res!=0):
    logger.info('error in apt-get install python')
 logger.info('apt-get install -y ansible')
 command="apt-get install -y ansible"
 res=subprocess.call(command ,shell=True)
 if(res!=0):
    logger.info('error in apt-get install -y ansible')
 logger.info('apt-get install -y python-pip')
 command="apt-get install -y python-pip"
 res=subprocess.call(command ,shell=True)
 if(res!=0):
    logger.info('error in apt-get install -y python-pip')
 logger.info('pip install --upgrade pip')
 command="pip install --upgrade pip"
 res=subprocess.call(command ,shell=True)
 if(res!=0):
    logger.info('error in pip install --upgrade pip')
 logger.info('pip install --upgrade ansible==2.3.1.0')
 command="pip install --upgrade ansible==2.3.1.0"
 res=subprocess.call(command ,shell=True)
 if(res!=0):
    logger.info('error in pip install --upgrade ansible==2.3.1.0')
 logger.info('apt-get install sshpass')
 command="apt-get install sshpass"
 res=subprocess.call(command ,shell=True)
 if(res!=0):
    logger.info('error in apt-get install sshpass')

 logger.info('pip install pyOpenSSL==16.2.0 ')
 command="pip install pyOpenSSL==16.2.0"
 res=subprocess.call(command ,shell=True)
 if(res!=0):
    logger.info('error in pip install pyOpenSSL==16.2.0')

 logger.info('apt-get install dos2unix')
 command="apt-get install dos2unix"
 res=subprocess.call(command ,shell=True)
 if(res!=0):
    logger.info('error in apt-get install dos2unix')
#from provision.hardware import pxe_utils


__author__ = '_ARICENT'

logger = logging.getLogger('launch_provisioning')

ARG_NOT_SET = "argument not set"

#def __readhwconfig(config, operation):
#    """
#     This will launch the provisioning of PXE setup on the configuration node.
#     :param config : This configuration data extracted from the host.yaml.
#    """
#    if config:
#      logger.info("Read & Validate functionality for Hardware Provisioning")
#      pxe_utils.__main(config,operation)

def __manage_operation(config, operation):
    """
     This will launch the provisioning of kubernetes setup on the cluster node which are defined in the deployment.yaml.
     :param config : This configuration data extracted from the provided yaml file.
    """

    if config:
        config_dict = {}
        if config.get('kubernetes'):
      	   logger.info("Your deployement model is :")
      	   #logger.info(config.get('kubernetes').get('deployment_type'))

           logger.info("########################### Yaml Configuration##############")
           logger.info(config)
           logger.info("############################################################")
           logger.info("Read & Validate functionality for Devstack")
           print "******operation********"
           print operation
           deploy_infra(config, operation)
        else:
      	   logger.error("Configuration Error ")



def main(arguments):
    """
     This will launch the provisioning of Bare metat & IaaS.
     There is pxe based configuration defined to provision the bare metal.
     For IaaS provisioning different deployment models are supported.
     Relevant conf files related to PXE based Hw provisioning & IaaS must be present in ./conf folder.
     :param command_line options: This expects command line options to be entered by user for relavant operations.
     :return: To the OS
    """
    if arguments.deploy is not ARG_NOT_SET:
      __launcher_conf(arguments.config);
    import file_utils
    import yaml

    log_level = logging.INFO

    if arguments.log_level != 'INFO':
        log_level = logging.DEBUG
    logging.basicConfig(level=log_level)

    logger.info('Launching Operation Starts ........')

    dir_path = os.path.dirname(os.path.realpath(__file__))
    export_path=dir_path+"/"
    os.environ['CWD_IAAS']=export_path
    print "===========================Current Exported Relevant Path=================================="
    logger.info(export_path)

    config = file_utils.read_yaml(arguments.config)
    logger.info('Read configuration file - ' + arguments.config)
    try:

   	  if arguments.deploy is not ARG_NOT_SET:
               __manage_operation(config, "deploy_k8")
    #Functions to read yml for IaaS environment
   	  if arguments.clean is not ARG_NOT_SET:
               __manage_operation(config, "clean_k8" )
   	  if arguments.dynamic_deploy is not ARG_NOT_SET:
               __manage_operation(config, "dynamic_deploy_k8" )
   	  if arguments.dynamic_clean is not ARG_NOT_SET:
               __manage_operation(config, "dynamic_clean_k8" )

    	  logger.info('Completed opeartion successfully')
    except Exception as e:
           logger.error('Unexpected error deploying environment. Rolling back due to - ' + e.message)
           raise e


if __name__ == '__main__':


#    if os.environ.get('CWD_IAAS') is None:
#         path=os.getcwd()

#         print'ENVIRONMENT VARIABLE "CWD_IAAS" IS NOT EXPORTED OR USER IS NOT ROOT USER : USE COMMAND: su root; export CWD_IAAS="'+path+ "\""
#         exit(1)

    # To ensure any files referenced via a relative path will begin from the diectory in which this file resides
    os.chdir(os.path.dirname(os.path.realpath(__file__)))

    parser = argparse.ArgumentParser()
    parser.add_argument('-k8_d', '--deploy_kubernetes', dest='deploy', nargs='?', default=ARG_NOT_SET,
                        help='When used, deployment of kubernetes will be started')
    parser.add_argument('-k8_c', '--clean_kubernetes', dest='clean', nargs='?', default=ARG_NOT_SET,
                        help='When used, the kubernetes cluster will be removed')
    parser.add_argument('-k8_dd', '--add_nodes_kubernetes', dest='dynamic_deploy', nargs='?', default=ARG_NOT_SET,
                        help='When used, the kubernetes nodes will be added')
    parser.add_argument('-k8_dc', '--clean_nodes_kubernetes', dest='dynamic_clean', nargs='?', default=ARG_NOT_SET,
                        help='When used, the kubernetes nodes will be removed')
    parser.add_argument('-f', '--file', dest='config', required=True,
                        help='The configuration file in YAML format - REQUIRED', metavar="FILE")
    parser.add_argument('-l', '--log-level', dest='log_level', default='INFO', help='Logging Level (INFO|DEBUG)')
    args = parser.parse_args()

    if  args.deploy is ARG_NOT_SET and args.clean is ARG_NOT_SET and args.dynamic_deploy is ARG_NOT_SET \
        and args.dynamic_clean is ARG_NOT_SET:
        logger.info('Must enter only one option either for deploy or for clean up kubernetes cluster')
        exit(1)
    if args.deploy is not ARG_NOT_SET and args.clean is not ARG_NOT_SET and args.dynamic_deploy is not ARG_NOT_SET \
        and args.dynamic_clean is not ARG_NOT_SET:
        logger.info('Cannot enter all option. Select one option either for deploy or for clean')
        exit(1)
    if args.deploy is not ARG_NOT_SET and args.config is ARG_NOT_SET:
        logger.info('Cannot start deploy operation without configuration. Choose the option -f/--file')
        exit(1)
    if args.deploy is ARG_NOT_SET and args.config is ARG_NOT_SET:
        logger.info('Cannot start any deploy operation without both -d/--deploy and -f/--file')
        exit(1)
#    if args.hardware is not ARG_NOT_SET and args.clean is not ARG_NOT_SET:
#        print 'Cannot start any deploy iaas operation without -d/--deploy and -f/--file'
#        exit(1)

    main(args)
