
from plugin_loader import PluginLoader
import logging

#data= {"1":"abc", "def":"123", "2":"ghy"}
logger = logging.getLogger('deploy_infra')

def deploy_infra (conf, flag):

     deploy=PluginLoader()
     ret=False
     #deployment_type = conf.get('kubernetes').get('deployement_type')
     print "*******flag*****"
     print  flag
     #if deploy.load(deployment_type, conf, flag) :
     if deploy.load(conf, flag) :
         logger.info('Kubernetes operation is successfull')
         ret=True
     else:
         logger.info('Kubernetes operation is unsuccessfull')
         ret=False
