# snaps-kubernetes CI
Readme for information on running _snaps-kubernetes_ unit tests

### Build Host Requirements

- Python installed
- Ansible has been installed into the Python runtime
- Download and install your binary for your platform from  https://www.terraform.io/downloads.html

### Setup vms on AWS and execute deployment from build vm

Run the following bash command from this directory:
```bash
export TF_CLI_CONFIG_FILE="{snaps-config dir}/aws/terraform_rc"
terraform init
terraform apply -auto-approve \
-var-file='{snaps-config dir}/aws/snaps-ci.tfvars' \
-var build_id={some unique readable value}
```

#### Optional variables
- run_build - When True, deployment will be attempted (default boolean True)
- run_validation - When True, deployment validation will be attempted (default True)
- run_conformance - When True, CNCF conformance tests will be started (default False)
- destroy - When True, the VMs will be destroyed at the end(default True)
- branch_name - The kubespray branch or version hash to use (default 'master')
- src_copy_dir - The directory to save all of the downloaded and generated files (default '/tmp')
- deployment_yaml_path - The path and filename to the generated config file (default '/tmp')
- k8s_version - The kubernetes version to install (default '1.14.3')
- networking_plugin - The cluster CNI to install with kubespray (default 'weave')
- deployment_yaml_tmplt - Override of the config template (do not recommend to use unless you know exactly what you are doing)

### Cleanup
Should the script either fail or configued not to cleanup, destruction of the
EC2 environment can be performed with the following command from this directory:
````
terraform destroy -auto-approve \
-var-file='{snaps-config dir}/aws/snaps-ci.tfvars' \
-var build_id={some unique readable value}
````
