# snaps-kubernetes CI
Readme for information on running _snaps-kubernetes_ CI

## Build Host Requirements

- Python installed
- Ansible has been installed into the Python runtime
- Download and install Terraform from  https://www.terraform.io/downloads.html

## Setup vms on AWS and execute deployment from build vm

Run the following bash command from this directory:
```bash
export TF_CLI_CONFIG_FILE="{snaps-config dir}/aws/terraform_rc"
terraform init
terraform apply -auto-approve \
-var-file='{snaps-config dir}/aws/snaps-ci.tfvars' \
-var build_id={some unique readable value}
```

## Cleanup
Always perform cleanup after completion by running the following command from this directory:
```bash
terraform destroy -auto-approve \
-var-file='{snaps-config dir}/aws/snaps-ci.tfvars' \
-var build_id={some unique readable value}
```
