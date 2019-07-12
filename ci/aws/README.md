# tofino-sim P4 CI
Readme for information on running tofino-sim unit tests

### Host Requirements

- Python installed
- The python-pip package has been installed
- The ansible has been installed

### Install terraform 0.12 or greater

Download and install your binary for your platform from  https://www.terraform.io/downloads.html

### Setup and execute playbook

This Terraform script has been designed to run and execute unit tests for P4
programs currently only for Tofino chips and requires 3 values:

1. build_id: this value must be unique to ensure multiple jobs can be run
simultaneously from multiple hosts

````
git clone https://github.com/cablelabs/snaps-pdp
git clone https://github.com/cablelabs/snaps-config
cd snaps-pdp/ci/p4/tofino-sim
ansible-playbook --extra-vars "tf_var_file={snaps-config dir}/aws/snaps-ci.tfvars build_id={some unique value}"
````

### Cleanup
````
# from snaps-pdp/ci/p4/tofino-P4_16 directory
terraform destroy -var-file={snaps-config dir}/aws/snaps-ci.tfvars \
-auto-approve -var\
'build_id={some unique value}'\
````
