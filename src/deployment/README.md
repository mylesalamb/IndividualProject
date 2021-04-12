# Deployment utilities

This folder contains a collection of deployment utilities to facilitate the deployment of the network analysis tool on multiple hosts.

## installer.\*.sh

A set of installer files that download and compile the tool for a specific platform. Two variants exist in this repository.

We provide 2 installer scripts that were used during the tools deployment. One that targets the Raspberry Pi 2/3/4/ and one for Amazon Machine images, although this should work on normal Ubuntu / Ubuntu Server installs.

## deployimg.json

Defines a configuration file to be used with packer. Under the current configuration it copies images so that they may be accessed in multiple regions.

The packer configuration requires AWS keys to be defined as environment variables. See the contents of the file for details.

It is recomended in running packer to redirect stdout to a file so that the output image IDs can be extracted with `packer-to-teraform.py` subsequently producing a `tfvars.json` file instead of copying over the machine configurations manually.

A sample workflow for building machine images with the tool installed is as follows

```
packer build -machine-readable deployimg.json > outfile
python3 packer-to-terraform --dry outfile
```

## main.tf + terraform-shared-config

Provides all the terraform configuration for the project. main.tf defines the areas to deploy to, the file as it exists currently comments out unused reagions, but this can be easily changed. 

terraform-shared-config defines a terraform module to setup some basic infrastructure for the tool to operate under e.g. security groups, ssh keys and IP address assignment 


the terraform configuration can be used as is with the following commands.

```
terraform init
terraform plan
teraform apply
```
