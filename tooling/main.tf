terraform {
  required_version = ">= 0.13"
}

# Populate all of these from packerwrapper.py -> *.tfvars.json
variable us-east-1_ami      {}
variable us-east-2_ami      {}
variable us-west-1_ami      {}
variable us-west-2_ami      {}

variable ap-east-1_ami      {}
variable ap-northeast-1_ami {}
variable ap-northeast-2_ami {}
variable ap-southeast-1_ami {}
variable ap-southeast-2_ami {}
variable ap-south-1_ami     {}

variable eu-west-1_ami      {}
variable eu-west-2_ami      {}
variable eu-west-3_ami      {}
variable eu-central-1_ami   {}
variable eu-south-1_ami     {}
variable eu-north-1_ami     {}

variable ca-central-1_ami   {}
variable me-south-1_ami     {}
variable sa-east-1_ami      {}

module "eu-west-2" {
  source = "./terraform-shared-config"
  region = "eu-west-2"
  ami_image = var.eu-west-2_ami
}

# module "eu-west-1" {
#   source = "./terraform-shared-config"
#   region = "eu-west-1"
# }