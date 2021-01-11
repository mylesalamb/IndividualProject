terraform {
  required_version = ">= 0.13"
}

# Populate all of these from packerwrapper.py -> *.tfvars.json
variable us-east-1_ami      {}
# variable us-east-2_ami      {}
variable us-west-1_ami      {}
# variable us-west-2_ami      {}

# variable ap-east-1_ami      {}
variable ap-northeast-1_ami {}
# variable ap-northeast-2_ami {}
# variable ap-southeast-1_ami {}
# variable ap-southeast-2_ami {}
# variable ap-south-1_ami     {}

# variable eu-west-1_ami      {}
variable eu-west-2_ami      {}
# variable eu-west-3_ami      {}
# variable eu-central-1_ami   {}
# variable eu-south-1_ami     {}
# variable eu-north-1_ami     {}

# variable ca-central-1_ami   {}
variable me-south-1_ami     {}
variable sa-east-1_ami      {}

# US

module "us-west-1" {
  source = "./terraform-shared-config"
  region = "us-west-1"
  ami_image = var.us-west-1_ami
}

# module "us-west-2" {
#   source = "./terraform-shared-config"
#   region = "us-west-2"
#   ami_image = var.us-west-2_ami
# }

module "us-east-1" {
  source = "./terraform-shared-config"
  region = "us-east-1"
  ami_image = var.us-east-1_ami
}

# module "us-east-2" {
#   source = "./terraform-shared-config"
#   region = "us-east-2"
#   ami_image = var.us-east-2_ami
# }

# # Asia/pacific

module "ap-northeast-1" {
  source = "./terraform-shared-config"
  region = "ap-northeast-1"
  ami_image = var.ap-northeast-1_ami
}

# module "ap-northeast-2" {
#   source = "./terraform-shared-config"
#   region = "ap-northeast-2"
#   ami_image = var.ap-northeast-2_ami
# }

# module "ap-southeast-1" {
#   source = "./terraform-shared-config"
#   region = "ap-southeast-1"
#   ami_image = var.ap-southeast-1_ami
# }

# module "ap-southeast-2" {
#   source = "./terraform-shared-config"
#   region = "ap-southeast-2"
#   ami_image = var.ap-southeast-2_ami
# }

# module "ap-south-1" {
#   source = "./terraform-shared-config"
#   region = "ap-south-1"
#   ami_image = var.ap-south-1_ami
# }

# module "ap-east-1" {
#   source = "./terraform-shared-config"
#   region = "ap-east-1"
#   ami_image = var.ap-east-1_ami
# }


# EU

# module "eu-west-1" {
#   source = "./terraform-shared-config"
#   region = "eu-west-1"
#   ami_image = var.eu-west-1_ami
# }

module "eu-west-2" {
  source = "./terraform-shared-config"
  region = "eu-west-2"
  ami_image = var.eu-west-2_ami
}

# module "eu-west-3" {
#   source = "./terraform-shared-config"
#   region = "eu-west-3"
#   ami_image = var.eu-west-3_ami
# }


# module "eu-south-1" {
#   source = "./terraform-shared-config"
#   region = "eu-south-1"
#   ami_image = var.eu-south-1_ami
# }

# module "eu-north-1" {
#   source = "./terraform-shared-config"
#   region = "eu-north-1"
#   ami_image = var.eu-north-1_ami
# }

# module "eu-central-1" {
#   source = "./terraform-shared-config"
#   region = "eu-central-1"
#   ami_image = var.eu-central-1_ami
# }

# # Various

# module "ca-central-1" {
#   source = "./terraform-shared-config"
#   region = "ca-central-1"
#   ami_image = var.ca-central-1_ami
# }

 module "me-south-1" {
   source = "./terraform-shared-config"
   region = "me-south-1"
   ami_image = var.me-south-1_ami
 }

module "sa-east-1" {
  source = "./terraform-shared-config"
  region = "sa-east-1"
  ami_image = var.sa-east-1_ami
}
