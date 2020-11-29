resource "aws_ecr_repository" "prod_ecr_repo" {
  name = "prod-ecr-repo"
}

data "aws_ami" "ami" {
  executable_users = ["self"]
  most_recent      = true
  name_regex       = "ecnDetector"
  owners           = ["self"]

  filter {
    name   = "name"
    values = ["ecnDetector"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

module "eu-west-1" {
  source = "./terraform-shared-config"
  aws_region = "eu-west-1"
  ami = "todo lmao"


}
