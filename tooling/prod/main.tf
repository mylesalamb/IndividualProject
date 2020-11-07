provider "aws" {
  region = "eu-west-2"
}

resource "aws_ecr_repository" "prod_ecr_repo" {
  name = "prod-ecr-repo"
}

# resource "aws_instance" "example" {
#   ami           = "ami-0fc841be1f929d7d1"
#   instance_type = "t2.micro"

#   #user_data

#   tags = {
#     Name = "ecn-detector-london"
#   }
# }

