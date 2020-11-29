# module "eu-west-1" {
#   source = "./terraform-shared-config"
#   aws_region = "eu-west-1"
#   providers = {
#     aws.singleregion = "aws.eu-west-1"
#   }
# }

module "eu-west-2" {
  source = "./terraform-shared-config"
  aws_region = "eu-west-2"
  providers = {
    aws.singleregion = "aws.eu-west-2"
  }
}

