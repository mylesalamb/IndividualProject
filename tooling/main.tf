terraform {
  required_version = "~> 0.12"
}

module "eu-west-1" {
  source = "./terraform-shared-config"
  region = "eu-west-1"
}

module "eu-west-2" {
  source = "./terraform-shared-config"
  region = "eu-west-2"
}