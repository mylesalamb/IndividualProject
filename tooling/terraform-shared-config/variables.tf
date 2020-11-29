variable "region" {}
variable "ami_image" {}

variable "aws_key_name" { default = "masterKey" }
# variable "aws_key_contents" {default = file("~/masterKey.pem")}