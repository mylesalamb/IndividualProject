terraform {
  required_version = ">= 0.12"
}

provider "aws" {
    alias = "singleregion"
    region = var.region
}

# data "aws_ami" "image" {
#   most_recent = true
#   owners = ["self"]
#   filter {                       
#     name = "tag:Application"     
#     values = ["ecnDetector"]
#   }                              
# }

# output "ami_id" {
#   value = "${data.aws_ami.image.id}"
# }


resource "aws_instance" "ecnDetector" {
  provider                    = aws.singleregion
  ami                         = "helloami"# data.aws_ami.default.id
  instance_type               = "t2.nano"
  vpc_security_group_ids      = ["${aws_security_group.default.id}"]
  subnet_id                   = "${aws_subnet.default.id}"
  associate_public_ip_address = true
  source_dest_check           = false
}
