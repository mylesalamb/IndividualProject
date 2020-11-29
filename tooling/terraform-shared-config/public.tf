# data "aws_ami" "ecn_detector" {
#   executable_users = ["self"]
#   most_recent      = true
#   name_regex       = "^myami-\\d{3}"
#   owners           = ["self"]
#   region = var.aws_region
#   filter {
#     name   = "name"
#     values = ["myami-*"]
#   }

#   filter {
#     name   = "root-device-type"
#     values = ["ebs"]
#   }

#   filter {
#     name   = "virtualization-type"
#     values = ["hvm"]
#   }
# }

resource "aws_instance" "ecnDetector" {
  provider                    = "aws.singleregion"
  ami                         = "ami-0326c1a8e20140c86"
  instance_type               = "t2.nano"
  vpc_security_group_ids      = ["${aws_security_group.default.id}"]
  subnet_id                   = "${aws_subnet.default.id}"
  associate_public_ip_address = true
  source_dest_check           = false

}
