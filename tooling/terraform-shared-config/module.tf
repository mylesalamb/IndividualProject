terraform {
  required_version = ">= 0.13"
}

provider "aws" {
    alias = "singleregion"
    region = var.region
}

resource "aws_instance" "ecnDetector" {
  provider                    = aws.singleregion
  ami                         = var.ami_image
  instance_type               = "t2.nano"
  vpc_security_group_ids      = ["${aws_security_group.default.id}"]
  subnet_id                   = "${aws_subnet.default.id}"
  associate_public_ip_address = true
  source_dest_check           = false
}
