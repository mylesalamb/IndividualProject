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
  key_name                    = var.aws_key_name
  instance_type               = "t2.medium"
  vpc_security_group_ids      = [aws_security_group.default.id]
  subnet_id                   = aws_subnet.default.id
  associate_public_ip_address = true
  source_dest_check           = false
  provisioner "remote-exec" {
    inline = [
      "echo \"AWS_REGION=${var.region}\" >> /home/ubuntu/.bashrc"
    ]
    connection {
      type = "ssh"
      user = "ubuntu"
      host = self.public_ip
      private_key = file("~/masterKey.pem")
    }
  }
}



output "instance_ip" {
  description = "Public ip addr"
  value = aws_instance.ecnDetector.public_ip
}
