resource "aws_vpc" "default" {
    provider = aws.singleregion
    enable_dns_support = true
    enable_dns_hostnames = true
    assign_generated_ipv6_cidr_block = true
    cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "default" {
    provider = aws.singleregion
    vpc_id = aws_vpc.default.id
    cidr_block = cidrsubnet(aws_vpc.default.cidr_block, 4, 1)
    map_public_ip_on_launch = true

    ipv6_cidr_block = cidrsubnet(aws_vpc.default.ipv6_cidr_block, 8, 1)
    assign_ipv6_address_on_creation = true
}


resource "aws_internet_gateway" "default" {
    provider = aws.singleregion
    vpc_id = aws_vpc.default.id
}

resource "aws_default_route_table" "default" {
    provider = aws.singleregion
    default_route_table_id = aws_vpc.default.default_route_table_id

    route {
        cidr_block = "0.0.0.0/0"
        gateway_id = aws_internet_gateway.default.id
    }

    route {
        ipv6_cidr_block = "::/0"
        gateway_id = aws_internet_gateway.default.id
    }
}

resource "aws_route_table_association" "default" {
    provider = aws.singleregion
    subnet_id      = aws_subnet.default.id
    route_table_id = aws_default_route_table.default.id
}

# Allow everything to the instances, will be fixed another time
resource "aws_security_group" "default" {
    provider = aws.singleregion
    name = "single-sec-group"
    vpc_id = aws_vpc.default.id
    ingress {
        from_port = 0
        to_port = 0
        protocol = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }

    ingress {
        from_port = 0
        to_port = 0
        protocol = "-1"
        ipv6_cidr_blocks = ["::/0"]
    }

    egress {
      from_port = 0
      to_port = 0
      protocol = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }

    egress {
      from_port = 0
      to_port = 0
      protocol = "-1"
      ipv6_cidr_blocks = ["::/0"]
    }
}