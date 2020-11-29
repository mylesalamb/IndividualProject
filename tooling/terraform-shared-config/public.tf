resource "aws_instance" "ecnDetector" {
    provider = "aws.singleregion"
    ami = "foobar todo"
    instance_type = "t2.nano"
}