resource "aws_ebs_volume" "unencrypted_volume" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = false

  tags = {
    Name = "secureiac-t06-unencrypted"
  }
}