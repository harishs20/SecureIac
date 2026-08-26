resource "aws_ebs_volume" "secure_volume" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = true

  tags = {
    Name = "secureiac-s01-secure"
  }
}