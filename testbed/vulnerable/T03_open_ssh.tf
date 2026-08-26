resource "aws_security_group" "open_ssh" {
  name        = "secureiac-t03-open-ssh"
  description = "Security group with unrestricted SSH access"

  ingress {
    description = "Unrestricted SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow HTTPS outbound"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}