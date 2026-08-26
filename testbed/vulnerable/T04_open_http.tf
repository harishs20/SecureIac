resource "aws_security_group" "open_http" {
  name        = "secureiac-t04-open-http"
  description = "Security group with unrestricted HTTP access"

  ingress {
    description = "Unrestricted HTTP"
    from_port   = 80
    to_port     = 80
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