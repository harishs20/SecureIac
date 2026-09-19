variable "environment" {
  type    = string
  default = "development"
}

locals {
  allow_public_access = var.environment != "production"
}

resource "aws_db_instance" "app_db" {
  identifier             = "c02-app-db"
  engine                 = "mysql"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = "admin"
  password               = "TestPassword123!"
  publicly_accessible    = local.allow_public_access
  skip_final_snapshot    = true
}
