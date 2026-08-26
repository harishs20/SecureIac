resource "aws_db_instance" "public_database" {
  identifier           = "secureiac-t07-public-db"
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password = var.db_password
  publicly_accessible  = true
  skip_final_snapshot  = true
}