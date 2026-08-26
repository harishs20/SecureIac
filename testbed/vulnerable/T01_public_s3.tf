resource "aws_s3_bucket" "public_bucket" {
  bucket = "secureiac-t01-public-bucket"

  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}