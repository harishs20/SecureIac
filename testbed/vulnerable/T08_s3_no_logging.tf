resource "aws_s3_bucket" "no_logging_bucket" {
  bucket = "secureiac-t08-no-logging"

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