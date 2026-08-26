resource "aws_s3_bucket" "unencrypted_bucket" {
  bucket = "secureiac-t02-unencrypted-bucket"

  versioning {
    enabled = true
  }
}