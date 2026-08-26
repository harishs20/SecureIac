resource "aws_iam_policy" "broad_policy" {
  name = "secureiac-t09-broad-policy"

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:DeleteBucket"
        Resource = "*"
      }
    ]
  })
}