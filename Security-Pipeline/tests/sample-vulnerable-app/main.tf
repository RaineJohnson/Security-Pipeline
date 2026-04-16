# ===========================================================================
# SAMPLE VULNERABLE TERRAFORM — FOR TESTING ONLY
# ===========================================================================
# Contains intentional misconfigurations to demonstrate what Checkov
# and tfsec catch. DO NOT deploy this infrastructure.
# ===========================================================================

provider "aws" {
  region = "us-west-2"
}

# VULN 1: S3 bucket without encryption
# Caught by: Checkov (CKV_AWS_19), tfsec (aws-s3-enable-bucket-encryption)
# Fix: Add server_side_encryption_configuration block
resource "aws_s3_bucket" "data_bucket" {
  bucket = "my-application-data"
  acl    = "public-read"  # VULN 2: Public read ACL — data exposure
  # Caught by: Checkov (CKV_AWS_20), tfsec (aws-s3-no-public-access)

  # VULN 3: No versioning — can't recover from accidental deletion
  # Caught by: Checkov (CKV_AWS_21)
}

# VULN 4: Security group with unrestricted SSH access
# Caught by: Checkov (CKV_AWS_24), tfsec (aws-vpc-no-public-ingress-sgr)
# Fix: Restrict to specific CIDR — cidr_blocks = ["10.0.0.0/8"]
resource "aws_security_group" "web_sg" {
  name        = "web-server-sg"
  description = "Security group for web servers"
  vpc_id      = "vpc-12345678"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # OPEN TO THE WORLD
  }

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # VULN 5: Unrestricted egress
  # Caught by: tfsec (aws-vpc-no-public-egress-sgr)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# VULN 6: RDS instance without encryption at rest
# Caught by: Checkov (CKV_AWS_16), tfsec (aws-rds-encrypt-instance-storage-data)
# Fix: storage_encrypted = true
resource "aws_db_instance" "production_db" {
  identifier           = "production-database"
  allocated_storage    = 100
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.medium"
  username             = "admin"
  password             = "hardcoded_password_123"  # VULN 7: Hardcoded password
  # Caught by: Checkov, tfsec, Gitleaks
  # Fix: Use aws_secretsmanager_secret or variable with sensitive = true

  publicly_accessible  = true   # VULN 8: DB accessible from internet
  # Caught by: Checkov (CKV_AWS_17), tfsec
  # Fix: publicly_accessible = false

  storage_encrypted    = false  # VULN 6: No encryption at rest

  skip_final_snapshot  = true
}

# VULN 9: IAM policy with wildcard actions
# Caught by: Checkov (CKV_AWS_1), tfsec (aws-iam-no-policy-wildcards)
# Fix: Specify exact actions needed — ["s3:GetObject", "s3:PutObject"]
resource "aws_iam_policy" "app_policy" {
  name        = "app-full-access"
  description = "Application policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# VULN 10: CloudWatch log group without encryption
# Caught by: Checkov (CKV_AWS_158)
# Fix: Add kms_key_id = aws_kms_key.log_key.arn
resource "aws_cloudwatch_log_group" "app_logs" {
  name              = "/app/production"
  retention_in_days = 0  # Logs retained forever — cost + compliance risk
}
