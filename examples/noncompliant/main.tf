# DELIBERATELY INSECURE. DO NOT APPLY.
#
# Every resource here is a realistic misconfiguration, annotated with the
# rule(s) it should trip. `make verify` plans this stack and asserts that the
# guardrails report exactly the IDs in expected-violations.txt. If you add a
# policy, add a resource here that breaks it.

# --- S3 -------------------------------------------------------------------------

# S3_001 no public access block, S3_003 no encryption, S3_102 no versioning
resource "aws_s3_bucket" "public_reports" {
  bucket = "guardrails-lab-public-reports"
}

# S3_004 public canned ACL
resource "aws_s3_bucket_acl" "public_reports" {
  bucket = aws_s3_bucket.public_reports.id
  acl    = "public-read"
}

# S3_102 no versioning
resource "aws_s3_bucket" "backups" {
  bucket = "guardrails-lab-backups"
}

# S3_002 a public access block with a hole in it
resource "aws_s3_bucket_public_access_block" "backups" {
  bucket                  = aws_s3_bucket.backups.id
  block_public_acls       = true
  block_public_policy     = false
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3_101 (advisory) SSE-S3 instead of KMS
resource "aws_s3_bucket_server_side_encryption_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# --- Network ---------------------------------------------------------------------

resource "aws_vpc" "legacy" {
  cidr_block = "10.99.0.0/16"
}

# NET_003 default SG left permissive
resource "aws_default_security_group" "legacy" {
  vpc_id = aws_vpc.legacy.id

  ingress {
    protocol  = "-1"
    from_port = 0
    to_port   = 0
    self      = true
  }
}

# NET_001 SSH to the world; NET_002 everything over IPv6
resource "aws_security_group" "legacy_admin" {
  name        = "legacy-admin"
  description = "Temporary, do not merge"
  vpc_id      = aws_vpc.legacy.id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description      = "Debugging"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    ipv6_cidr_blocks = ["::/0"]
  }
}

# NET_001 database port to the world
resource "aws_vpc_security_group_ingress_rule" "postgres_public" {
  security_group_id = aws_security_group.legacy_admin.id
  description       = "Postgres for the BI vendor"
  ip_protocol       = "tcp"
  from_port         = 5432
  to_port           = 5432
  cidr_ipv4         = "0.0.0.0/0"
}

# --- Compute ---------------------------------------------------------------------

# CMP_001 IMDSv1, CMP_002 unencrypted root, CMP_101 (advisory) public IP
resource "aws_instance" "jumpbox" {
  ami                         = "ami-0123456789abcdef0"
  instance_type               = "t3.micro"
  associate_public_ip_address = true

  metadata_options {
    http_tokens = "optional"
  }
}

# CMP_003 unencrypted volume
resource "aws_ebs_volume" "scratch" {
  availability_zone = "eu-west-1a"
  size              = 50
}

# --- Data stores -----------------------------------------------------------------

# DATA_001 unencrypted, DATA_002 public
resource "aws_db_instance" "reporting" {
  identifier                  = "reporting"
  engine                      = "postgres"
  instance_class              = "db.t4g.micro"
  allocated_storage           = 20
  username                    = "reporting_admin"
  manage_master_user_password = true
  publicly_accessible         = true
  storage_encrypted           = false
  skip_final_snapshot         = true
}

# DATA_003 no key rotation
resource "aws_kms_key" "legacy" {
  description         = "Legacy app key"
  enable_key_rotation = false
}

# --- IAM ---------------------------------------------------------------------------

# IAM_001 full admin by wildcard
resource "aws_iam_policy" "god_mode" {
  name = "god-mode"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}

# IAM_002 kms:* on everything; IAM_103 (advisory) Allow + NotAction
resource "aws_iam_policy" "ops_helper" {
  name = "ops-helper"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["kms:*"], Resource = "*" },
      { Effect = "Allow", NotAction = ["iam:*"], Resource = "*" },
    ]
  })
}

# IAM_004 anyone in any AWS account can assume this role
resource "aws_iam_role" "vendor_access" {
  name = "vendor-access"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { AWS = "*" }, Action = "sts:AssumeRole" }]
  })
}

# IAM_003 AWS-managed admin policy
resource "aws_iam_role_policy_attachment" "vendor_admin" {
  role       = aws_iam_role.vendor_access.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_user" "ci_bot" {
  name = "ci-bot"
}

# IAM_101 (advisory) long-lived key
resource "aws_iam_access_key" "ci_bot" {
  user = aws_iam_user.ci_bot.name
}

# IAM_102 (advisory) permissions on a user
resource "aws_iam_user_policy_attachment" "ci_bot" {
  user       = aws_iam_user.ci_bot.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# --- Logging -----------------------------------------------------------------------

# LOG_001 single region, LOG_002 no validation, LOG_003 no KMS, LOG_004 no IAM events
resource "aws_cloudtrail" "minimal" {
  name                          = "minimal"
  s3_bucket_name                = aws_s3_bucket.backups.id
  is_multi_region_trail         = false
  include_global_service_events = false
  enable_log_file_validation    = false
}

# LOG_101/LOG_102 (advisory) no retention, no KMS; TAG_101 (advisory) untagged
resource "aws_cloudwatch_log_group" "app" {
  provider = aws.untagged
  name     = "/legacy/app"
}

# --- Tagging -----------------------------------------------------------------------

# TAG_001 / TAG_002 values outside the allowed vocabularies
resource "aws_sns_topic" "alerts" {
  name = "legacy-alerts"
  tags = {
    DataClassification = "top-secret"
    Environment        = "production"
  }
}
