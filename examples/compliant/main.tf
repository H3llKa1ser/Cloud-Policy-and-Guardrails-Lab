# A small, realistic stack that passes every guardrail: an audited account,
# a private VPC, an app instance and its data bucket. Almost all of the
# security comes from the reusable modules, which is the point: the secure
# path should also be the easy path.

# --- Account-level controls ---------------------------------------------------

resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

module "audit" {
  source = "../../modules/audit-logging"

  trail_name  = "${var.name_prefix}-audit"
  bucket_name = "${var.name_prefix}-${var.account_id}-audit-logs"
  account_id  = var.account_id
  region      = var.region
}

# --- Network ------------------------------------------------------------------

resource "aws_vpc" "this" {
  #checkov:skip=CKV2_AWS_11:VPC flow logs are left as a lab exercise (see README).
  cidr_block           = "10.40.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.name_prefix}-vpc" }
}

# Adopt the default security group and strip all of its rules.
resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id
}

resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = "10.40.1.0/24"
  map_public_ip_on_launch = false

  tags = { Name = "${var.name_prefix}-private" }
}

module "app_sg" {
  source = "../../modules/restricted-security-group"

  name        = "${var.name_prefix}-app"
  description = "App tier: HTTPS from the internet, SSH from VPN only"
  vpc_id      = aws_vpc.this.id

  ingress_rules = [
    {
      description = "HTTPS from internet"
      ip_protocol = "tcp"
      from_port   = 443
      to_port     = 443
      cidr_ipv4   = "0.0.0.0/0"
    },
    {
      description = "SSH from corporate VPN"
      ip_protocol = "tcp"
      from_port   = 22
      to_port     = 22
      cidr_ipv4   = var.vpn_cidr
    },
  ]
}

# --- Data ---------------------------------------------------------------------

module "app_data" {
  source = "../../modules/secure-s3-bucket"

  name = "${var.name_prefix}-${var.account_id}-app-data"
}

# --- Identity -----------------------------------------------------------------

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "app" {
  name               = "${var.name_prefix}-app"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

data "aws_iam_policy_document" "app" {
  statement {
    sid       = "ReadAppData"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [module.app_data.bucket_arn, "${module.app_data.bucket_arn}/*"]
  }

  statement {
    sid       = "DecryptAppData"
    actions   = ["kms:Decrypt"]
    resources = [module.app_data.kms_key_arn]
  }
}

resource "aws_iam_role_policy" "app" {
  name   = "read-app-data"
  role   = aws_iam_role.app.id
  policy = data.aws_iam_policy_document.app.json
}

resource "aws_iam_instance_profile" "app" {
  name = "${var.name_prefix}-app"
  role = aws_iam_role.app.name
}

# --- Compute ------------------------------------------------------------------

resource "aws_instance" "app" {
  ami                         = var.ami_id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.private.id
  vpc_security_group_ids      = [module.app_sg.security_group_id]
  iam_instance_profile        = aws_iam_instance_profile.app.name
  associate_public_ip_address = false
  monitoring                  = true
  ebs_optimized               = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  root_block_device {
    encrypted   = true
    volume_type = "gp3"
    volume_size = 20
  }

  tags = { Name = "${var.name_prefix}-app" }
}
