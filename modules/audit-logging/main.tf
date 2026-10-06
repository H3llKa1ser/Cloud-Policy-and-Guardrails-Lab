# Organisation audit trail: multi-region CloudTrail, integrity validation,
# KMS encryption, a hardened bucket and a CloudWatch Logs feed for
# detections. Satisfies every rule in policies/aws/logging.rego.

locals {
  trail_arn      = "arn:${var.partition}:cloudtrail:${var.region}:${var.account_id}:trail/${var.trail_name}"
  bucket_arn     = "arn:${var.partition}:s3:::${var.bucket_name}"
  log_group_name = "/aws/cloudtrail/${var.trail_name}"
  log_group_arn  = "arn:${var.partition}:logs:${var.region}:${var.account_id}:log-group:${local.log_group_name}"
  account_root   = "arn:${var.partition}:iam::${var.account_id}:root"
}

# --- KMS ---------------------------------------------------------------------

data "aws_iam_policy_document" "kms" {
  #checkov:skip=CKV_AWS_109:KMS key policies must use Resource "*" (it means "this key").
  #checkov:skip=CKV_AWS_111:KMS key policies must use Resource "*" (it means "this key").
  #checkov:skip=CKV_AWS_356:KMS key policies must use Resource "*" (it means "this key").
  statement {
    sid       = "AccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }
  }

  statement {
    sid       = "CloudTrailEncrypt"
    actions   = ["kms:GenerateDataKey*"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:${var.partition}:cloudtrail:*:${var.account_id}:trail/*"]
    }
  }

  statement {
    sid       = "CloudTrailDescribe"
    actions   = ["kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid = "CloudWatchLogsEncrypt"
    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*",
    ]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["logs.${var.region}.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = [local.log_group_arn]
    }
  }
}

resource "aws_kms_key" "this" {
  description             = "CloudTrail ${var.trail_name}: log files and CloudWatch Logs"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.kms.json
  tags                    = var.tags
}

resource "aws_kms_alias" "this" {
  name          = "alias/cloudtrail/${var.trail_name}"
  target_key_id = aws_kms_key.this.key_id
}

# --- S3 ----------------------------------------------------------------------

data "aws_iam_policy_document" "cloudtrail_delivery" {
  statement {
    sid       = "CloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [local.bucket_arn]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "CloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${local.bucket_arn}/AWSLogs/${var.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
}

module "bucket" {
  source = "../secure-s3-bucket"

  name                              = var.bucket_name
  create_kms_key                    = false
  kms_key_arn                       = aws_kms_key.this.arn
  additional_policy_json            = data.aws_iam_policy_document.cloudtrail_delivery.json
  noncurrent_version_retention_days = 365
  tags                              = var.tags
}

# --- CloudWatch Logs (feeds detections) ---------------------------------------

resource "aws_cloudwatch_log_group" "this" {
  name              = local.log_group_name
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.this.arn
  tags              = var.tags
}

data "aws_iam_policy_document" "cloudtrail_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
}

data "aws_iam_policy_document" "cloudtrail_to_logs" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.this.arn}:log-stream:*"]
  }
}

resource "aws_iam_role" "cloudtrail_to_logs" {
  name               = "${var.trail_name}-to-cloudwatch"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy" "cloudtrail_to_logs" {
  name   = "deliver-to-cloudwatch-logs"
  role   = aws_iam_role.cloudtrail_to_logs.id
  policy = data.aws_iam_policy_document.cloudtrail_to_logs.json
}

# --- Trail -------------------------------------------------------------------

resource "aws_cloudtrail" "this" {
  #checkov:skip=CKV_AWS_252:SNS delivery notifications are optional; detections consume CloudWatch Logs instead.
  name                          = var.trail_name
  s3_bucket_name                = module.bucket.bucket_id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.this.arn
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.this.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_to_logs.arn
  tags                          = var.tags

  depends_on = [module.bucket]
}
