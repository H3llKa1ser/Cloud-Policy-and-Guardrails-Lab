variable "trail_name" {
  description = "CloudTrail trail name."
  type        = string
  default     = "organisation-audit"
}

variable "bucket_name" {
  description = "Name for the trail's log bucket (globally unique)."
  type        = string
}

variable "account_id" {
  description = "AWS account ID that owns the trail. Passed in rather than looked up so the lab can plan offline."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "region" {
  description = "Home region of the trail."
  type        = string
}

variable "partition" {
  description = "AWS partition (aws, aws-us-gov, aws-cn)."
  type        = string
  default     = "aws"
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the trail's log group."
  type        = number
  default     = 365

  validation {
    condition     = contains([90, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "Choose a CloudWatch retention value of at least 90 days."
  }
}

variable "tags" {
  description = "Tags applied to every resource in the module."
  type        = map(string)
  default     = {}
}
