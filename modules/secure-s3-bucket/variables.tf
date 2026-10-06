variable "name" {
  description = "Globally unique bucket name."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.name)) && !can(regex("\\.\\.", var.name))
    error_message = "Bucket name must be 3-63 chars of lowercase letters, digits, dots and hyphens."
  }
}

variable "create_kms_key" {
  description = "Create a dedicated customer-managed KMS key (with rotation) for this bucket. Set false and pass kms_key_arn to use an existing key."
  type        = bool
  default     = true
}

variable "kms_key_arn" {
  description = "Existing customer-managed KMS key for default encryption. Required when create_kms_key = false, must be null otherwise."
  type        = string
  default     = null

  validation {
    condition     = var.create_kms_key ? var.kms_key_arn == null : can(regex("^arn:aws[a-z-]*:kms:", var.kms_key_arn))
    error_message = "Pass a KMS key ARN when create_kms_key = false, and leave kms_key_arn null when create_kms_key = true."
  }
}

variable "additional_policy_json" {
  description = "Extra bucket policy statements (JSON) merged with the module's TLS-only policy, e.g. a CloudTrail delivery grant."
  type        = string
  default     = null
}

variable "access_log_bucket" {
  description = "Target bucket for S3 server access logs. Null disables access logging."
  type        = string
  default     = null
}

variable "noncurrent_version_retention_days" {
  description = "Days to keep noncurrent object versions before expiry."
  type        = number
  default     = 90

  validation {
    condition     = var.noncurrent_version_retention_days >= 7
    error_message = "Keep noncurrent versions for at least 7 days so overwrites are recoverable."
  }
}

variable "force_destroy" {
  description = "Allow destroying a non-empty bucket. Keep false outside throwaway labs."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags applied to every resource in the module."
  type        = map(string)
  default     = {}
}
