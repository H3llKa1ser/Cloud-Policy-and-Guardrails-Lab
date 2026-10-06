terraform {
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

# Offline lab mode (default): `terraform plan` runs with dummy credentials
# and no API calls, so the whole guardrail pipeline works without an AWS
# account. Nothing in this stack uses data sources that call AWS.
# Set `offline = false` to plan against a real account.
provider "aws" {
  region = var.region

  access_key                  = var.offline ? "mock_access_key" : null
  secret_key                  = var.offline ? "mock_secret_key" : null
  skip_credentials_validation = var.offline
  skip_requesting_account_id  = var.offline
  skip_metadata_api_check     = var.offline

  default_tags {
    tags = {
      Owner              = "security-engineering"
      Environment        = "lab"
      DataClassification = "internal"
      Project            = "Cloud-Policy-and-Guardrails-Lab"
      ManagedBy          = "terraform"
    }
  }
}
