# Append-only audit store for the workload response runner
# (MIG-SPEC-001 §23.4, SEC-07, AT-37). Separate root on purpose: it adds an
# IAM role and a bucket, so it is applied only with the owner's approval.
#
# Object Lock in GOVERNANCE mode with a short default retention keeps every
# evidence version. The writer role can add and read objects but cannot
# remove a locked version, shorten retention, bypass the lock or change the
# bucket's lock, versioning or policy. After the retention ends the owner
# can clean up without any bypass.
terraform {
  required_version = ">= 1.15, < 2.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "= 6.67.0" }
  }
  backend "local" {}
}

variable "region" {
  type    = string
  default = "ap-northeast-2"
}
variable "account_id" { type = string }
variable "operator_arn" { type = string }
variable "run_id" {
  type = string
  validation {
    condition     = can(regex("^[a-z0-9]{6,12}$", var.run_id))
    error_message = "Use the source run ID."
  }
}
variable "expires_at" { type = string }
variable "retention_days" {
  type    = number
  default = 1
  validation {
    condition     = var.retention_days >= 1 && var.retention_days <= 30
    error_message = "Retention between 1 and 30 days."
  }
}

locals {
  name = "sova-response-${var.run_id}"
  tags = {
    Project   = "Sova"
    component = "sova-response-audit"
    RunId     = var.run_id
    ExpiresAt = var.expires_at
    ManagedBy = "Terraform"
  }
}

provider "aws" {
  region              = var.region
  allowed_account_ids = [var.account_id]
  default_tags { tags = local.tags }
}

resource "aws_s3_bucket" "audit" {
  bucket              = "${local.name}-audit-${substr(sha256(var.account_id), 0, 8)}"
  object_lock_enabled = true
  force_destroy       = true # Only after retention; the lock still applies.
}
resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_object_lock_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.retention_days
    }
  }
  depends_on = [aws_s3_bucket_versioning.audit]
}
resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}
resource "aws_s3_bucket_public_access_block" "audit" {
  bucket                  = aws_s3_bucket.audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_policy" "audit" {
  bucket = aws_s3_bucket.audit.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.audit.arn, "${aws_s3_bucket.audit.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
  depends_on = [aws_s3_bucket_public_access_block.audit]
}

resource "aws_iam_role" "writer" {
  name                 = "${local.name}-audit-writer"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { AWS = var.operator_arn }, Action = "sts:AssumeRole" }]
  })
}
resource "aws_iam_role_policy" "writer" {
  role = aws_iam_role.writer.id
  name = "append-and-read-only"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Append"
        Effect = "Allow"
        Action = [
          "s3:PutObject", "s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectRetention",
          "s3:ListBucket", "s3:ListBucketVersions", "s3:DeleteObject", "s3:DeleteObjectVersion",
        ]
        Resource = [aws_s3_bucket.audit.arn, "${aws_s3_bucket.audit.arn}/*"]
      },
      {
        # Deletes are allowed by IAM so the WORM check proves the lock itself
        # refuses them; weakening or bypassing the lock is never allowed.
        Sid    = "NoLockChanges"
        Effect = "Deny"
        Action = [
          "s3:BypassGovernanceRetention", "s3:PutObjectRetention", "s3:PutObjectLegalHold",
          "s3:PutBucketObjectLockConfiguration", "s3:PutBucketVersioning", "s3:PutBucketPolicy",
          "s3:DeleteBucket", "s3:DeleteBucketPolicy",
        ]
        Resource = [aws_s3_bucket.audit.arn, "${aws_s3_bucket.audit.arn}/*"]
      },
    ]
  })
}

output "audit_bucket" { value = aws_s3_bucket.audit.id }
output "audit_writer_role_arn" { value = aws_iam_role.writer.arn }
