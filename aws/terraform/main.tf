terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

provider "aws" {
  region  = var.region
  profile = var.aws_profile
}

data "aws_caller_identity" "current" {}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

locals {
  trail_name            = "cloudarena-management"
  trail_bucket_name     = "cloudarena-trail-${random_id.bucket_suffix.hex}"
  artifacts_bucket_name = "cloudarena-artifacts-${random_id.bucket_suffix.hex}"
}

resource "aws_s3_bucket" "cloudtrail_trail" {
  bucket = local.trail_bucket_name
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_trail" {
  bucket = aws_s3_bucket.cloudtrail_trail.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "cloudtrail_trail" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail_trail.arn]
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.cloudtrail_trail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
    ]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_trail" {
  bucket = aws_s3_bucket.cloudtrail_trail.id
  policy = data.aws_iam_policy_document.cloudtrail_trail.json
}

resource "aws_s3_bucket" "artifacts" {
  bucket = local.artifacts_bucket_name
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_cloudtrail" "management" {
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.cloudtrail_trail.bucket
  is_multi_region_trail         = false
  enable_log_file_validation    = true
  include_global_service_events = true
  enable_logging                = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  depends_on = [
    aws_s3_bucket_policy.cloudtrail_trail
  ]
}
