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
  public_bucket_name    = "cloudarena-public-${random_id.bucket_suffix.hex}"
  kms_alias_name        = "alias/cloudarena-vulnerable-${random_id.bucket_suffix.hex}"
  ecr_repository_name   = "cloudarena-workshop-${random_id.bucket_suffix.hex}"
  iam_role_name         = "cloudarena-workshop-role-${random_id.bucket_suffix.hex}"
  iam_user_name         = "cloudarena-stale-user-${random_id.bucket_suffix.hex}"
}

data "aws_vpc" "default" {
  default = true
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

    actions = ["s3:PutObject"]
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

resource "aws_security_group" "open_admin" {
  name        = "cloudarena-open-admin-${random_id.bucket_suffix.hex}"
  description = "Deliberately open administrative access for CloudArena exercises"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "SSH from the internet"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "RDP from the internet"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Purpose  = "CloudArena"
    Exposure = "PublicIngress"
  }
}

resource "aws_s3_bucket" "public_objects" {
  bucket        = local.public_bucket_name
  force_destroy = true

  tags = {
    Purpose  = "CloudArena"
    Exposure = "PublicAccess"
  }
}

resource "aws_s3_bucket_public_access_block" "public_objects" {
  bucket = aws_s3_bucket.public_objects.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_ownership_controls" "public_objects" {
  bucket = aws_s3_bucket.public_objects.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "public_objects" {
  bucket = aws_s3_bucket.public_objects.id
  acl    = "public-read"

  depends_on = [
    aws_s3_bucket_public_access_block.public_objects,
    aws_s3_bucket_ownership_controls.public_objects,
  ]
}

data "aws_iam_policy_document" "public_bucket" {
  statement {
    sid    = "AllowPublicRead"
    effect = "Allow"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = [
      "s3:GetObject"
    ]

    resources = [
      "${aws_s3_bucket.public_objects.arn}/*"
    ]
  }
}

resource "aws_s3_bucket_policy" "public_objects" {
  bucket = aws_s3_bucket.public_objects.id
  policy = data.aws_iam_policy_document.public_bucket.json
}

resource "aws_s3_object" "public_sample" {
  bucket       = aws_s3_bucket.public_objects.id
  key          = "public/sample.txt"
  content      = "CloudArena sample object exposed publicly."
  content_type = "text/plain"

  depends_on = [
    aws_s3_bucket_acl.public_objects,
    aws_s3_bucket_policy.public_objects,
  ]
}

resource "aws_kms_key" "no_rotation" {
  description             = "CloudArena exercise key without rotation"
  enable_key_rotation     = false
  deletion_window_in_days = 7

  tags = {
    Purpose  = "CloudArena"
    Exposure = "RotationDisabled"
  }
}

resource "aws_kms_alias" "no_rotation" {
  name          = local.kms_alias_name
  target_key_id = aws_kms_key.no_rotation.key_id
}

resource "aws_ecr_repository" "workshop" {
  name                 = local.ecr_repository_name
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.no_rotation.arn
  }

  tags = {
    Purpose = "CloudArena"
  }
}

data "aws_iam_policy_document" "assume_ec2" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "workshop" {
  name               = local.iam_role_name
  assume_role_policy = data.aws_iam_policy_document.assume_ec2.json

  tags = {
    Purpose = "CloudArena"
  }
}

resource "aws_iam_role_policy" "workshop" {
  name = "cloudarena-workshop-policy"
  role = aws_iam_role.workshop.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:ListAllMyBuckets", "iam:ListRoles", "ecr:DescribeRepositories"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_user" "stale" {
  name          = local.iam_user_name
  force_destroy = true

  tags = {
    Purpose  = "CloudArena"
    Exposure = "StaleAccessKey"
  }
}

resource "aws_iam_access_key" "stale" {
  user   = aws_iam_user.stale.name
  status = "Active"
}
