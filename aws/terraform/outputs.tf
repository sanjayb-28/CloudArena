output "trail_bucket_name" {
  description = "Name of the S3 bucket receiving CloudTrail logs."
  value       = aws_s3_bucket.cloudtrail_trail.bucket
}

output "artifacts_bucket_name" {
  description = "Name of the S3 bucket storing CloudArena evidence artifacts."
  value       = aws_s3_bucket.artifacts.bucket
}

output "public_bucket_name" {
  description = "Publicly accessible S3 bucket seeded with vulnerable objects."
  value       = aws_s3_bucket.public_objects.bucket
}

output "open_admin_security_group_id" {
  description = "Security group exposing administrative ports to the internet."
  value       = aws_security_group.open_admin.id
}

output "vulnerable_kms_key_id" {
  description = "KMS key without automatic rotation enabled."
  value       = aws_kms_key.no_rotation.key_id
}

output "ecr_repository_name" {
  description = "Workshop ECR repository used for enumeration exercises."
  value       = aws_ecr_repository.workshop.name
}

output "stale_iam_user" {
  description = "IAM user configured with an access key for stale credential detection."
  value       = aws_iam_user.stale.name
}
