output "trail_bucket_name" {
  description = "Name of the S3 bucket receiving CloudTrail logs."
  value       = aws_s3_bucket.cloudtrail_trail.bucket
}

output "artifacts_bucket_name" {
  description = "Name of the S3 bucket storing CloudArena evidence artifacts."
  value       = aws_s3_bucket.artifacts.bucket
}
