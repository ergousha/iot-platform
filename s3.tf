# ---------------------------------------------------------------------------
# S3 Bucket for OTA Firmware Binaries
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "firmware" {
  bucket = "${var.project_name}-firmware-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_public_access_block" "firmware" {
  bucket                  = aws_s3_bucket.firmware.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "firmware" {
  bucket = aws_s3_bucket.firmware.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# ACLs off: the bucket owner owns every object, whatever the writer asks for.
resource "aws_s3_bucket_ownership_controls" "firmware" {
  bucket = aws_s3_bucket.firmware.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# An abandoned multipart upload is billed until aborted; firmware images are
# uploaded in seconds, so a day is generous.
resource "aws_s3_bucket_lifecycle_configuration" "firmware" {
  bucket = aws_s3_bucket.firmware.id

  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}
