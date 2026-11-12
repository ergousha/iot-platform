# ===========================================================================
# Public, signed firmware over CloudFront.
#
# https://<distribution>/<product>/<X.Y.Z>/app.bin serves
# s3://<firmware bucket>/releases/<product>/<X.Y.Z>/app.bin through Origin
# Access Control: the bucket stays private, only this distribution may read
# releases/, and nothing else in the bucket is reachable. Images are public
# by design (no secrets; signed manifests), so there are no presigned URLs:
# a job document carries a stable URL, and a device's Range resume survives
# reboots.
#
# Cost: put the distribution on the CloudFront **Free flat-rate plan** right
# after the first apply (console: CloudFront > the distribution > Pricing
# plan). The plan never bills overage and includes WAF with a rate rule; the
# AWS provider cannot set it yet. Without it, pay-as-you-go applies past
# the always-free 1 TB and 10M requests a month: a download-flood risk. If
# the account is not eligible, set firmware_download_url_template
# to the GitHub Releases fallback and disable this distribution.
# ===========================================================================

data "aws_cloudfront_cache_policy" "caching_optimized" {
  name = "Managed-CachingOptimized"
}

resource "aws_cloudfront_origin_access_control" "firmware" {
  name                              = "${var.project_name}-firmware"
  description                       = "Firmware releases (releases/*) of ${aws_s3_bucket.firmware.id}"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_distribution" "firmware" {
  enabled         = true
  comment         = "${var.project_name} signed firmware releases"
  is_ipv6_enabled = true
  http_version    = "http2"
  price_class     = "PriceClass_100"

  origin {
    origin_id                = "firmware-releases"
    domain_name              = aws_s3_bucket.firmware.bucket_regional_domain_name
    origin_path              = "/releases"
    origin_access_control_id = aws_cloudfront_origin_access_control.firmware.id
  }

  default_cache_behavior {
    target_origin_id       = "firmware-releases"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    viewer_protocol_policy = "https-only"
    cache_policy_id        = data.aws_cloudfront_cache_policy.caching_optimized.id
    compress               = false # images do not compress, and Range needs the stored bytes
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  lifecycle {
    # The Free plan attaches its own WAF web ACL and may change the price
    # class; those are the plan's, not Terraform's.
    ignore_changes = [web_acl_id, price_class]
  }
}

data "aws_iam_policy_document" "firmware_bucket" {
  statement {
    sid       = "CloudFrontReadsReleases"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.firmware.arn}/releases/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.firmware.arn]
    }
  }

  statement {
    sid     = "TLSOnly"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.firmware.arn,
      "${aws_s3_bucket.firmware.arn}/*",
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "firmware" {
  bucket = aws_s3_bucket.firmware.id
  policy = data.aws_iam_policy_document.firmware_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.firmware]
}

output "firmware_base_url" {
  description = "Public base URL of the signed firmware: <base>/<product>/<X.Y.Z>/{app.bin,factory.bin,manifest.json,manifest.sig}."
  value       = "https://${aws_cloudfront_distribution.firmware.domain_name}"
}
