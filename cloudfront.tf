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
# Cost: both distributions (this one and the portal's) are on the CloudFront
# **Free flat-rate plan**, managed below (aws_pricingplanmanager_subscription).
# The plan bills no overage however far traffic passes its allowance (1M
# requests and 100 GB a month; delivery may be slowed instead), and covers
# the distribution's WAF web ACL. That is why the kill switch leaves
# CloudFront alone: a download flood cannot run up a bill while the plan is
# in place. What could is a distribution off the plan (pay-as-you-go past the
# always-free 1 TB and 10M requests a month), so the OTA controller checks
# every hour that each distribution is in an ACTIVE Free subscription, with
# no cancellation or downgrade pending, and emails if not.
#
# GitHub Releases is the fallback if the plan is ever unavailable: set
# firmware_download_url_template to
# https://github.com/{repository}/releases/download/v{version}/app.bin (the
# SDK's OTA client follows the redirect to GitHub's asset host and trusts it
# through the ESP-IDF certificate bundle). It is not the default: a release
# asset can be replaced on a re-run (the device would refuse the changed
# image, by its manifest hash, but the update fails), while S3 keeps each
# published release immutable (If-None-Match), and on the Free plan
# CloudFront costs nothing more.
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

  # Missing paths are cached too (as on the portal), so probing random URLs
  # barely reaches S3. A release is uploaded before its job exists, so no
  # device asks for an image that is not there yet.
  dynamic "custom_error_response" {
    for_each = toset([403, 404])
    content {
      error_code            = custom_error_response.value
      error_caching_min_ttl = 300
    }
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

# ---------------------------------------------------------------------------
# The Free flat-rate plan, one subscription per distribution: the
# distribution and the WAF web ACL the plan attached to it (CloudFront
# creates that web ACL; Terraform reads it from the distribution). Never
# destroyed by Terraform: cancelling puts the distribution back on
# pay-as-you-go. A distribution already on the plan (subscribed in the
# console) is imported once:
#   terraform import 'aws_pricingplanmanager_subscription.cloudfront["firmware"]' <subscription ARN>
# (aws pricing-plan-manager list-subscriptions lists them).
# ---------------------------------------------------------------------------
locals {
  cloudfront_distributions = {
    firmware = aws_cloudfront_distribution.firmware
    portal   = aws_cloudfront_distribution.portal
  }
}

resource "aws_pricingplanmanager_subscription" "cloudfront" {
  for_each = local.cloudfront_distributions

  plan_family   = "CloudFront"
  plan_tier     = "FREE"
  resource_arns = compact([each.value.arn, each.value.web_acl_id])

  lifecycle {
    prevent_destroy = true
  }
}

output "firmware_base_url" {
  description = "Public base URL of the signed firmware: <base>/<product>/<X.Y.Z>/{app.bin,factory.bin,manifest.json,manifest.sig}."
  value       = "https://${aws_cloudfront_distribution.firmware.domain_name}"
}
