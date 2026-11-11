# ===========================================================================
# OTA controller: the release pipeline and the claim lifecycle.
#
# A release workflow (iot-device-sdk firmware-release.yml) puts
# releases/<product>/<X.Y.Z>/{app.bin, factory.bin, manifest.json,
# manifest.sig} into the firmware bucket, manifest.sig last. The controller
# verifies the manifest against SSM /iot-platform/products/<product>/
# signing_keys, runs the release on the canaries, holds it for the soak,
# promotes it to the fleet, halts and emails. It runs on:
#
#   - a 15-minute schedule: the source of truth (a dropped event only delays);
#   - the S3 event of each manifest.sig: the same, for that product, at once;
#   - owner overrides: scripts/ota.sh (aws lambda invoke) or the AWS_IAM
#     Function URL (the portal, Phase 4).
#
# It also owns the claim certificate (iot.tf): ACTIVE only while an
# enrolment window is open, rotated after site windows, never in Terraform.
# Cost: $0 (Lambda, Scheduler, SNS within the free tier; IoT control-plane
# calls are free; a few shadow reads while a release is pending).
# ===========================================================================

locals {
  ota_controller_name = "${var.project_name}-ota-controller"

  claim_parameter_prefix = "/iot-platform/claim"
  signing_keys_parameter = "/iot-platform/products/{product}/signing_keys"

  firmware_download_url_template = coalesce(
    var.firmware_download_url_template,
    "https://${aws_cloudfront_distribution.firmware.domain_name}/{product}/{version}/app.bin",
  )

  product_group_arns = flatten([
    for id in keys(local.products) : [
      aws_iot_thing_group.fleet[id].arn,
      aws_iot_thing_group.canary[id].arn,
      aws_iot_thing_group.excluded[id].arn,
    ]
  ])
}

resource "terraform_data" "build_ota_controller" {
  triggers_replace = {
    source_hash = sha256(join("", concat(
      [for f in sort(fileset("${path.module}/lambda/ota_controller", "*.go")) : filesha256("${path.module}/lambda/ota_controller/${f}")],
      [filesha256("${path.module}/go.sum")],
    )))
  }

  provisioner "local-exec" {
    working_dir = path.module
    command     = "GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o lambda/ota_controller/bootstrap ./lambda/ota_controller"
  }
}

data "archive_file" "ota_controller_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda/ota_controller/bootstrap"
  output_path = "${path.module}/.build/ota_controller.zip"
  depends_on  = [terraform_data.build_ota_controller]
}

resource "aws_cloudwatch_log_group" "ota_controller" {
  name              = "/aws/lambda/${local.ota_controller_name}"
  retention_in_days = var.log_retention_days
}

# ---------------------------------------------------------------------------
# Owner email for the pipeline (canary, halt, promotion, claim rotation).
# Separate from the guard topic: that one invokes the kill switch, and these
# messages quote device-reported text. AWS sends a confirmation mail first.
# ---------------------------------------------------------------------------
resource "aws_sns_topic" "ota" {
  name = "${var.project_name}-ota"
}

resource "aws_sns_topic_subscription" "ota_email" {
  topic_arn = aws_sns_topic.ota.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ---------------------------------------------------------------------------
# Role.
# ---------------------------------------------------------------------------
resource "aws_iam_role" "ota_controller" {
  name               = "${local.ota_controller_name}-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "ota_controller" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.ota_controller.arn}:*"]
  }

  statement {
    sid       = "ListReleases"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.firmware.arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["releases/*"]
    }
  }

  statement {
    sid       = "ReadReleases"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.firmware.arn}/releases/*"]
  }

  statement {
    sid     = "ReadGuardAndSigningKeys"
    actions = ["ssm:GetParameter"]
    resources = [
      aws_ssm_parameter.guard_state.arn,
      "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/iot-platform/products/*/signing_keys",
    ]
  }

  # The claim's SecureStrings use the AWS managed aws/ssm key, whose key
  # policy allows its use through SSM to principals of this account.
  statement {
    sid       = "Claim"
    actions   = ["ssm:GetParameter", "ssm:PutParameter"]
    resources = ["arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter${local.claim_parameter_prefix}/*"]
  }

  statement {
    sid       = "Registry"
    actions   = ["dynamodb:Scan"]
    resources = [aws_dynamodb_table.device_registry.arn, aws_dynamodb_table.presence.arn]
  }

  statement {
    sid = "NoResourceLevelPermissions"
    actions = [
      "iot:ListJobs", "iot:ListCertificates", "iot:ListThings", "iot:CreateCertificateFromCsr",
    ]
    resources = ["*"]
  }

  # CreateJob is authorised against the job and every target.
  statement {
    sid     = "Jobs"
    actions = ["iot:CreateJob", "iot:CancelJob", "iot:ListJobExecutionsForJob", "iot:DescribeJobExecution", "iot:CancelJobExecution"]
    resources = concat(
      ["${local.iot_arn}:job/ota-*", "${local.iot_arn}:thing/*"],
      [for g in aws_iot_thing_group.fleet : g.arn],
      [for g in aws_iot_thing_group.canary : g.arn],
    )
  }

  statement {
    sid       = "FleetState"
    actions   = ["iot:DescribeThingGroup", "iot:UpdateThingGroup"]
    resources = [for g in aws_iot_thing_group.fleet : g.arn]
  }

  statement {
    sid       = "Membership"
    actions   = ["iot:ListThingsInThingGroup", "iot:UpdateThingGroupsForThing"]
    resources = concat(local.product_group_arns, ["${local.iot_arn}:thing/*"])
  }

  statement {
    sid       = "PlatformShadow"
    actions   = ["iot:GetThingShadow"]
    resources = ["${local.iot_arn}:thing/*"]
  }

  # The claim lifecycle and certificate hygiene. The code only ever touches
  # targets of the claim policy and certificates attached to no thing (or
  # superseded on a re-enrolled thing).
  statement {
    sid = "Certificates"
    actions = [
      "iot:ListTargetsForPolicy", "iot:AttachPolicy", "iot:DetachPolicy",
      "iot:DescribeCertificate", "iot:UpdateCertificate", "iot:DeleteCertificate",
      "iot:ListThingPrincipals", "iot:DetachThingPrincipal",
    ]
    resources = [
      aws_iot_policy.claim.arn,
      "${local.iot_arn}:cert/*",
      "${local.iot_arn}:thing/*",
    ]
  }

  statement {
    sid       = "Notify"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.ota.arn]
  }
}

resource "aws_iam_role_policy" "ota_controller" {
  name   = "${local.ota_controller_name}-policy"
  role   = aws_iam_role.ota_controller.id
  policy = data.aws_iam_policy_document.ota_controller.json
}

# ---------------------------------------------------------------------------
# Function.
# ---------------------------------------------------------------------------
resource "aws_lambda_function" "ota_controller" {
  function_name    = local.ota_controller_name
  role             = aws_iam_role.ota_controller.arn
  runtime          = "provided.al2023"
  handler          = "bootstrap"
  filename         = data.archive_file.ota_controller_zip.output_path
  source_code_hash = data.archive_file.ota_controller_zip.output_base64sha256

  memory_size = 128
  timeout     = 120

  # Every value is required: the Lambda refuses to start without one.
  environment {
    variables = {
      ACCOUNT_ID            = data.aws_caller_identity.current.account_id
      FIRMWARE_BUCKET       = aws_s3_bucket.firmware.bucket
      DOWNLOAD_URL_TEMPLATE = local.firmware_download_url_template
      PRODUCTS = jsonencode({
        for id, p in local.products : id => {
          fleet_group_arn    = aws_iot_thing_group.fleet[id].arn
          canary_group_arn   = aws_iot_thing_group.canary[id].arn
          excluded_group_arn = aws_iot_thing_group.excluded[id].arn
          repository         = p.github_repository
          soak_hours         = p.soak_hours
          legacy             = p.legacy
        }
      })
      REGISTRY_TABLE                   = aws_dynamodb_table.device_registry.name
      PRESENCE_TABLE                   = aws_dynamodb_table.presence.name
      GUARD_STATE_PARAMETER            = aws_ssm_parameter.guard_state.name
      SIGNING_KEYS_PARAMETER           = local.signing_keys_parameter
      CLAIM_POLICY                     = aws_iot_policy.claim.name
      CLAIM_CERT_PARAMETER             = "${local.claim_parameter_prefix}/cert"
      CLAIM_KEY_PARAMETER              = "${local.claim_parameter_prefix}/key"
      CLAIM_STATE_PARAMETER            = "${local.claim_parameter_prefix}/state"
      NOTIFY_TOPIC_ARN                 = aws_sns_topic.ota.arn
      IOT_DATA_ENDPOINT                = data.aws_iot_endpoint.ats.endpoint_address
      OTA_ROLLOUT_BASE_RATE_PER_MINUTE = var.ota_rollout_base_rate_per_minute
      OTA_ROLLOUT_INCREMENT_FACTOR     = var.ota_rollout_increment_factor
      OTA_ROLLOUT_SUCCEEDED_THINGS     = var.ota_rollout_succeeded_things
      OTA_ROLLOUT_MAX_PER_MINUTE       = var.ota_rollout_max_per_minute
      OTA_IN_PROGRESS_TIMEOUT_MINUTES  = var.ota_in_progress_timeout_minutes
    }
  }

  lifecycle {
    precondition {
      condition     = var.ota_rollout_base_rate_per_minute <= var.ota_rollout_max_per_minute
      error_message = "ota_rollout_base_rate_per_minute must not exceed ota_rollout_max_per_minute."
    }
  }

  # The policy first, so the code never runs without the permissions it calls.
  depends_on = [
    aws_cloudwatch_log_group.ota_controller,
    aws_iam_role_policy.ota_controller,
  ]
}

# Asynchronous invocations (the schedule, S3) retry once; a failure then goes
# to the owner. A missed tick is harmless: the next one redoes it.
resource "aws_lambda_function_event_invoke_config" "ota_controller" {
  function_name                = aws_lambda_function.ota_controller.function_name
  maximum_retry_attempts       = 1
  maximum_event_age_in_seconds = 900

  destination_config {
    on_failure {
      destination = aws_sns_topic.ota.arn
    }
  }
}

# Owner overrides for the portal (Phase 4 adds its CORS origin). AWS_IAM:
# only principals of this account with lambda:InvokeFunctionUrl get in, and
# a rejected request never runs the function.
resource "aws_lambda_function_url" "ota_controller" {
  function_name      = aws_lambda_function.ota_controller.function_name
  authorization_type = "AWS_IAM"
}

# ---------------------------------------------------------------------------
# Triggers.
# ---------------------------------------------------------------------------
resource "aws_lambda_permission" "ota_controller_s3" {
  statement_id   = "AllowFirmwareBucket"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.ota_controller.function_name
  principal      = "s3.amazonaws.com"
  source_arn     = aws_s3_bucket.firmware.arn
  source_account = data.aws_caller_identity.current.account_id
}

# Only the last object of a release; everything else in the bucket is quiet.
resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = aws_s3_bucket.firmware.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.ota_controller.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "releases/"
    filter_suffix       = "/manifest.sig"
  }

  depends_on = [aws_lambda_permission.ota_controller_s3]
}

resource "aws_iam_role" "ota_scheduler" {
  name = "${local.ota_controller_name}-scheduler-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "scheduler.amazonaws.com" }
      Condition = { StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id } }
    }]
  })
}

resource "aws_iam_role_policy" "ota_scheduler" {
  name = "${local.ota_controller_name}-scheduler-policy"
  role = aws_iam_role.ota_scheduler.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "lambda:InvokeFunction", Resource = aws_lambda_function.ota_controller.arn }]
  })
}

# On the quarter hour: the tick at :00 also does the hourly work (GitHub
# reconcile, certificate hygiene).
resource "aws_scheduler_schedule" "ota_tick" {
  name                         = "${local.ota_controller_name}-tick"
  schedule_expression          = "cron(0/15 * * * ? *)"
  schedule_expression_timezone = "UTC"

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = aws_lambda_function.ota_controller.arn
    role_arn = aws_iam_role.ota_scheduler.arn
    input    = jsonencode({ action = "tick" })

    retry_policy {
      maximum_retry_attempts = 0
    }
  }
}

output "ota_controller_function_url" {
  description = "AWS_IAM Function URL for owner overrides (the portal, Phase 4). scripts/ota.sh invokes the function directly."
  value       = aws_lambda_function_url.ota_controller.function_url
}
