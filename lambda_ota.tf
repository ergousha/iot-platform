# ---------------------------------------------------------------------------
# OTA Trigger Lambda (serverless, event-driven).
# ---------------------------------------------------------------------------
resource "terraform_data" "build_ota_trigger" {
  triggers_replace = {
    source_hash = sha256(join("", [
      filesha256("${path.module}/lambda/ota_trigger/main.go"),
    ]))
  }

  provisioner "local-exec" {
    command = "GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags='-s -w' -o ${path.module}/lambda/ota_trigger/bootstrap ${path.module}/lambda/ota_trigger/main.go"
  }
}

data "archive_file" "ota_trigger_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda/ota_trigger/bootstrap"
  output_path = "${path.module}/.build/ota_trigger.zip"
  depends_on  = [terraform_data.build_ota_trigger]
}

resource "aws_cloudwatch_log_group" "ota_trigger" {
  name              = "/aws/lambda/${var.project_name}-ota-trigger"
  retention_in_days = var.log_retention_days
}

resource "aws_iam_role" "ota_trigger" {
  name = "${var.project_name}-ota-trigger-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "ota_trigger" {
  name = "${var.project_name}-ota-trigger-policy"
  role = aws_iam_role.ota_trigger.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.ota_trigger.arn}:*"
      },
      {
        # CreateJob is authorised against the job being created AND every
        # target; the only target is the fleet thing group.
        Effect = "Allow"
        Action = "iot:CreateJob"
        Resource = [
          "${local.iot_arn}:job/ota-*",
          aws_iot_thing_group.fleet.arn,
        ]
      },
      {
        # A new release cancels the group's older OTA jobs.
        Effect   = "Allow"
        Action   = "iot:CancelJob"
        Resource = "${local.iot_arn}:job/ota-*"
      },
      {
        # ListJobs supports no resource-level permissions.
        Effect   = "Allow"
        Action   = "iot:ListJobs"
        Resource = "*"
      },
      {
        # The job's presignedUrlConfig hands AWS IoT the presign role.
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = aws_iam_role.ota_presign.arn
        Condition = {
          StringEquals = {
            "iam:PassedToService" = "iot.amazonaws.com"
          }
        }
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# Role AWS IoT Jobs assumes to presign the firmware download URL each time a
# device fetches its job document. A URL signed once at upload time would
# expire under a CONTINUOUS job, whose devices can join months later.
# ---------------------------------------------------------------------------
resource "aws_iam_role" "ota_presign" {
  name = "${var.project_name}-ota-presign-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "iot.amazonaws.com"
      }
      # Confused-deputy guard: only IoT jobs in this account.
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnLike = {
          "aws:SourceArn" = "${local.iot_arn}:job/*"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "ota_presign" {
  name = "${var.project_name}-ota-presign-policy"
  role = aws_iam_role.ota_presign.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:GetObject"
      Resource = "${aws_s3_bucket.firmware.arn}/*"
    }]
  })
}

resource "aws_lambda_function" "ota_trigger" {
  function_name    = "${var.project_name}-ota-trigger"
  role             = aws_iam_role.ota_trigger.arn
  runtime          = "provided.al2023"
  handler          = "bootstrap"
  filename         = data.archive_file.ota_trigger_zip.output_path
  source_code_hash = data.archive_file.ota_trigger_zip.output_base64sha256

  memory_size = 128
  timeout     = 30

  # The OTA_* settings are all required: the Lambda refuses to start if one is
  # missing or invalid.
  environment {
    variables = {
      S3_BUCKET_NAME                   = aws_s3_bucket.firmware.bucket
      OTA_THING_GROUP_ARN              = aws_iot_thing_group.fleet.arn
      OTA_PRESIGN_ROLE_ARN             = aws_iam_role.ota_presign.arn
      OTA_ROLLOUT_BASE_RATE_PER_MINUTE = var.ota_rollout_base_rate_per_minute
      OTA_ROLLOUT_INCREMENT_FACTOR     = var.ota_rollout_increment_factor
      OTA_ROLLOUT_SUCCEEDED_THINGS     = var.ota_rollout_succeeded_things
      OTA_ROLLOUT_MAX_PER_MINUTE       = var.ota_rollout_max_per_minute
      OTA_ABORT_FAILURE_PERCENTAGE     = var.ota_abort_failure_percentage
      OTA_ABORT_MIN_EXECUTED_THINGS    = var.ota_abort_min_executed_things
      OTA_IN_PROGRESS_TIMEOUT_MINUTES  = var.ota_in_progress_timeout_minutes
    }
  }

  lifecycle {
    # A variable validation cannot compare two variables on Terraform 1.5.
    precondition {
      condition     = var.ota_rollout_base_rate_per_minute <= var.ota_rollout_max_per_minute
      error_message = "ota_rollout_base_rate_per_minute must not exceed ota_rollout_max_per_minute."
    }
  }

  # The policy first, so the code never runs without the permissions it calls.
  depends_on = [
    aws_cloudwatch_log_group.ota_trigger,
    aws_iam_role_policy.ota_trigger,
  ]
}

resource "aws_lambda_permission" "allow_s3" {
  statement_id  = "AllowExecutionFromS3Bucket"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ota_trigger.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.firmware.arn
}

resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = aws_s3_bucket.firmware.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.ota_trigger.arn
    events              = ["s3:ObjectCreated:*"]
    filter_suffix       = ".bin"
  }

  depends_on = [aws_lambda_permission.allow_s3]
}
