# ===========================================================================
# Guard rails: alarms and budgets -> SNS -> email + kill switch.
#
# Denial-of-wallet is the platform's main threat. Free CloudWatch alarms
# (thresholds 20x or more above the measured baseline) and two budgets publish
# to one SNS topic. The topic emails the owner and invokes the kill switch,
# which acts by scope:
#   provisioning  claim certificate INACTIVE
#   traffic       + killable IoT rules disabled
#   fleet         + deny-all policy on every fleet group (devices go offline)
# scripts/guard-reset.sh undoes a trip. Cost: $0 (8 of the 10 free alarm
# metrics, budgets without actions, Lambda and SNS inside the free tier).
#
# Limits worth knowing: the publish alarms count messages, not bytes (AWS/IoT
# has no inbound-bytes metric, and Device Defender is not available), so a
# flood of large messages just under the threshold is bounded by the budgets
# alone, hours later. And an ACTUAL budget alert fires once per month, so each
# budget also re-alerts at 150 % in case the guard was reset that month.
# ===========================================================================

locals {
  guard_prefix = "${var.project_name}-guard"

  # Alarm name -> kill-switch scope. "notify" only emails.
  guard_alarm_scopes = {
    "${local.guard_prefix}-publish-5m"         = "traffic"
    "${local.guard_prefix}-publish-30m"        = "fleet"
    "${local.guard_prefix}-connect-5m"         = "provisioning"
    "${local.guard_prefix}-hook-5m"            = "provisioning"
    "${local.guard_prefix}-ota-errors"         = "notify"
    "${local.guard_prefix}-kill-switch-errors" = "notify"
  }

  # Budget name -> kill-switch scope. Neither name contains the other: the
  # kill switch matches them in the budget notification text.
  guard_budget_scopes = {
    "${local.guard_prefix}-traffic" = "traffic"
    "${local.guard_prefix}-fleet"   = "fleet"
  }

  # Rules the traffic scope disables. Their per-message cost (rule, action,
  # Logs ingestion) is what an attacker with a device certificate could drive.
  guard_killable_rules = [
    aws_iot_topic_rule.telemetry_to_logs.name,
    aws_iot_topic_rule.opcua_telemetry_to_logs.name,
    aws_iot_topic_rule.presence.name,
  ]

  # The killable rules Terraform keeps enabled: what a guard reset through
  # the OTA controller (the portal) re-enables. guard-reset.sh leaves this
  # to the next apply.
  guard_restore_rules = concat(
    [aws_iot_topic_rule.presence.name],
    var.debug_telemetry_logs ? [aws_iot_topic_rule.telemetry_to_logs.name, aws_iot_topic_rule.opcua_telemetry_to_logs.name] : [],
  )

  # Every group whose devices the fleet scope cuts off. Canary groups inherit
  # from their fleet group; excluded groups are outside that hierarchy.
  guard_fleet_group_arns = concat(
    [for g in aws_iot_thing_group.fleet : g.arn],
    [for g in aws_iot_thing_group.excluded : g.arn],
  )

  # Publishes over MQTT and HTTPS together: a device certificate works for both.
  guard_publish_metrics = {
    mqtt = "MQTT"
    http = "HTTP"
  }
}

# ---------------------------------------------------------------------------
# SNS topic. Only this account's guard alarms and budgets may publish (plus
# principals of this account, through their own IAM policies).
# ---------------------------------------------------------------------------
resource "aws_sns_topic" "guard" {
  name = local.guard_prefix
}

data "aws_iam_policy_document" "guard_topic" {
  statement {
    sid = "AccountOwner"
    actions = [
      "sns:GetTopicAttributes", "sns:SetTopicAttributes", "sns:AddPermission", "sns:RemovePermission",
      "sns:DeleteTopic", "sns:Subscribe", "sns:ListSubscriptionsByTopic", "sns:Publish",
    ]
    resources = [aws_sns_topic.guard.arn]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid       = "GuardAlarms"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.guard.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudwatch:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:alarm:${local.guard_prefix}-*"]
    }
  }

  statement {
    sid       = "GuardBudgets"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.guard.arn]
    principals {
      type        = "Service"
      identifiers = ["budgets.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:budgets::${data.aws_caller_identity.current.account_id}:*"]
    }
  }
}

resource "aws_sns_topic_policy" "guard" {
  arn    = aws_sns_topic.guard.arn
  policy = data.aws_iam_policy_document.guard_topic.json
}

# Email the owner. AWS sends a confirmation mail first; nothing arrives until
# the link in it is clicked.
resource "aws_sns_topic_subscription" "guard_email" {
  topic_arn = aws_sns_topic.guard.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ---------------------------------------------------------------------------
# Deny-all policy. The kill switch attaches it to the fleet groups (fleet
# scope); it is permanently attached to the quarantine group, the manual tool
# to cut off one device: aws iot add-thing-to-thing-group --thing-name <thing>
# --thing-group-name esp32-ztp-quarantine. An explicit Deny beats every Allow.
# ---------------------------------------------------------------------------
resource "aws_iot_policy" "guard_deny_all" {
  name = "${local.guard_prefix}-deny-all"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Deny", Action = "iot:*", Resource = "*" }]
  })
}

resource "aws_iot_thing_group" "quarantine" {
  name = "${var.project_name}-quarantine"

  properties {
    description = "Devices cut off from AWS IoT: the deny-all policy is attached to this group."
  }
}

resource "aws_iot_policy_attachment" "quarantine" {
  policy = aws_iot_policy.guard_deny_all.name
  target = aws_iot_thing_group.quarantine.arn
}

# ---------------------------------------------------------------------------
# Guard state, written by the kill switch and cleared by guard-reset.sh.
# Terraform only creates it: a trip must survive an apply.
# ---------------------------------------------------------------------------
resource "aws_ssm_parameter" "guard_state" {
  name        = "/${var.project_name}/guard/state"
  type        = "String"
  value       = jsonencode({ tripped = false })
  description = "Kill-switch state: tripped, scope, since, reasons. Cleared by scripts/guard-reset.sh."

  lifecycle {
    ignore_changes = [value]
  }
}

# ---------------------------------------------------------------------------
# Kill switch Lambda.
# ---------------------------------------------------------------------------
resource "terraform_data" "build_kill_switch" {
  triggers_replace = {
    source_hash = filesha256("${path.module}/lambda/kill_switch/main.go")
  }

  provisioner "local-exec" {
    command = "GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags='-s -w' -o ${path.module}/lambda/kill_switch/bootstrap ${path.module}/lambda/kill_switch/main.go"
  }
}

data "archive_file" "kill_switch_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda/kill_switch/bootstrap"
  output_path = "${path.module}/.build/kill_switch.zip"
  depends_on  = [terraform_data.build_kill_switch]
}

resource "aws_cloudwatch_log_group" "kill_switch" {
  name              = "/aws/lambda/${local.guard_prefix}-kill-switch"
  retention_in_days = var.log_retention_days
}

resource "aws_iam_role" "kill_switch" {
  name = "${local.guard_prefix}-kill-switch-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "kill_switch" {
  name = "${local.guard_prefix}-kill-switch-policy"
  role = aws_iam_role.kill_switch.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.kill_switch.arn}:*"
      },
      {
        # The claim is whatever the claim policy is attached to (the OTA
        # controller rotates it); the code only ever sets INACTIVE.
        Effect   = "Allow"
        Action   = "iot:ListTargetsForPolicy"
        Resource = aws_iot_policy.claim.arn
      },
      {
        Effect   = "Allow"
        Action   = "iot:UpdateCertificate"
        Resource = "${local.iot_arn}:cert/*"
      },
      {
        Effect   = "Allow"
        Action   = "iot:DisableTopicRule"
        Resource = [for r in local.guard_killable_rules : "${local.iot_arn}:rule/${r}"]
      },
      {
        # AttachPolicy is authorised against the target; only the fleet and
        # excluded groups, and only this one policy can be attached (the API
        # call names it, and the role cannot create policies).
        Effect   = "Allow"
        Action   = "iot:AttachPolicy"
        Resource = concat(local.guard_fleet_group_arns, [aws_iot_policy.guard_deny_all.arn])
      },
      {
        Effect   = "Allow"
        Action   = ["ssm:GetParameter", "ssm:PutParameter"]
        Resource = aws_ssm_parameter.guard_state.arn
      },
    ]
  })
}

resource "aws_lambda_function" "kill_switch" {
  function_name    = "${local.guard_prefix}-kill-switch"
  role             = aws_iam_role.kill_switch.arn
  runtime          = "provided.al2023"
  handler          = "bootstrap"
  filename         = data.archive_file.kill_switch_zip.output_path
  source_code_hash = data.archive_file.kill_switch_zip.output_base64sha256

  memory_size = 128
  timeout     = 30

  environment {
    variables = {
      ALARM_SCOPES          = jsonencode(local.guard_alarm_scopes)
      BUDGET_SCOPES         = jsonencode(local.guard_budget_scopes)
      CLAIM_POLICY          = aws_iot_policy.claim.name
      KILLABLE_RULES        = jsonencode(local.guard_killable_rules)
      DENY_POLICY           = aws_iot_policy.guard_deny_all.name
      FLEET_GROUP_ARNS      = jsonencode(local.guard_fleet_group_arns)
      GUARD_STATE_PARAMETER = aws_ssm_parameter.guard_state.name
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.kill_switch,
    aws_iam_role_policy.kill_switch,
  ]
}

resource "aws_lambda_permission" "kill_switch_sns" {
  statement_id  = "AllowGuardTopic"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.kill_switch.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.guard.arn
}

resource "aws_sns_topic_subscription" "kill_switch" {
  topic_arn  = aws_sns_topic.guard.arn
  protocol   = "lambda"
  endpoint   = aws_lambda_function.kill_switch.arn
  depends_on = [aws_lambda_permission.kill_switch_sns]
}

# ---------------------------------------------------------------------------
# Alarms. Measured baseline (Nov 2026, 2 devices): at most 48 publishes and 4
# connects per 5 minutes. Missing data (an idle fleet) is not a breach.
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_metric_alarm" "publish" {
  for_each = {
    "${local.guard_prefix}-publish-5m"  = 1 # one breaching 5-minute period: traffic scope
    "${local.guard_prefix}-publish-30m" = 6 # six in a row, 30 minutes: fleet scope
  }

  alarm_name          = each.key
  alarm_description   = "IoT publishes (MQTT + HTTPS) above ${var.guard_publish_per_5min} per 5 min for ${each.value * 5} min. Kill-switch scope: ${local.guard_alarm_scopes[each.key]}."
  comparison_operator = "GreaterThanThreshold"
  threshold           = var.guard_publish_per_5min
  evaluation_periods  = each.value
  datapoints_to_alarm = each.value
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.guard.arn]
  ok_actions          = [aws_sns_topic.guard.arn]

  metric_query {
    id          = "total"
    expression  = "FILL(mqtt, 0) + FILL(http, 0)"
    label       = "PublishIn.Success, all protocols"
    return_data = true
  }

  dynamic "metric_query" {
    for_each = local.guard_publish_metrics
    content {
      id = metric_query.key
      metric {
        namespace   = "AWS/IoT"
        metric_name = "PublishIn.Success"
        dimensions  = { Protocol = metric_query.value }
        period      = 300
        stat        = "Sum"
      }
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "connect" {
  alarm_name          = "${local.guard_prefix}-connect-5m"
  alarm_description   = "IoT MQTT connects above ${var.guard_connect_per_5min} per 5 min. Kill-switch scope: provisioning."
  namespace           = "AWS/IoT"
  metric_name         = "Connect.Success"
  dimensions          = { Protocol = "MQTT" }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  comparison_operator = "GreaterThanThreshold"
  threshold           = var.guard_connect_per_5min
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.guard.arn]
  ok_actions          = [aws_sns_topic.guard.arn]
}

resource "aws_cloudwatch_metric_alarm" "hook" {
  alarm_name          = "${local.guard_prefix}-hook-5m"
  alarm_description   = "Pre-provisioning hook invocations above ${var.guard_hook_per_5min} per 5 min. Kill-switch scope: provisioning."
  namespace           = "AWS/Lambda"
  metric_name         = "Invocations"
  dimensions          = { FunctionName = aws_lambda_function.pre_provisioning_hook.function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  comparison_operator = "GreaterThanThreshold"
  threshold           = var.guard_hook_per_5min
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.guard.arn]
  ok_actions          = [aws_sns_topic.guard.arn]
}

resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  for_each = {
    "${local.guard_prefix}-ota-errors"         = aws_lambda_function.ota_controller.function_name
    "${local.guard_prefix}-kill-switch-errors" = aws_lambda_function.kill_switch.function_name
  }

  alarm_name          = each.key
  alarm_description   = "Lambda ${each.value} failed. Email only."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = each.value }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.guard.arn]
}

# ---------------------------------------------------------------------------
# Budgets: the backstop (billing data lags hours). No budget actions, so free.
# ---------------------------------------------------------------------------
resource "aws_budgets_budget" "guard" {
  for_each = {
    "${local.guard_prefix}-traffic" = var.guard_budget_traffic_usd
    "${local.guard_prefix}-fleet"   = var.guard_budget_fleet_usd
  }

  name         = each.key
  budget_type  = "COST"
  limit_amount = tostring(each.value)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  # Over the limit: the kill switch (and the topic's email). ACTUAL alerts fire
  # once per month each, so 150 % re-arms the kill switch after a reset.
  dynamic "notification" {
    for_each = toset([100, 150])
    content {
      comparison_operator       = "GREATER_THAN"
      threshold                 = notification.value
      threshold_type            = "PERCENTAGE"
      notification_type         = "ACTUAL"
      subscriber_sns_topic_arns = [aws_sns_topic.guard.arn]
    }
  }

  # Early warnings by email only, on the lower budget.
  dynamic "notification" {
    for_each = each.key == "${local.guard_prefix}-traffic" ? {
      ACTUAL     = 50
      FORECASTED = 100
    } : {}
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value
      threshold_type             = "PERCENTAGE"
      notification_type          = notification.key
      subscriber_email_addresses = [var.alert_email]
    }
  }

  depends_on = [aws_sns_topic_policy.guard]
}
