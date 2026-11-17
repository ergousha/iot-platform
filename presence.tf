# ===========================================================================
# Device presence, for the OTA controller's canary choice and soak gate.
#
# AWS IoT publishes a lifecycle event on every connect and disconnect. Two
# rules, one per event type, keep the latest of each kind per thing: two
# items, keyed (thing, event). A thing is online when its latest connect is
# newer than its latest disconnect (the OTA controller and the portal compare
# timestamps, and versionNumber, `session`, only for events close together;
# AWS restarts it after about an hour offline). Claim connections
# (claim-<MAC12>) are left out.
#
# Only connected/+ and disconnected/+: `+/+` would also match
# connect_failed/<client id>, which any TLS-valid certificate produces with
# any client id it likes (a refused Connect), so it could write rows for
# made-up things and fill the table the controller scans. A connected or
# disconnected event exists only after Connect passed, and Connect demands
# client id = thing name.
#
# Cost: one rule and one action per connect or disconnect ($0.15/M each) and
# one DynamoDB write (capped at 2 a second): fractions of a cent at this
# fleet's reconnect rate. The traffic scope of the kill switch disables both
# rules; a reset (the portal) or the next `terraform apply` restores them.
# ===========================================================================

resource "aws_dynamodb_table" "presence" {
  name         = "${var.project_name}-device-presence"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "thing"
  range_key    = "event"

  attribute {
    name = "thing"
    type = "S"
  }

  attribute {
    name = "event"
    type = "S"
  }

  on_demand_throughput {
    max_read_request_units  = 2
    max_write_request_units = 2
  }

  server_side_encryption {
    enabled = true
  }
}

locals {
  # Lifecycle event type -> rule name.
  presence_rules = {
    for event in ["connected", "disconnected"] : event => replace("${var.project_name}_presence_${event}", "-", "_")
  }
}

# The trust policy of the presence rules' role. Confused-deputy guard: IoT
# may assume it only for this account's presence rules. The ARNs are built as
# strings: the rule resources reference this role.
data "aws_iam_policy_document" "iot_rule_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["iot.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [for name in values(local.presence_rules) : "arn:aws:iot:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:rule/${name}"]
    }
  }
}

resource "aws_iam_role" "presence_rule" {
  name               = "${var.project_name}-presence-rule-role"
  assume_role_policy = data.aws_iam_policy_document.iot_rule_assume.json
}

resource "aws_iam_role_policy" "presence_rule" {
  name = "${var.project_name}-presence-rule-policy"
  role = aws_iam_role.presence_rule.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "dynamodb:PutItem", Resource = aws_dynamodb_table.presence.arn }]
  })
}

resource "aws_iot_topic_rule" "presence" {
  for_each = local.presence_rules

  name        = each.value
  description = "Lifecycle ${each.key} events -> ${aws_dynamodb_table.presence.name} (OTA controller)."
  enabled     = true
  sql_version = "2016-03-23"
  sql         = "SELECT clientId AS thing, eventType AS event, timestamp AS at, versionNumber AS session, principalIdentifier AS principal FROM '$aws/events/presence/${each.key}/+' WHERE NOT startswith(clientId, 'claim-')"

  dynamodbv2 {
    role_arn = aws_iam_role.presence_rule.arn
    put_item {
      table_name = aws_dynamodb_table.presence.name
    }
  }

  depends_on = [aws_iam_role_policy.presence_rule]
}
