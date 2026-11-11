# ===========================================================================
# Device presence, for the OTA controller's canary choice and soak gate.
#
# AWS IoT publishes a lifecycle event on every connect and disconnect. A rule
# keeps the latest of each kind per thing: two items, keyed (thing, event).
# A thing is online when its latest connect is newer than its latest
# disconnect; versionNumber (`session`) orders them, since a disconnect of an
# old session can arrive after the next connect. Claim connections
# (claim-<MAC12>) are left out.
#
# Cost: one rule and one action per connect or disconnect ($0.15/M each) and
# one DynamoDB write (capped at 2 a second): fractions of a cent at this
# fleet's reconnect rate. The traffic scope of the kill switch disables the
# rule; the next `terraform apply` restores it.
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
  name        = replace("${var.project_name}_presence", "-", "_")
  description = "Lifecycle events -> ${aws_dynamodb_table.presence.name} (OTA controller)."
  enabled     = true
  sql_version = "2016-03-23"
  sql         = "SELECT clientId AS thing, eventType AS event, timestamp AS at, versionNumber AS session, principalIdentifier AS principal FROM '$aws/events/presence/+/+' WHERE NOT startswith(clientId, 'claim-')"

  dynamodbv2 {
    role_arn = aws_iam_role.presence_rule.arn
    put_item {
      table_name = aws_dynamodb_table.presence.name
    }
  }

  depends_on = [aws_iam_role_policy.presence_rule]
}
