# ===========================================================================
# AWS IoT Core - Fleet Provisioning by Claim
# ===========================================================================

# ---------------------------------------------------------------------------
# 1) CLAIM (bootstrap) certificate.
#    COMMON certificate carried by all devices leaving the factory.
#    Can only access provisioning MQTT topics; cannot send telemetry.
#    active=true + no csr => AWS generates a keypair, private_key is returned in outputs.
# ---------------------------------------------------------------------------
resource "aws_iot_certificate" "claim" {
  active = true
}

resource "aws_iot_policy" "claim" {
  name = "${var.project_name}-claim-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Connect"
        Effect   = "Allow"
        Action   = "iot:Connect"
        Resource = "arn:aws:iot:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:client/*"
      },
      {
        Sid    = "CreateKeysAndCertificate"
        Effect = "Allow"
        Action = ["iot:Publish", "iot:Receive"]
        Resource = [
          "arn:aws:iot:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:topic/$aws/certificates/create/*",
          "arn:aws:iot:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:topic/$aws/provisioning-templates/${var.provisioning_template_name}/provision/*",
        ]
      },
      {
        Sid    = "SubscribeProvisioningResponses"
        Effect = "Allow"
        Action = "iot:Subscribe"
        Resource = [
          "arn:aws:iot:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:topicfilter/$aws/certificates/create/*",
          "arn:aws:iot:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:topicfilter/$aws/provisioning-templates/${var.provisioning_template_name}/provision/*",
        ]
      },
    ]
  })
}

resource "aws_iot_policy_attachment" "claim" {
  policy = aws_iot_policy.claim.name
  target = aws_iot_certificate.claim.arn
}

# ---------------------------------------------------------------------------
# 2) DEVICE policy.
#    Provisioning template binds this to each device's unique certificate.
#    Using policy variables, each device can only access its OWN topics.
# ---------------------------------------------------------------------------
locals {
  # An IoT policy document has a HARD 2048-byte limit, and every ARN below
  # repeats this 38-character prefix. Spelling each statement out per topic (as
  # this policy originally did) overflowed the limit as soon as the OPC UA
  # shadow topics were added, so the document is deliberately written as one
  # statement per ACTION with a resource list, rather than one per topic group.
  iot_arn = "arn:aws:iot:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}"

  # Policy variable, resolved by AWS per connection. `$$` escapes the Terraform
  # interpolation so the literal `${iot:...}` reaches the policy document.
  thing = "$${iot:Connection.Thing.ThingName}"
}

resource "aws_iot_policy" "device" {
  name = "${var.project_name}-device-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Connect"
        Effect = "Allow"
        Action = "iot:Connect"
        # ClientId must be the same as thing name (this is how firmware connects).
        Resource = "${local.iot_arn}:client/${local.thing}"
      },
      # Publish, Subscribe and Receive stay separate: the device must be able to
      # PUBLISH telemetry but never SUBSCRIBE to it, and the split is what keeps
      # that enforceable. Every resource is still pinned to the device's own
      # thing name, so one device can never reach another's topics.
      {
        Sid    = "Publish"
        Effect = "Allow"
        Action = "iot:Publish"
        Resource = [
          "${local.iot_arn}:topic/${var.telemetry_topic_prefix}/${local.thing}/*",
          "${local.iot_arn}:topic/$aws/things/${local.thing}/jobs/*",
          # The OPC UA config plane lives on the `opcua` NAMED shadow, so this
          # has to cover `shadow/name/<name>/...`, not just the classic shadow.
          "${local.iot_arn}:topic/$aws/things/${local.thing}/shadow/*",
        ]
      },
      {
        Sid    = "Subscribe"
        Effect = "Allow"
        Action = "iot:Subscribe"
        Resource = [
          "${local.iot_arn}:topicfilter/cmd/${local.thing}/*",
          "${local.iot_arn}:topicfilter/$aws/things/${local.thing}/jobs/*",
          "${local.iot_arn}:topicfilter/$aws/things/${local.thing}/shadow/*",
        ]
      },
      {
        Sid    = "Receive"
        Effect = "Allow"
        Action = "iot:Receive"
        Resource = [
          "${local.iot_arn}:topic/cmd/${local.thing}/*",
          "${local.iot_arn}:topic/$aws/things/${local.thing}/jobs/*",
          "${local.iot_arn}:topic/$aws/things/${local.thing}/shadow/*",
        ]
      },
    ]
  })
}

# ---------------------------------------------------------------------------
# 3) OTA thing groups.
#    Every OTA job targets the FLEET group. CANARY is its child, so canary
#    devices are part of every fleet job too; it marks the bench units a
#    canary-first rollout would update first. AWS IoT allows a thing in only
#    one group of a hierarchy, which keeps the two sets disjoint.
#    New devices join the fleet group through the provisioning template below;
#    canary devices are listed in var.ota_canary_things.
# ---------------------------------------------------------------------------
resource "aws_iot_thing_group" "fleet" {
  name = "${var.project_name}-fleet"

  properties {
    description = "All provisioned gateways. OTA jobs target this group."
  }
}

resource "aws_iot_thing_group" "canary" {
  name              = "${var.project_name}-canary"
  parent_group_name = aws_iot_thing_group.fleet.name

  properties {
    description = "Bench and test gateways. A child of the fleet group, so they receive every fleet OTA job."
  }
}

resource "aws_iot_thing_group_membership" "canary" {
  for_each = toset(var.ota_canary_things)

  thing_name       = each.value
  thing_group_name = aws_iot_thing_group.canary.name
}

# ---------------------------------------------------------------------------
# 4) Fleet Provisioning Template.
#    Defines which thing/cert/policy will be created in the RegisterThing call.
#    pre_provisioning_hook: Lambda validation is required on each request.
# ---------------------------------------------------------------------------
resource "aws_iot_provisioning_template" "fleet" {
  name                  = var.provisioning_template_name
  description           = "ESP32-S3 zero-touch fleet provisioning (by claim)"
  provisioning_role_arn = aws_iam_role.provisioning.arn
  enabled               = true

  pre_provisioning_hook {
    target_arn      = aws_lambda_function.pre_provisioning_hook.arn
    payload_version = "2020-04-01"
  }

  template_body = jsonencode({
    Parameters = {
      SerialNumber = { Type = "String" }
      MacAddress   = { Type = "String" }
      # Secret goes to the hook but is not used in the thing resource.
      Secret                      = { Type = "String" }
      "AWS::IoT::Certificate::Id" = { Type = "String" }
    }

    Resources = {
      certificate = {
        Type = "AWS::IoT::Certificate"
        Properties = {
          CertificateId = { Ref = "AWS::IoT::Certificate::Id" }
          Status        = "ACTIVE"
        }
      }

      policy = {
        Type = "AWS::IoT::Policy"
        Properties = {
          PolicyName = aws_iot_policy.device.name
        }
      }

      thing = {
        Type = "AWS::IoT::Thing"
        Properties = {
          ThingName = { Ref = "SerialNumber" }
          AttributePayload = {
            mac = { Ref = "MacAddress" }
          }
          # New devices join the fleet group, so they get the OTA job in flight.
          ThingGroups = [aws_iot_thing_group.fleet.name]
        }
        OverrideSettings = {
          AttributePayload = "MERGE"
          ThingTypeName    = "REPLACE"
          # A device that provisions again keeps the groups it has: MERGE would
          # fail for a canary device (fleet is in the same hierarchy), and
          # REPLACE would silently drop it out of canary.
          ThingGroups = "DO_NOTHING"
        }
      }
    }
  })

  # Hook resource-policy must be ready before the template.
  depends_on = [
    aws_lambda_permission.allow_iot,
    aws_iam_role_policy_attachment.provisioning,
  ]
}

# ---------------------------------------------------------------------------
# 5) (Optional) Simple IoT Rule to route telemetry to CloudWatch Logs.
#    Useful to see that the device actually publishes in PoC.
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "telemetry" {
  name              = "/${var.project_name}/telemetry"
  retention_in_days = var.log_retention_days
}

data "aws_iam_policy_document" "iot_rule_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["iot.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "iot_rule" {
  name               = "${var.project_name}-telemetry-rule-role"
  assume_role_policy = data.aws_iam_policy_document.iot_rule_assume.json
}

resource "aws_iam_role_policy" "iot_rule" {
  name = "${var.project_name}-telemetry-rule-policy"
  role = aws_iam_role.iot_rule.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
      Resource = [
        "${aws_cloudwatch_log_group.telemetry.arn}:*",
        "${aws_cloudwatch_log_group.opcua_telemetry.arn}:*",
      ]
    }]
  })
}

resource "aws_iot_topic_rule" "telemetry_to_logs" {
  name        = replace("${var.project_name}_telemetry_to_logs", "-", "_")
  enabled     = true
  sql         = "SELECT *, topic() AS topic, timestamp() AS ts FROM '${var.telemetry_topic_prefix}/+/data'"
  sql_version = "2016-03-23"

  cloudwatch_logs {
    log_group_name = aws_cloudwatch_log_group.telemetry.name
    role_arn       = aws_iam_role.iot_rule.arn
  }
}

# ---------------------------------------------------------------------------
# 6) OPC UA gateway telemetry.
#    The OPC UA driver publishes BATCHES on `<prefix>/<thing>/opcua`, which the
#    `<prefix>/+/data` rule above does not match. A separate log group keeps the
#    batched OPC UA payloads out of the plain-telemetry stream, which is what
#    makes the firmware repo's on-device test (`gateway-hil`) observable from
#    the cloud side.
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "opcua_telemetry" {
  name              = "/${var.project_name}/opcua-telemetry"
  retention_in_days = var.log_retention_days
}

resource "aws_iot_topic_rule" "opcua_telemetry_to_logs" {
  name        = replace("${var.project_name}_opcua_telemetry_to_logs", "-", "_")
  enabled     = true
  sql         = "SELECT *, topic() AS topic, timestamp() AS ts FROM '${var.telemetry_topic_prefix}/+/opcua'"
  sql_version = "2016-03-23"

  cloudwatch_logs {
    log_group_name = aws_cloudwatch_log_group.opcua_telemetry.name
    role_arn       = aws_iam_role.iot_rule.arn
  }
}
