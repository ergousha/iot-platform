# ===========================================================================
# AWS IoT Core - Fleet Provisioning by Claim
# ===========================================================================

locals {
  # CreateCertificateFromCsr only: every product's key stays on the device (a
  # secure element or NVS), and the hook enrols only the registered key.
  # CreateKeysAndCertificate ($aws/certificates/create/*), where AWS generated
  # the key, is not reachable.
  claim_topics = concat(
    ["$aws/certificates/create-from-csr/*"],
    [for p in values(local.products) : "$aws/provisioning-templates/${p.provisioning_template_name}/provision/*"],
  )
}

# ---------------------------------------------------------------------------
# 1) CLAIM (bootstrap) certificate.
#    The certificate a board enrols with, carried only between `ergo
#    commission` and its enrolment (it is erased from the board afterwards).
#    It can reach the provisioning topics and nothing else.
#
#    Not in Terraform: the OTA controller creates it
#    from a CSR whose key never leaves the Lambda's memory and SSM
#    (/iot-platform/claim/{cert,key}), keeps it INACTIVE outside enrolment
#    windows, rotates it after site windows and on demand
#    (scripts/ota.sh rotate-claim), and deletes the previous one. Terraform
#    owns only the policy; its targets are the controller's. The claim key is
#    therefore never in Terraform state.
# ---------------------------------------------------------------------------
removed {
  from = aws_iot_certificate.claim
  lifecycle {
    destroy = false # the controller rotates it, then deletes it
  }
}

removed {
  from = aws_iot_policy_attachment.claim
  lifecycle {
    destroy = false
  }
}

resource "aws_iot_policy" "claim" {
  name = "${var.project_name}-claim-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Firmware connects as claim-<MAC12> while enrolling. Restricting the
        # claim to that prefix keeps a claim holder from taking over a device's
        # client id (AWS IoT drops the older session on a duplicate id).
        Sid      = "Connect"
        Effect   = "Allow"
        Action   = "iot:Connect"
        Resource = "arn:aws:iot:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:client/claim-*"
      },
      {
        Sid      = "Provision"
        Effect   = "Allow"
        Action   = ["iot:Publish", "iot:Receive"]
        Resource = [for t in local.claim_topics : "${local.iot_arn}:topic/${t}"]
      },
      {
        Sid      = "SubscribeProvisioningResponses"
        Effect   = "Allow"
        Action   = "iot:Subscribe"
        Resource = [for t in local.claim_topics : "${local.iot_arn}:topicfilter/${t}"]
      },
    ]
  })
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
  iot_arn = "arn:aws:iot:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}"

  # Policy variable, resolved by AWS per connection. `$$` escapes the Terraform
  # interpolation so the literal `${iot:...}` reaches the policy document.
  thing = "$${iot:Connection.Thing.ThingName}"

  # The thing's `product` attribute (the provisioning template sets it). A
  # device may publish straight into its own product's rules over Basic
  # Ingest (`$aws/rules/<product>_*`): no messaging charge, and no other
  # product's rules. A thing without the attribute matches nothing.
  product = "$${iot:Connection.Thing.Attributes[product]}"

  # The device's own Jobs and named-shadow topics. In a policy resource `*`
  # matches any characters, `/` included; MQTT wildcards are literal.
  jobs   = "$aws/things/${local.thing}/jobs"
  shadow = "$aws/things/${local.thing}/shadow/name/*"
}

locals {
  # Request topics and the answers the firmware acts on, nothing more
  # (PLATFORM.md §6). In particular no shadow `update/accepted` or
  # `update/documents`: each would echo every report back to the device and
  # double its messaging.
  device_policy = jsonencode({
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
          # DescribeJobExecution ($next or a job id) and UpdateJobExecution.
          "${local.iot_arn}:topic/${local.jobs}/*/get",
          "${local.iot_arn}:topic/${local.jobs}/*/update",
          # Named shadows only: `platform` and the product's.
          "${local.iot_arn}:topic/${local.shadow}/get",
          "${local.iot_arn}:topic/${local.shadow}/update",
          "${local.iot_arn}:topic/$aws/rules/${local.product}_*",
        ]
      },
      {
        Sid    = "Subscribe"
        Effect = "Allow"
        Action = "iot:Subscribe"
        Resource = [
          # The gateway's retained OPC UA tag bundle.
          "${local.iot_arn}:topicfilter/cmd/${local.thing}/*",
          "${local.iot_arn}:topicfilter/${local.jobs}/notify-next",
          "${local.iot_arn}:topicfilter/${local.jobs}/*/accepted",
          "${local.iot_arn}:topicfilter/${local.jobs}/*/rejected",
          "${local.iot_arn}:topicfilter/${local.shadow}/get/*",
          "${local.iot_arn}:topicfilter/${local.shadow}/update/delta",
          "${local.iot_arn}:topicfilter/${local.shadow}/update/rejected",
        ]
      },
      {
        # Receive applies only to messages of a subscription the statement
        # above allowed, so it may stay broad: listing every topic again would
        # not fit the 2048-character limit.
        Sid    = "Receive"
        Effect = "Allow"
        Action = "iot:Receive"
        Resource = [
          "${local.iot_arn}:topic/cmd/${local.thing}/*",
          "${local.iot_arn}:topic/$aws/things/${local.thing}/*",
        ]
      },
    ]
  })
}

resource "aws_iot_policy" "device" {
  name = "${var.project_name}-device-policy"

  policy = local.device_policy

  lifecycle {
    precondition {
      # AWS IoT refuses a policy document over 2048 characters (whitespace
      # excluded), and the apply would fail halfway. jsonencode is compact.
      condition     = length(local.device_policy) <= 2048
      error_message = "The device policy is ${length(local.device_policy)} characters; AWS IoT allows 2048."
    }
  }
}

# ---------------------------------------------------------------------------
# 3) OTA thing groups, three per product.
#    fleet     every provisioned device (the provisioning template puts new
#              ones here). Target of the CONTINUOUS fleet job, and holder of
#              the product's OTA state in its attributes (ota_mode,
#              soak_hours, fleet_version, halted_version, ...), which only the
#              OTA controller and the owner write: Terraform ignores them.
#    canary    a child of fleet: target of each release's SNAPSHOT canary job.
#              A thing is in one group of a hierarchy, so the two sets are
#              disjoint, and canaries get the fleet job too (they already run
#              the version and settle it without a download). Membership is
#              the controller's: registry records with canary=true, else a
#              device it picks, and it substitutes an unplugged canary.
#    excluded  outside the hierarchy: a device that failed a fleet job while
#              others succeeded, until `scripts/ota.sh target` brings it back.
#    The products' hierarchies are separate, so a job never crosses products.
# ---------------------------------------------------------------------------
resource "aws_iot_thing_group" "fleet" {
  for_each = local.products
  name     = each.value.fleet_group_name

  properties {
    description = "All provisioned ${each.value.description} devices. Promoted OTA jobs for product '${each.key}' target this group."
  }

  lifecycle {
    # The OTA state; see above.
    ignore_changes = [properties[0].attribute_payload]
  }
}

resource "aws_iot_thing_group" "canary" {
  for_each          = local.products
  name              = each.value.canary_group_name
  parent_group_name = aws_iot_thing_group.fleet[each.key].name

  properties {
    description = "Bench and test ${each.value.description} devices. Every release's OTA job targets this group first; a child of the fleet group."
  }
}

resource "aws_iot_thing_group" "excluded" {
  for_each = local.products
  name     = each.value.excluded_group_name

  properties {
    description = "${each.value.description} devices that failed a fleet OTA job while others succeeded. No fleet job reaches them."
  }
}

# Canary membership was Terraform's (var.products[*].canary_things) until the
# controller took it over. The memberships stay as they are.
removed {
  from = aws_iot_thing_group_membership.canary
  lifecycle {
    destroy = false
  }
}

# ---------------------------------------------------------------------------
# 4) Fleet Provisioning Templates, one per product.
#    Defines which thing/cert/policy will be created in the RegisterThing call.
#    pre_provisioning_hook: Lambda validation is required on each request; it
#    also checks that the device is registered for THIS template's product.
# ---------------------------------------------------------------------------
resource "aws_iot_provisioning_template" "fleet" {
  for_each = local.products

  name                  = each.value.provisioning_template_name
  description           = "${each.value.description}: zero-touch fleet provisioning (by claim)"
  provisioning_role_arn = aws_iam_role.provisioning.arn
  enabled               = true

  pre_provisioning_hook {
    target_arn      = aws_lambda_function.pre_provisioning_hook.arn
    payload_version = "2020-04-01"
  }

  template_body = jsonencode({
    Parameters = {
      SerialNumber                = { Type = "String" }
      MacAddress                  = { Type = "String" }
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
            mac     = { Ref = "MacAddress" }
            product = each.key
          }
          # New devices join their product's fleet group, so they get the OTA
          # job in flight for that product.
          ThingGroups = [aws_iot_thing_group.fleet[each.key].name]
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

# The single-product resources became the gateway's entries. These keep them in
# place instead of destroying and recreating them (which would empty the groups).
moved {
  from = aws_iot_thing_group.fleet
  to   = aws_iot_thing_group.fleet["gateway"]
}

moved {
  from = aws_iot_thing_group.canary
  to   = aws_iot_thing_group.canary["gateway"]
}

moved {
  from = aws_iot_provisioning_template.fleet
  to   = aws_iot_provisioning_template.fleet["gateway"]
}

# ---------------------------------------------------------------------------
# 5) Telemetry rules belong to the products (plan §7): a product's cloud/
#    root (state products/<id>/cloud.tfstate) owns its rules, named <id>_*,
#    which the kill switch disables by name. The platform keeps none.
#
#    The gateway's OPC UA debug rule moved to its cloud/. Its log group,
#    /esp32-ztp/opcua-telemetry, which gateway-hil reads, is kept and
#    imported there; the rule itself is recreated as
#    gateway_opcua_telemetry_to_logs, so its old one is destroyed here. The
#    dt/+/data rule had no producer and is gone, with its log group and role.
# ---------------------------------------------------------------------------
removed {
  from = aws_cloudwatch_log_group.opcua_telemetry

  lifecycle {
    destroy = false
  }
}
