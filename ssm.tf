# ---------------------------------------------------------------------------
# SSM Parameter Store. The /esp32-ztp/poc/* build parameters are gone: builds
# compile the endpoint and template from platform.toml, and the facts below
# replace them.
# ---------------------------------------------------------------------------

# The claim certificate and key are in /iot-platform/claim/{cert,key},
# written by the OTA controller (see iot.tf), never by Terraform.

# ---------------------------------------------------------------------------
# Platform facts per product (plan §7), at /iot-platform/products/<id>/platform:
# what `ergo product init` writes into the product repository (platform.toml,
# repository variables) and what a product's cloud/ root reads instead of
# this state. Public facts only. signing_keys next to it is written by
# `ergo product init` (or scripts/signing-keys.sh), never by Terraform.
# ---------------------------------------------------------------------------
resource "aws_ssm_parameter" "product_platform" {
  for_each = local.products

  name        = "/iot-platform/products/${each.key}/platform"
  type        = "String"
  description = "Platform facts of product '${each.key}' (JSON): endpoint, template, groups, release role and bucket, cloud/ state key and rule prefix."
  value = jsonencode({
    product                 = each.key
    region                  = data.aws_region.current.region
    account_id              = data.aws_caller_identity.current.account_id
    iot_endpoint            = data.aws_iot_endpoint.ats.endpoint_address
    provisioning_template   = aws_iot_provisioning_template.fleet[each.key].name
    fleet_group             = aws_iot_thing_group.fleet[each.key].name
    canary_group            = aws_iot_thing_group.canary[each.key].name
    excluded_group          = aws_iot_thing_group.excluded[each.key].name
    shadow_name             = each.value.shadow_name
    github_actions_role_arn = aws_iam_role.github_actions[each.key].arn
    firmware_bucket         = aws_s3_bucket.firmware.id
    # A product's cloud/ root: S3 backend in the platform's state bucket,
    # its rules named <rule_prefix>* (killable by the guard), logs kept
    # log_retention_days.
    cloud_state_bucket = local.state_bucket
    cloud_state_key    = "products/${each.key}/cloud.tfstate"
    rule_prefix        = "${each.key}_"
    log_retention_days = var.log_retention_days
  })
}
