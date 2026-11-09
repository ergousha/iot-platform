# ---------------------------------------------------------------------------
# SSM Parameter Store integration
# Stores the outputs required by the firmware build system.
# ---------------------------------------------------------------------------

resource "aws_ssm_parameter" "iot_endpoint" {
  name        = "/esp32-ztp/poc/iot_endpoint"
  type        = "String"
  value       = data.aws_iot_endpoint.ats.endpoint_address
  description = "AWS IoT Core endpoint for firmware"
}

# Each product's template, read by that product's firmware build.
resource "aws_ssm_parameter" "product_provisioning_template" {
  for_each = local.products

  name        = "/esp32-ztp/poc/${each.key}/provisioning_template_name"
  type        = "String"
  value       = aws_iot_provisioning_template.fleet[each.key].name
  description = "Fleet provisioning template name for product '${each.key}'"
}

# The parameter from before products existed, still read by the legacy
# product's build.rs. Remove once that build reads its product parameter.
resource "aws_ssm_parameter" "provisioning_template" {
  count = local.legacy_product == null ? 0 : 1

  name        = "/esp32-ztp/poc/provisioning_template_name"
  type        = "String"
  value       = aws_iot_provisioning_template.fleet[local.legacy_product].name
  description = "Fleet provisioning template name"
}

moved {
  from = aws_ssm_parameter.provisioning_template
  to   = aws_ssm_parameter.provisioning_template[0]
}

resource "aws_ssm_parameter" "claim_certificate" {
  name        = "/esp32-ztp/poc/claim_certificate_pem"
  type        = "SecureString"
  value       = aws_iot_certificate.claim.certificate_pem
  description = "Bootstrap claim certificate"
}

resource "aws_ssm_parameter" "claim_private_key" {
  name        = "/esp32-ztp/poc/claim_private_key"
  type        = "SecureString"
  value       = aws_iot_certificate.claim.private_key
  description = "Bootstrap claim private key"
}
