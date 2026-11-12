data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ATS data endpoint the device will connect to (mutual TLS, port 8883).
data "aws_iot_endpoint" "ats" {
  endpoint_type = "iot:Data-ATS"
}

locals {
  # var.products with every optional name resolved. Everything per-product
  # iterates over this map.
  products = {
    for id, p in var.products : id => merge(p, {
      fleet_group_name           = coalesce(p.fleet_group_name, "${var.project_name}-${id}-fleet")
      canary_group_name          = coalesce(p.canary_group_name, "${var.project_name}-${id}-canary")
      excluded_group_name        = coalesce(p.excluded_group_name, "${var.project_name}-${id}-excluded")
      provisioning_template_name = coalesce(p.provisioning_template_name, "${var.project_name}-${id}-fleet-template")
      github_actions_role_name   = coalesce(p.github_actions_role_name, "${var.project_name}-${id}-github-actions-role")
      shadow_name                = coalesce(p.shadow_name, id)
      # The repository name without its owner and a trailing -rust.
      display_name = coalesce(p.display_name, trimsuffix(element(split("/", p.github_repository), 1), "-rust"))
    })
  }

  # The product marked `legacy`, or null.
  legacy_product = one([for id, p in var.products : id if p.legacy])

  # The provisioning template ARNs, built as strings rather than read from the
  # template resources. This lets the hook's Lambda permission be created
  # BEFORE the templates (a template refuses a hook it cannot invoke), which
  # breaks the chicken-and-egg loop.
  provisioning_template_arns = {
    for id, p in local.products :
    id => "arn:aws:iot:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:provisioningtemplate/${p.provisioning_template_name}"
  }
}
