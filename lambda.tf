# ---------------------------------------------------------------------------
# Pre-provisioning hook Lambda (serverless, on-demand).
# ---------------------------------------------------------------------------
resource "terraform_data" "build_hook" {
  triggers_replace = {
    source_hash = sha256(join("", [
      filesha256("${path.module}/lambda/pre_provisioning_hook/main.go"),
    ]))
  }

  provisioner "local-exec" {
    command = "GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags='-s -w' -o ${path.module}/lambda/pre_provisioning_hook/bootstrap ${path.module}/lambda/pre_provisioning_hook/main.go"
  }
}

data "archive_file" "hook_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda/pre_provisioning_hook/bootstrap"
  output_path = "${path.module}/.build/pre_provisioning_hook.zip"
  depends_on  = [terraform_data.build_hook]
}

resource "aws_cloudwatch_log_group" "hook" {
  name              = "/aws/lambda/${var.project_name}-pre-provisioning-hook"
  retention_in_days = var.log_retention_days
}

resource "aws_lambda_function" "pre_provisioning_hook" {
  function_name    = "${var.project_name}-pre-provisioning-hook"
  role             = aws_iam_role.hook.arn
  runtime          = "provided.al2023"
  handler          = "bootstrap"
  filename         = data.archive_file.hook_zip.output_path
  source_code_hash = data.archive_file.hook_zip.output_base64sha256

  memory_size = 128 # the minimum; the hook does one GetItem and one UpdateItem
  timeout     = 5   # AWS IoT waits about 5 s for the hook anyway

  environment {
    variables = {
      DEVICE_TABLE = aws_dynamodb_table.device_registry.name
      # Which product each template enrols, and whether that product must prove
      # itself with a registered public key. See lambda/pre_provisioning_hook.
      PRODUCTS_BY_TEMPLATE = jsonencode({
        for id, p in local.products : p.provisioning_template_name => {
          product            = id
          require_public_key = p.require_public_key
        }
      })
      # Registry records written before products existed carry no `product`
      # attribute; they belong to the legacy product ("" = none: rejected).
      LEGACY_RECORD_PRODUCT = local.legacy_product == null ? "" : local.legacy_product
    }
  }

  depends_on = [aws_cloudwatch_log_group.hook]
}

# Lets AWS IoT invoke the hook, once per provisioning template. source_arn
# comes from a string local rather than the template resources: referencing
# them would be a cycle, and this way the permission exists before the
# template that needs it. The legacy product keeps the statement id it had
# before products existed, so its permission is updated in place, never removed.
resource "aws_lambda_permission" "allow_iot" {
  for_each = local.products

  statement_id  = each.value.legacy ? "AllowIoTFleetProvisioningInvoke" : "AllowIoTFleetProvisioningInvoke-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.pre_provisioning_hook.function_name
  principal     = "iot.amazonaws.com"
  source_arn    = local.provisioning_template_arns[each.key]
}

moved {
  from = aws_lambda_permission.allow_iot
  to   = aws_lambda_permission.allow_iot["gateway"]
}
