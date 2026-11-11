output "iot_endpoint" {
  description = "Use as CONFIG_MQTT_BROKER_ENDPOINT in firmware (port 8883)."
  value       = data.aws_iot_endpoint.ats.endpoint_address
}

output "provisioning_template_names" {
  description = "Provisioning template of each product (also in SSM at /esp32-ztp/poc/<product>/provisioning_template_name)."
  value       = { for id, t in aws_iot_provisioning_template.fleet : id => t.name }
}

output "fleet_thing_groups" {
  description = "Fleet thing group of each product: target of its fleet OTA job, and holder of its OTA state attributes."
  value       = { for id, g in aws_iot_thing_group.fleet : id => g.name }
}

output "dynamodb_table" {
  value = aws_dynamodb_table.device_registry.name
}

output "github_actions_role_arns" {
  description = "IAM role each product's release workflow assumes through GitHub OIDC from Environment `release` (the repository's AWS_ROLE_ARN variable)."
  value       = { for id, r in aws_iam_role.github_actions : id => r.arn }
}

output "firmware_bucket_name" {
  description = "S3 bucket the release workflows publish to, under s3://<bucket>/releases/<product>/<X.Y.Z>/ (the repository's AWS_FIRMWARE_BUCKET variable)."
  value       = aws_s3_bucket.firmware.id
}

output "canary_thing_groups" {
  description = "Canary thing group of each product: the target of each release's canary job."
  value       = { for id, g in aws_iot_thing_group.canary : id => g.name }
}

output "excluded_thing_groups" {
  description = "Excluded thing group of each product: devices that failed a fleet job (scripts/ota.sh target brings one back)."
  value       = { for id, g in aws_iot_thing_group.excluded : id => g.name }
}

# The claim is not in Terraform at all: the OTA controller keeps it in SSM
# (/iot-platform/claim/{cert,key}), where only `ergo commission` reads it.
#
# Amazon Root CA 1:
#   curl -s https://www.amazontrust.com/repository/AmazonRootCA1.pem \
#     > ../certs/AmazonRootCA1.pem

output "guard_topic_arn" {
  description = "SNS topic of the guard alarms and budgets (email + kill switch)."
  value       = aws_sns_topic.guard.arn
}
