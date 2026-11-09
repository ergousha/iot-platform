output "iot_endpoint" {
  description = "Use as CONFIG_MQTT_BROKER_ENDPOINT in firmware (port 8883)."
  value       = data.aws_iot_endpoint.ats.endpoint_address
}

output "provisioning_template_names" {
  description = "Provisioning template of each product (also in SSM at /esp32-ztp/poc/<product>/provisioning_template_name)."
  value       = { for id, t in aws_iot_provisioning_template.fleet : id => t.name }
}

output "fleet_thing_groups" {
  description = "Fleet thing group of each product: the target of its OTA jobs."
  value       = { for id, g in aws_iot_thing_group.fleet : id => g.name }
}

output "dynamodb_table" {
  value = aws_dynamodb_table.device_registry.name
}

output "github_actions_role_arns" {
  description = "IAM role each product's release workflow assumes through GitHub OIDC (the repository's AWS_ROLE_ARN variable)."
  value       = { for id, r in aws_iam_role.github_actions : id => r.arn }
}

output "firmware_bucket_name" {
  description = "S3 bucket where the release workflows upload firmware images, each under s3://<bucket>/<product>/."
  value       = aws_s3_bucket.firmware.id
}

output "claim_certificate_pem" {
  description = "CLAIM certificate to be flashed to device (certs/claim.crt.pem)."
  value       = aws_iot_certificate.claim.certificate_pem
  sensitive   = true
}

output "claim_private_key" {
  description = "CLAIM private key to be flashed to device (certs/claim.private.key)."
  value       = aws_iot_certificate.claim.private_key
  sensitive   = true
}

output "claim_public_key" {
  value     = aws_iot_certificate.claim.public_key
  sensitive = true
}

# ---------------------------------------------------------------------------
# To extract certificates to files (not printed to screen because they are sensitive):
#
#   terraform output -raw claim_certificate_pem > ../certs/claim.crt.pem
#   terraform output -raw claim_private_key     > ../certs/claim.private.key
#
# Amazon Root CA 1:
#   curl -s https://www.amazontrust.com/repository/AmazonRootCA1.pem \
#     > ../certs/AmazonRootCA1.pem
# ---------------------------------------------------------------------------
