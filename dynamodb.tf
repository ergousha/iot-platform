# ---------------------------------------------------------------------------
# Device registry database.
# PAY_PER_REQUEST = on-demand: cost is ~0 when idle, you only pay per
# read/write request. Ideal for PoC.
# ---------------------------------------------------------------------------
resource "aws_dynamodb_table" "device_registry" {
  name         = "${var.project_name}-device-registry"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "mac_address"

  attribute {
    name = "mac_address"
    type = "S"
  }

  point_in_time_recovery {
    enabled = false # PoC: disabled. Set to true in production.
  }

  server_side_encryption {
    enabled = true # AWS-owned KMS key (no additional charge).
  }

  tags = {
    Name = "${var.project_name}-device-registry"
  }
}
