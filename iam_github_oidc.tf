# ---------------------------------------------------------------------------
# GitHub OIDC Provider and Role
# ---------------------------------------------------------------------------

locals {
  # The OIDC subject of each product's repository, main branch only. GitHub
  # puts the immutable owner and repository ids in the subject, so a renamed
  # or re-created repository with the same name cannot assume the role.
  github_oidc_subs = {
    for id, p in local.products :
    id => "repo:${split("/", p.github_repository)[0]}@${var.github_owner_id}/${split("/", p.github_repository)[1]}@${p.github_repository_id}:ref:refs/heads/main"
  }
}

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1", "1c58a3a8518e8759bf075b76b750d4f2df264fcd"] # GitHub's standard thumbprints
}

# One role per product, trusted by that product's repository only. A release of
# one product therefore cannot overwrite another's firmware or read its
# template parameter.
data "aws_iam_policy_document" "github_assume_role" {
  for_each = local.products

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = [local.github_oidc_subs[each.key]]
    }
  }
}

resource "aws_iam_role" "github_actions" {
  for_each = local.products

  name               = each.value.github_actions_role_name
  assume_role_policy = data.aws_iam_policy_document.github_assume_role[each.key].json
}

data "aws_iam_policy_document" "github_actions_policy" {
  for_each = local.products

  # Uploads go under the product's own prefix, where the OTA trigger maps them
  # to the product's fleet group. The legacy product may still upload at the
  # bucket root, where its releases went before products existed.
  statement {
    actions = ["s3:PutObject"]
    resources = concat(
      ["${aws_s3_bucket.firmware.arn}/${each.key}/*"],
      each.value.legacy ? ["${aws_s3_bucket.firmware.arn}/firmware_*"] : [],
    )
  }

  # The firmware release build compiles the IoT endpoint, the provisioning
  # template and the claim identity into the image; its build.rs reads them
  # from these parameters. Read-only, and exactly these. The SecureStrings use
  # the AWS managed aws/ssm key, whose key policy already allows decryption
  # through SSM for principals in this account.
  statement {
    actions = ["ssm:GetParameter"]
    resources = concat(
      [
        aws_ssm_parameter.iot_endpoint.arn,
        aws_ssm_parameter.claim_certificate.arn,
        aws_ssm_parameter.claim_private_key.arn,
        aws_ssm_parameter.product_provisioning_template[each.key].arn,
      ],
      each.value.legacy ? [aws_ssm_parameter.provisioning_template[0].arn] : [],
    )
  }
}

resource "aws_iam_role_policy" "github_actions_s3" {
  for_each = local.products

  name   = "${var.project_name}-github-actions-s3-policy"
  role   = aws_iam_role.github_actions[each.key].id
  policy = data.aws_iam_policy_document.github_actions_policy[each.key].json
}

# The single role became the legacy product's (the gateway's) role.
moved {
  from = aws_iam_role.github_actions
  to   = aws_iam_role.github_actions["gateway"]
}

moved {
  from = aws_iam_role_policy.github_actions_s3
  to   = aws_iam_role_policy.github_actions_s3["gateway"]
}
