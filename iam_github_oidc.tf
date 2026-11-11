# ---------------------------------------------------------------------------
# GitHub OIDC Provider and Role
# ---------------------------------------------------------------------------

locals {
  # The OIDC subject of each product's repository, Environment `release`
  # only (which only protected main may deploy to; the signing key lives
  # there). GitHub puts the immutable owner and repository ids in the subject,
  # so a renamed or re-created repository with the same name cannot assume
  # the role.
  github_oidc_subs = {
    for id, p in local.products :
    id => "repo:${split("/", p.github_repository)[0]}@${var.github_owner_id}/${split("/", p.github_repository)[1]}@${p.github_repository_id}:environment:release"
  }
}

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1", "1c58a3a8518e8759bf075b76b750d4f2df264fcd"] # GitHub's standard thumbprints
}

# One role per product, trusted by that product's repository only, and only
# from inside the SDK's reusable release workflow (job_workflow_ref): a
# workflow edited in the product repository cannot assume it. A release of
# one product therefore cannot write another's firmware.
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
    # Callers pin the workflow by commit SHA; any ref of it is accepted.
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:job_workflow_ref"
      values   = ["${var.release_workflow}@*"]
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

  # Only the product's own releases/<product>/ prefix. GetObject lets a re-run
  # compare what is already there (uploads are If-None-Match: *, so a
  # published release is never overwritten). No SSM, no IoT: images are built
  # without AWS, and the OTA controller verifies every upload's signature.
  statement {
    actions   = ["s3:PutObject", "s3:GetObject"]
    resources = ["${aws_s3_bucket.firmware.arn}/releases/${each.key}/*"]
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
