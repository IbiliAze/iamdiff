terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_region_validation      = true
  skip_metadata_api_check     = true
}

data "aws_iam_policy_document" "deploy" {
  statement {
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = ["arn:aws:s3:::assets", "arn:aws:s3:::assets/*"]
  }
}

resource "aws_iam_policy" "deploy" {
  name   = "deploy"
  policy = data.aws_iam_policy_document.deploy.json
}

resource "aws_iam_policy" "orphan" {
  name = "orphan"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "dynamodb:DeleteItem", Resource = "*" }]
  })
}

resource "aws_iam_role" "deploy" {
  name = "deploy"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  permissions_boundary = "arn:aws:iam::123456789012:policy/ci-boundary"
  inline_policy {
    name = "legacy"
    policy = jsonencode({
      Version   = "2012-10-17"
      Statement = [{ Effect = "Allow", Action = "ec2:DescribeInstances", Resource = "*" }]
    })
  }
}

resource "aws_iam_role_policy" "extra" {
  name = "extra"
  role = aws_iam_role.deploy.name
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["iam:PassRole"], Resource = "*" }]
  })
}

resource "aws_iam_role_policy_attachment" "deploy" {
  role       = aws_iam_role.deploy.name
  policy_arn = aws_iam_policy.deploy.arn
}

resource "aws_iam_role_policy_attachment" "readonly" {
  role       = aws_iam_role.deploy.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role" "worker" {
  name_prefix = "worker-"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "worker" {
  name = "worker"
  role = aws_iam_role.worker.name
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sqs:ReceiveMessage", Resource = "*" }]
  })
}

resource "aws_iam_user" "ci" {
  name = "ci"
}

resource "aws_iam_user_policy" "ci" {
  name = "ci"
  user = aws_iam_user.ci.name
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Resource = aws_iam_role.deploy.arn }]
  })
}

resource "aws_organizations_policy" "deny_iam" {
  name = "deny-iam"
  content = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Deny", Action = "iam:*", Resource = "*" }]
  })
}

module "svc" {
  source   = "./svc"
  for_each = toset(["a", "b"])
  name     = each.key
}
