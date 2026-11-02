# Isolated qualification source. Not a production HA reference deployment.
terraform {
  required_version = ">= 1.15, < 2.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "= 6.67.0" }
  }
}

variable "region" {
  type    = string
  default = "ap-northeast-2"
}
variable "account_id" { type = string }
variable "operator_arn" { type = string }
variable "operator_cidr" {
  type    = string
  default = null
  validation {
    condition     = var.operator_cidr == null ? true : (can(cidrnetmask(var.operator_cidr)) && endswith(var.operator_cidr, "/32"))
    error_message = "Optional public access must be restricted to one operator IPv4 /32."
  }
}
variable "run_id" {
  type = string
  validation {
    condition     = can(regex("^[a-z0-9]{6,12}$", var.run_id))
    error_message = "Use a unique 6..12 character run ID."
  }
}
variable "expires_at" { type = string }

locals {
  name = "sova-exit-${var.run_id}"
  tags = { Project = "Sova", Component = "eks-rke2-qualification", RunId = var.run_id, ExpiresAt = var.expires_at, ManagedBy = "Terraform" }
}

provider "aws" {
  region              = var.region
  allowed_account_ids = [var.account_id]
  default_tags { tags = local.tags }
}

resource "aws_vpc" "source" {
  cidr_block           = "172.27.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = local.name }
}
resource "aws_internet_gateway" "source" { vpc_id = aws_vpc.source.id }
resource "aws_subnet" "source" {
  for_each                = { a = { cidr = "172.27.10.0/24", az = "${var.region}a" }, c = { cidr = "172.27.20.0/24", az = "${var.region}c" } }
  vpc_id                  = aws_vpc.source.id
  cidr_block              = each.value.cidr
  availability_zone       = each.value.az
  map_public_ip_on_launch = true
  tags                    = { Name = "${local.name}-${each.key}" }
}
resource "aws_route_table" "source" {
  vpc_id = aws_vpc.source.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.source.id
  }
}
resource "aws_route_table_association" "source" {
  for_each       = aws_subnet.source
  subnet_id      = each.value.id
  route_table_id = aws_route_table.source.id
}

resource "aws_iam_role" "cluster" {
  name               = "${local.name}-cluster"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "eks.amazonaws.com" }, Action = "sts:AssumeRole" }] })
}
resource "aws_iam_role_policy_attachment" "cluster" {
  role       = aws_iam_role.cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}
resource "aws_cloudwatch_log_group" "control" {
  name              = "/aws/eks/${local.name}/cluster"
  retention_in_days = 1
}
resource "aws_eks_cluster" "source" {
  name                      = local.name
  role_arn                  = aws_iam_role.cluster.arn
  version                   = "1.35"
  enabled_cluster_log_types = ["audit", "authenticator"]
  access_config {
    authentication_mode                         = "API"
    bootstrap_cluster_creator_admin_permissions = false
  }
  upgrade_policy { support_type = "STANDARD" }
  vpc_config {
    subnet_ids              = [for subnet in aws_subnet.source : subnet.id]
    endpoint_private_access = true
    endpoint_public_access  = var.operator_cidr != null
    public_access_cidrs     = var.operator_cidr == null ? null : [var.operator_cidr]
  }
  depends_on = [aws_iam_role_policy_attachment.cluster, aws_cloudwatch_log_group.control]
}
resource "aws_eks_access_entry" "operator" {
  cluster_name  = aws_eks_cluster.source.name
  principal_arn = var.operator_arn
  type          = "STANDARD"
}
resource "aws_eks_access_policy_association" "operator" {
  cluster_name  = aws_eks_cluster.source.name
  principal_arn = var.operator_arn
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
  access_scope { type = "cluster" }
  depends_on = [aws_eks_access_entry.operator]
}
resource "aws_iam_role" "node" {
  name               = "${local.name}-node"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }] })
}
resource "aws_iam_role_policy_attachment" "node" {
  for_each   = toset(["AmazonEKSWorkerNodePolicy", "AmazonEC2ContainerRegistryPullOnly", "AmazonEKS_CNI_Policy", "AmazonSSMManagedInstanceCore"])
  role       = aws_iam_role.node.name
  policy_arn = "arn:aws:iam::aws:policy/${each.value}"
}
resource "aws_launch_template" "node" {
  name_prefix = "${local.name}-"
  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      encrypted             = true
      volume_type           = "gp3"
      volume_size           = 20
      delete_on_termination = true
    }
  }
  tag_specifications {
    resource_type = "instance"
    tags          = local.tags
  }
  tag_specifications {
    resource_type = "volume"
    tags          = local.tags
  }
}
resource "aws_eks_node_group" "source" {
  cluster_name    = aws_eks_cluster.source.name
  node_group_name = "qualification"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = [aws_subnet.source["a"].id]
  ami_type        = "AL2023_ARM_64_STANDARD"
  instance_types  = ["t4g.medium"]
  capacity_type   = "ON_DEMAND"
  launch_template {
    id      = aws_launch_template.node.id
    version = aws_launch_template.node.latest_version
  }
  scaling_config {
    desired_size = 1
    min_size     = 1
    max_size     = 1
  }
  update_config { max_unavailable = 1 }
  depends_on = [aws_iam_role_policy_attachment.node, aws_route_table_association.source]
}
resource "aws_ecr_repository" "app" {
  name                 = local.name
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration { scan_on_push = true }
  force_delete = true # This repository is disposable, run-owned qualification data.
}

output "cluster_name" { value = aws_eks_cluster.source.name }
output "cluster_arn" { value = aws_eks_cluster.source.arn }
output "repository_url" { value = aws_ecr_repository.app.repository_url }
output "vpc_id" { value = aws_vpc.source.id }
