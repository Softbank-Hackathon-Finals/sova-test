# AWS source for the hybrid workload response runner (EKS source, local RKE2 target).
# Disposable and run-owned: one VPC, one EKS cluster, one node group, one ECR
# repository. Destroy with `terraform destroy` when the run ends.
terraform {
  required_version = ">= 1.15, < 2.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "= 6.67.0" }
  }
  backend "local" {}
}

variable "region" {
  type    = string
  default = "ap-northeast-2"
}
variable "account_id" { type = string }
variable "operator_arn" { type = string }
variable "operator_cidr" {
  type = string
  validation {
    condition     = can(cidrnetmask(var.operator_cidr)) && endswith(var.operator_cidr, "/32")
    error_message = "Public API access must be restricted to one operator IPv4 /32."
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
variable "kubernetes_version" {
  type    = string
  default = "1.35"
}
# Pinned: the support record binds the CNI and policy engine images, so an
# add-on upgrade is a deliberate change that needs requalification.
variable "addon_versions" {
  type = map(string)
  default = {
    "vpc-cni"                = "v1.22.4-eksbuild.14"
    "kube-proxy"             = "v1.35.3-eksbuild.69"
    "eks-pod-identity-agent" = "v1.4.1-eksbuild.3"
    "coredns"                = "v1.13.2-eksbuild.75"
    "aws-ebs-csi-driver"     = "v1.68.0-eksbuild.1"
  }
}
variable "node_release_version" {
  type    = string
  default = "1.35.9-20261107"
}

locals {
  name = "sova-response-${var.run_id}"
  tags = {
    Project   = "Sova"
    component = "sova-response-hybrid-source"
    RunId     = var.run_id
    ExpiresAt = var.expires_at
    ManagedBy = "Terraform"
  }
}

provider "aws" {
  region              = var.region
  allowed_account_ids = [var.account_id]
  default_tags { tags = local.tags }
}

# Public subnets without a NAT gateway keep the run cheap. Nodes get public
# addresses but only the EKS-managed cluster security group admits traffic.
resource "aws_vpc" "source" {
  cidr_block           = "172.28.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = local.name }
}
resource "aws_internet_gateway" "source" { vpc_id = aws_vpc.source.id }
resource "aws_subnet" "source" {
  for_each                = { a = { cidr = "172.28.10.0/24", az = "${var.region}a" }, c = { cidr = "172.28.20.0/24", az = "${var.region}c" } }
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
  retention_in_days = 3
}
resource "aws_eks_cluster" "source" {
  name                          = local.name
  role_arn                      = aws_iam_role.cluster.arn
  version                       = var.kubernetes_version
  enabled_cluster_log_types     = ["audit", "authenticator"]
  bootstrap_self_managed_addons = false
  access_config {
    authentication_mode                         = "API"
    bootstrap_cluster_creator_admin_permissions = false
  }
  upgrade_policy { support_type = "STANDARD" }
  vpc_config {
    subnet_ids              = [for subnet in aws_subnet.source : subnet.id]
    endpoint_private_access = true
    endpoint_public_access  = true
    public_access_cidrs     = [var.operator_cidr]
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

# Node networking add-ons come first so nodes join Ready. The VPC CNI network
# policy agent enforces Kubernetes NetworkPolicy on the source workload.
resource "aws_eks_addon" "vpc_cni" {
  cluster_name                = aws_eks_cluster.source.name
  addon_name                  = "vpc-cni"
  addon_version               = var.addon_versions["vpc-cni"]
  resolve_conflicts_on_create = "OVERWRITE"
  configuration_values        = jsonencode({ enableNetworkPolicy = "true" })
}
resource "aws_eks_addon" "kube_proxy" {
  cluster_name                = aws_eks_cluster.source.name
  addon_name                  = "kube-proxy"
  addon_version               = var.addon_versions["kube-proxy"]
  resolve_conflicts_on_create = "OVERWRITE"
}
resource "aws_eks_addon" "pod_identity" {
  cluster_name                = aws_eks_cluster.source.name
  addon_name                  = "eks-pod-identity-agent"
  addon_version               = var.addon_versions["eks-pod-identity-agent"]
  resolve_conflicts_on_create = "OVERWRITE"
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
# Two nodes in one AZ: the source DB volume is zonal EBS, so it can move to the
# other node without crossing zones. Scale-out has room for a second worker.
resource "aws_eks_node_group" "source" {
  cluster_name    = aws_eks_cluster.source.name
  node_group_name = "source"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = [aws_subnet.source["a"].id]
  ami_type        = "AL2023_ARM_64_STANDARD"
  release_version = var.node_release_version
  instance_types  = ["t4g.medium"]
  capacity_type   = "ON_DEMAND"
  launch_template {
    id      = aws_launch_template.node.id
    version = aws_launch_template.node.latest_version
  }
  scaling_config {
    desired_size = 2
    min_size     = 2
    max_size     = 2
  }
  update_config { max_unavailable = 1 }
  depends_on = [
    aws_iam_role_policy_attachment.node,
    aws_route_table_association.source,
    aws_eks_addon.vpc_cni,
    aws_eks_addon.kube_proxy,
    aws_eks_addon.pod_identity,
  ]
}

resource "aws_eks_addon" "coredns" {
  cluster_name                = aws_eks_cluster.source.name
  addon_name                  = "coredns"
  addon_version               = var.addon_versions["coredns"]
  resolve_conflicts_on_create = "OVERWRITE"
  depends_on                  = [aws_eks_node_group.source]
}

resource "aws_iam_role" "ebs_csi" {
  name = "${local.name}-ebs-csi"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [{ Effect = "Allow", Principal = { Service = "pods.eks.amazonaws.com" }, Action = ["sts:AssumeRole", "sts:TagSession"] }]
  })
}
resource "aws_iam_role_policy_attachment" "ebs_csi" {
  role       = aws_iam_role.ebs_csi.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
}
resource "aws_eks_addon" "ebs_csi" {
  cluster_name  = aws_eks_cluster.source.name
  addon_name    = "aws-ebs-csi-driver"
  addon_version = var.addon_versions["aws-ebs-csi-driver"]
  # Dynamically provisioned volumes are outside Terraform's default_tags;
  # tag them so cost and the post-destroy leftover check can find them.
  configuration_values = jsonencode({
    controller = { extraVolumeTags = { RunId = var.run_id, component = local.tags.component, ExpiresAt = var.expires_at } }
  })
  resolve_conflicts_on_create = "OVERWRITE"
  pod_identity_association {
    role_arn        = aws_iam_role.ebs_csi.arn
    service_account = "ebs-csi-controller-sa"
  }
  depends_on = [aws_eks_node_group.source, aws_iam_role_policy_attachment.ebs_csi]
}

resource "aws_ecr_repository" "app" {
  name                 = local.name
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration { scan_on_push = true }
  force_delete = true # Disposable, run-owned images only.
}

output "cluster_name" { value = aws_eks_cluster.source.name }
output "cluster_arn" { value = aws_eks_cluster.source.arn }
output "repository_url" { value = aws_ecr_repository.app.repository_url }
output "vpc_id" { value = aws_vpc.source.id }
output "node_group_asg" { value = aws_eks_node_group.source.resources[0].autoscaling_groups[0].name }
