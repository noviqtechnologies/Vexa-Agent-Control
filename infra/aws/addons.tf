# ─── IAM Role for EBS CSI Driver (IRSA) ──────────────────────────────────────

resource "aws_iam_role" "ebs_csi_driver" {
  name = "${var.cluster_name}-ebs-csi-driver"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = local.oidc_provider_arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${local.oidc_provider_host}:sub" = "system:serviceaccount:kube-system:ebs-csi-controller-sa"
          "${local.oidc_provider_host}:aud" = "sts.amazonaws.com"
        }
      }
    }]
  })

  tags = {
    Name = "${var.cluster_name}-ebs-csi-driver-role"
  }
}

resource "aws_iam_role_policy_attachment" "ebs_csi_driver" {
  role       = aws_iam_role.ebs_csi_driver.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
}

# ─── EKS Add-ons ──────────────────────────────────────────────────────────────

resource "aws_eks_addon" "vpc_cni" {
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = "vpc-cni"
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"

  depends_on = [aws_eks_fargate_profile.kube_system]

  tags = { Name = "${var.cluster_name}-vpc-cni" }
}

resource "aws_eks_addon" "coredns" {
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = "coredns"
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"

  depends_on = [
    aws_eks_fargate_profile.kube_system,
    aws_eks_fargate_profile.agentwall
  ]

  tags = { Name = "${var.cluster_name}-coredns" }
}

resource "aws_eks_addon" "kube_proxy" {
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = "kube-proxy"
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"

  depends_on = [aws_eks_fargate_profile.kube_system]

  tags = { Name = "${var.cluster_name}-kube-proxy" }
}

resource "aws_eks_addon" "ebs_csi_driver" {
  cluster_name             = aws_eks_cluster.this.name
  addon_name               = "aws-ebs-csi-driver"
  service_account_role_arn = aws_iam_role.ebs_csi_driver.arn
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"

  depends_on = [
    aws_eks_fargate_profile.kube_system,
    aws_iam_role_policy_attachment.ebs_csi_driver,
  ]

  tags = { Name = "${var.cluster_name}-ebs-csi-driver" }
}

# ─── Patch CoreDNS for Fargate Execution ───────────────────────────────────────
# By default CoreDNS has `eks.amazonaws.com/compute-type: ec2` annotation which
# prevents CoreDNS pods from scheduling onto Fargate nodes. Unsetting it allows
# CoreDNS to run on Fargate seamlessly.

resource "kubernetes_annotations" "coredns_fargate" {
  api_version = "apps/v1"
  kind        = "Deployment"

  metadata {
    name      = "coredns"
    namespace = "kube-system"
  }

  annotations = {
    "eks.amazonaws.com/compute-type" = "fargate"
  }

  force = true

  depends_on = [
    aws_eks_addon.coredns,
    aws_eks_fargate_profile.kube_system
  ]
}
