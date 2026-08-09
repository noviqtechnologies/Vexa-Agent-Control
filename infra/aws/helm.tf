# ─── AgentWall Helm Release ───────────────────────────────────────────────────
#
# Equivalent to the manual command from the deployment guide, enhanced with:
#   • ECR image repositories (when ecr_enabled = true)
#   • TLS disabled at pod level — the ALB terminates HTTPS externally

locals {
  # When ECR is enabled, map each Helm image.repository key to its ECR URI.
  # When ECR is disabled, an empty map means no set blocks are generated and
  # the chart falls back to its default Docker Hub image paths.
  ecr_image_sets = var.ecr_enabled ? {
    "gateway.image.repository"            = "${local.ecr_base_url}/agentwall"
    "operator.image.repository"           = "${local.ecr_base_url}/agentwall-operator"
    "dashboardApi.image.repository"       = "${local.ecr_base_url}/agentwall-dashboard-api"
    "dashboardFrontend.image.repository"  = "${local.ecr_base_url}/agentwall-dashboard-frontend"
  } : {}

  # TLS at the pod level:
  #   • ALB mode  → gateway speaks plain HTTP (ALB terminates HTTPS)
  #   • Self-signed fallback → only when no domain / cert is configured
  pod_tls_enabled       = local.resolved_acm_certificate_arn == "" && var.tls_create_self_signed
  pod_tls_self_signed   = local.resolved_acm_certificate_arn == "" && var.tls_create_self_signed
}

resource "helm_release" "agentwall" {
  name             = "agentwall"
  chart            = var.chart_path
  namespace        = var.agentwall_namespace
  create_namespace = true

  # ── Gateway ────────────────────────────────────────────────────────────────
  set {
    name  = "gateway.replicas"
    value = var.gateway_replicas
  }

  set {
    name  = "gateway.tls.enabled"
    value = tostring(local.pod_tls_enabled)
  }

  set {
    name  = "gateway.tls.createSelfSigned"
    value = tostring(local.pod_tls_self_signed)
  }

  set {
    name  = "gateway.mcpUrl"
    value = var.mcp_url
  }

  # ── ECR image repositories (dynamic — only set when ecr_enabled = true) ───
  dynamic "set" {
    for_each = local.ecr_image_sets
    content {
      name  = set.key
      value = set.value
    }
  }

  # ── Dashboard API ──────────────────────────────────────────────────────────
  set {
    name  = "dashboardApi.enabled"
    value = "true"
  }

  # ── Dashboard Frontend ─────────────────────────────────────────────────────
  set {
    name  = "dashboardFrontend.enabled"
    value = "true"
  }

  # ── Dashboard Database (PostgreSQL) ────────────────────────────────────────
  set {
    name  = "dashboardDb.enabled"
    value = "true"
  }

  set {
    name  = "dashboardDb.storageClass"
    value = "gp3"
  }

  # ── Policy CR ──────────────────────────────────────────────────────────────
  set {
    name  = "policy.create"
    value = "false"
  }

  # ── CRDs ───────────────────────────────────────────────────────────────────
  set {
    name  = "crds.install"
    value = "true"
  }

  # Wait until all pods are Running before marking the release as complete.
  # This ensures the CRDs are available for the kubernetes_manifest in policy.tf.
  wait          = true
  wait_for_jobs = true
  timeout       = 600 # 10 minutes

  depends_on = [
    kubernetes_storage_class_v1.gp3,
    aws_eks_addon.coredns,
    aws_eks_addon.vpc_cni,
    aws_eks_addon.kube_proxy,
    aws_eks_addon.ebs_csi_driver,
    aws_ecr_repository.agentwall,
  ]
}

