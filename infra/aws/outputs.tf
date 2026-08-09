# ─── Cluster ──────────────────────────────────────────────────────────────────

output "cluster_name" {
  description = "Name of the EKS cluster."
  value       = aws_eks_cluster.this.name
}

output "cluster_endpoint" {
  description = "Kubernetes API server endpoint."
  value       = aws_eks_cluster.this.endpoint
}

output "cluster_version" {
  description = "Kubernetes version running on the cluster."
  value       = aws_eks_cluster.this.version
}

output "cluster_certificate_authority_data" {
  description = "Base64-encoded CA certificate for the EKS cluster."
  value       = aws_eks_cluster.this.certificate_authority[0].data
  sensitive   = true
}

output "oidc_issuer_url" {
  description = "OIDC issuer URL for IAM Roles for Service Accounts (IRSA)."
  value       = local.oidc_issuer_url
}

output "oidc_provider_arn" {
  description = "ARN of the IAM OIDC identity provider."
  value       = local.oidc_provider_arn
}

# ─── Networking ───────────────────────────────────────────────────────────────

output "vpc_id" {
  description = "ID of the VPC created for the cluster."
  value       = aws_vpc.this.id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets (Fargate pods run here)."
  value       = aws_subnet.private[*].id
}

output "public_subnet_ids" {
  description = "IDs of the public subnets (load balancers are placed here)."
  value       = aws_subnet.public[*].id
}

# ─── Fargate Profiles ─────────────────────────────────────────────────────────

output "fargate_profile_agentwall_arn" {
  description = "ARN of the AgentWall Fargate Profile."
  value       = aws_eks_fargate_profile.agentwall.arn
}

output "fargate_profile_kube_system_arn" {
  description = "ARN of the Kube System Fargate Profile."
  value       = aws_eks_fargate_profile.kube_system.arn
}

output "fargate_pod_execution_role_arn" {
  description = "IAM role ARN assumed by Fargate pods."
  value       = aws_iam_role.fargate.arn
}

# ─── Post-deploy helper ───────────────────────────────────────────────────────

output "kubeconfig_command" {
  description = "Run this command to update your local kubeconfig after apply."
  value       = "aws eks update-kubeconfig --region ${var.aws_region} --name ${aws_eks_cluster.this.name}"
}

output "health_check_command" {
  description = "Port-forward and health-check command once kubeconfig is updated."
  value       = "kubectl port-forward svc/agentwall-gateway 8080:8080 -n ${var.agentwall_namespace}"
}

# ─── ECR ──────────────────────────────────────────────────────────────────

output "ecr_repository_urls" {
  description = "Map of image name → ECR repository URL for all AgentWall components."
  value       = { for k, v in aws_ecr_repository.agentwall : k => v.repository_url }
}

output "ecr_registry_url" {
  description = "Base ECR registry URL for this account/region (use with docker login)."
  value       = var.ecr_enabled ? "${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com" : ""
}

output "ecr_login_command" {
  description = "Run this command to authenticate Docker with ECR before pushing images."
  value       = var.ecr_enabled ? "aws ecr get-login-password --region ${var.aws_region} | docker login --username AWS --password-stdin ${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com" : ""
}

# ─── ACM & ALB ─────────────────────────────────────────────────────────────────

output "acm_certificate_arn" {
  description = "ARN of the ACM certificate in use (either created or pre-existing)."
  value       = local.resolved_acm_certificate_arn
}

output "acm_validation_records" {
  description = "DNS CNAME records required for ACM certificate validation (when create_route53_records = false)."
  value = length(aws_acm_certificate.agentwall) > 0 ? [
    for dvo in aws_acm_certificate.agentwall[0].domain_validation_options : {
      name  = dvo.resource_record_name
      type  = dvo.resource_record_type
      value = dvo.resource_record_value
    }
  ] : []
}

output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer provisioned by the ALB Ingress Controller. Point your domain CNAME here."
  value       = length(kubernetes_ingress_v1.agentwall) > 0 ? kubernetes_ingress_v1.agentwall[0].status[0].load_balancer[0].ingress[0].hostname : ""
}

output "agentwall_url" {
  description = "Public HTTPS endpoint for the AgentWall gateway (available after ALB is provisioned)."
  value       = var.domain_name != "" ? "https://agentwall.${var.domain_name}" : (
    length(kubernetes_ingress_v1.agentwall) > 0 ? "http://${try(kubernetes_ingress_v1.agentwall[0].status[0].load_balancer[0].ingress[0].hostname, "<pending>")}/" : ""
  )
}
