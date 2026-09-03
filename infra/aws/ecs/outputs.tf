# ─── Public Service Endpoints ─────────────────────────────────────────────────

output "gateway_url" {
  description = "AgentWall Local Observability Proxy Endpoint (Port 8080)"
  value       = "http://${aws_lb.alb.dns_name}:8080"
}

output "control_plane_url" {
  description = "AgentWall Enterprise Control Plane & SOC Dashboard (Port 8081)"
  value       = "http://${aws_lb.alb.dns_name}:8081"
}

output "control_plane_ui_url" {
  description = "Alias for control_plane_url — matches cross-platform consistency"
  value       = "http://${aws_lb.alb.dns_name}:8081"
}

output "dashboard_api_url" {
  description = "AgentWall Dashboard API internal endpoint (Port 8400 — container-internal only, no public ALB listener). Gateway and UI communicate with this via 127.0.0.1:8400 inside the task."
  value       = "http://127.0.0.1:8400"
}

output "health_check_url" {
  description = "Health check endpoint URL"
  value       = "http://${aws_lb.alb.dns_name}:8080/healthz"
}

# ─── Resource & Environment Identifiers ───────────────────────────────────────

output "aws_region" {
  value = var.aws_region
}

output "environment" {
  value = var.environment
}

output "ecs_cluster_name" {
  value = aws_ecs_cluster.main.name
}

output "ecs_service_name" {
  value = aws_ecs_service.agentwall.name
}

output "container_image_in_use" {
  value = var.container_image
}

output "ecr_repository_urls" {
  description = "Map of provisioned Amazon ECR repository URLs (when ecr_enabled = true)"
  value       = var.ecr_enabled ? { for k, v in aws_ecr_repository.repos : k => v.repository_url } : {}
}

# ─── Verification & Diagnostics ───────────────────────────────────────────────

output "quick_verify_command" {
  description = "Universal curl command to verify gateway health"
  value       = "curl -i http://${aws_lb.alb.dns_name}:8080/healthz"
}

output "view_gateway_logs_command" {
  description = "AWS CLI command to tail gateway container logs"
  value       = "aws logs tail /ecs/${local.name_prefix} --follow --filter-pattern \"gateway\""
}
