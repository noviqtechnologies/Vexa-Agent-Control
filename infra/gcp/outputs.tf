# ─── Public Service Endpoints (Free Google Managed HTTPS / TLS) ───────────────

output "gateway_url" {
  description = "Public HTTPS endpoint for the AgentControl Gateway proxy."
  value       = google_cloud_run_v2_service.gateway.uri
}

output "control_plane_ui_url" {
  description = "Public HTTPS endpoint for the AgentControl Enterprise Control Plane UI."
  value       = google_cloud_run_v2_service.ui.uri
}

output "control_plane_url" {
  description = "Alias for control_plane_ui_url — matches cross-platform consistency."
  value       = google_cloud_run_v2_service.ui.uri
}

output "dashboard_api_url" {
  description = "Public HTTPS endpoint for the Control Plane Dashboard API."
  value       = google_cloud_run_v2_service.api.uri
}

output "health_check_url" {
  description = "Direct health check URL for the AgentControl Gateway."
  value       = "${google_cloud_run_v2_service.gateway.uri}/healthz"
}

# ─── Resource & Environment Identifiers ───────────────────────────────────────

output "gcp_project_id" {
  description = "Target Google Cloud Project ID."
  value       = var.gcp_project_id
}

output "gcp_region" {
  description = "Google Cloud deployment region."
  value       = var.gcp_region
}

output "environment" {
  description = "Deployed environment stage identifier."
  value       = var.environment
}

output "service_account_email" {
  description = "Email of the dedicated Cloud Run runtime service account."
  value       = google_service_account.cloud_run_sa.email
}

output "gateway_service_name" {
  description = "Name of the deployed AgentControl Gateway Cloud Run service."
  value       = google_cloud_run_v2_service.gateway.name
}

output "ui_service_name" {
  description = "Name of the deployed Control Plane UI Cloud Run service."
  value       = google_cloud_run_v2_service.ui.name
}

output "api_service_name" {
  description = "Name of the deployed Dashboard API & PostgreSQL Cloud Run service."
  value       = google_cloud_run_v2_service.api.name
}

output "artifact_registry_repo" {
  description = "Google Artifact Registry Docker repo URL (when enabled)."
  value       = var.gar_enabled ? "${var.gcp_region}-docker.pkg.dev/${var.gcp_project_id}/${local.repo_id}" : "disabled"
}

# ─── Cross-Platform Verification & Diagnostic Helpers ─────────────────────────

output "quick_verify_command" {
  description = "Universal curl command to verify gateway health across Windows, Linux, and macOS."
  value       = "curl -i ${google_cloud_run_v2_service.gateway.uri}/healthz"
}

output "view_gateway_logs_command" {
  description = "Google Cloud SDK command to stream live logs from the AgentControl Gateway service."
  value       = "gcloud run services logs tail ${google_cloud_run_v2_service.gateway.name} --project ${var.gcp_project_id} --region ${var.gcp_region}"
}
