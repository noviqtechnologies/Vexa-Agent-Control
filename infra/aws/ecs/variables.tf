# ─── AWS Region & Environment ─────────────────────────────────────────────────

variable "aws_region" {
  description = "AWS region to deploy resources (e.g. eu-west-1, us-east-1)."
  type        = string
  default     = "eu-west-1"
}

variable "environment" {
  description = "Deployment environment name (e.g. stage, dev, prod)."
  type        = string
  default     = "stage"
}

# ─── Container Images ─────────────────────────────────────────────────────────

variable "container_image" {
  description = "Container image for the AgentControl Gateway proxy."
  type        = string
  default     = "ghcr.io/noviqtechnologies/agentcontrol:latest"
}

variable "control_plane_ui_image" {
  description = "Enterprise Control Plane UI container image."
  type        = string
  default     = "ghcr.io/noviqtechnologies/agentcontrol-dashboard-frontend:latest"
}

variable "control_plane_api_image" {
  description = "Enterprise Control Plane API container image."
  type        = string
  default     = "ghcr.io/noviqtechnologies/agentcontrol-dashboard-api:latest"
}

variable "control_plane_db_image" {
  description = "Control Plane PostgreSQL Database container image with migrations."
  type        = string
  default     = "ghcr.io/noviqtechnologies/agentcontrol-db:latest"
}

# ─── Task Sizing & Resources ──────────────────────────────────────────────────

variable "task_cpu" {
  description = "Fargate task CPU units (1024 = 1.0 vCPU, 512 = 0.5 vCPU)."
  type        = string
  default     = "1024"
}

variable "task_memory" {
  description = "Fargate task memory in MiB (2048 = 2 GiB, 1024 = 1 GiB)."
  type        = string
  default     = "2048"
}

variable "desired_count" {
  description = "Desired number of ECS service task replicas."
  type        = number
  default     = 1
}

# ─── Secrets & Credentials ────────────────────────────────────────────────────

variable "gateway_secret" {
  description = "Shared secret authenticating telemetry pushes. If empty, auto-generated."
  type        = string
  default     = ""
  sensitive   = true
}

variable "policy_read_secret" {
  description = "Shared secret for gateway policy pulls. If empty, auto-generated."
  type        = string
  default     = ""
  sensitive   = true
}

variable "encryption_secret" {
  description = "Master 32-byte hex encryption key (64 hex characters). If empty, auto-generated."
  type        = string
  default     = ""
  sensitive   = true
}

variable "session_secret" {
  description = "Session cookie signing secret. If empty, auto-generated."
  type        = string
  default     = ""
  sensitive   = true
}

variable "postgres_user" {
  description = "PostgreSQL username."
  type        = string
  default     = "agentwall"
}

variable "postgres_password" {
  description = "PostgreSQL password. If empty, auto-generated."
  type        = string
  default     = ""
  sensitive   = true
}

variable "postgres_db" {
  description = "PostgreSQL database name."
  type        = string
  default     = "agentcontrol"
}

variable "database_url" {
  description = "Optional connection string for a persistent external PostgreSQL database (e.g. RDS, Neon, Supabase). When set, the dashboard API connects directly to this database."
  type        = string
  default     = ""
  sensitive   = true
}

variable "enable_rds" {
  description = "When true, provisions an Amazon RDS PostgreSQL instance. Default is false to minimize staging deployment cost."
  type        = bool
  default     = false
}

variable "rds_instance_class" {
  description = "Database instance class for managed RDS PostgreSQL (e.g. 'db.t4g.micro')."
  type        = string
  default     = "db.t4g.micro"
}

variable "rds_allocated_storage" {
  description = "Initial allocated storage in GB for RDS PostgreSQL."
  type        = number
  default     = 20
}

# ─── Amazon Elastic Container Registry (ECR) ──────────────────────────────────

variable "ecr_enabled" {
  description = "When true, provisions private Amazon ECR repositories with automated 2-version retention lifecycle policies."
  type        = bool
  default     = false
}

# ─── Custom Tags ──────────────────────────────────────────────────────────────

variable "tags" {
  description = "Custom AWS tags."
  type        = map(string)
  default     = {}
}
