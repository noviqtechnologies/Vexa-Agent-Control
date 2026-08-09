# ─── Region & naming ──────────────────────────────────────────────────────────

variable "aws_region" {
  description = "AWS region to deploy all resources into."
  type        = string
  default     = "eu-west-1" # Ireland
}

variable "environment" {
  description = "Deployment environment tag (e.g. dev, staging, production)."
  type        = string
  default     = "dev"
}

variable "cluster_name" {
  description = "Name of the EKS cluster."
  type        = string
  default     = "agentwall-eks-cluster"
}

variable "cluster_version" {
  description = "Kubernetes version for the EKS control plane."
  type        = string
  default     = "1.31"
}

# ─── VPC ──────────────────────────────────────────────────────────────────────

variable "vpc_cidr" {
  description = "CIDR block for the dedicated VPC."
  type        = string
  default     = "10.0.0.0/16"
}

# ─── AgentWall application ────────────────────────────────────────────────────

variable "agentwall_namespace" {
  description = "Kubernetes namespace where AgentWall is deployed."
  type        = string
  default     = "agentwall-system"
}

variable "gateway_replicas" {
  description = "Number of AgentWall gateway pod replicas."
  type        = number
  default     = 1
}

variable "chart_path" {
  description = "Path to the AgentWall Helm chart directory (relative to this module or absolute)."
  type        = string
  default     = "../../chart"
}

variable "tls_create_self_signed" {
  description = "When true, the Helm chart generates a self-signed TLS certificate. Not used when domain_name is set and ACM/ALB handles TLS termination."
  type        = bool
  default     = false
}

variable "mcp_url" {
  description = "Upstream MCP server URL that the AgentWall gateway forwards allowed calls to."
  type        = string
  default     = "http://mock-mcp:3000"
}

# ─── ECR ──────────────────────────────────────────────────────────────────────

variable "ecr_enabled" {
  description = "When true, creates ECR repositories for all AgentWall images and configures the Helm chart to pull from ECR instead of Docker Hub."
  type        = bool
  default     = true
}

# ─── ACM & TLS ────────────────────────────────────────────────────────────────

variable "domain_name" {
  description = "Root domain name used for the ACM certificate and ALB Ingress host rule (e.g. example.com). Leave empty to skip ACM/ALB TLS setup."
  type        = string
  default     = ""
}

variable "acm_certificate_arn" {
  description = "ARN of a pre-existing ACM certificate to use for the ALB Ingress. Takes precedence over domain_name when set."
  type        = string
  default     = ""
}

variable "create_route53_records" {
  description = "When true, creates Route 53 DNS validation CNAME records automatically. Requires route53_zone_id. Set to false to add DNS records manually."
  type        = bool
  default     = false
}

variable "route53_zone_id" {
  description = "Route 53 hosted zone ID for the domain. Required when create_route53_records = true."
  type        = string
  default     = ""
}

# ─── Tagging ──────────────────────────────────────────────────────────────────

variable "tags" {
  description = "Additional AWS resource tags merged with the module defaults."
  type        = map(string)
  default     = {}
}
