# =============================================================================
# SVT System — Terraform Variables
# =============================================================================

variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP region for all resources"
  type        = string
  default     = "us-central1"
}

variable "db_tier" {
  description = "Cloud SQL machine tier"
  type        = string
  default     = "db-custom-2-8192"  # 2 vCPU, 8GB RAM
}

variable "db_app_password" {
  description = "Password for the svt_app database user"
  type        = string
  sensitive   = true
}

variable "deletion_protection" {
  description = "Enable deletion protection for critical resources"
  type        = bool
  default     = true
}
