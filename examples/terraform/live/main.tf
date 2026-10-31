terraform {
  required_version = ">= 1.8.0"
}

# Terraform's built-in provider. No external cloud, provider secrets, or network resources.
resource "terraform_data" "example" {
  input            = "synthetic-local-test"
  triggers_replace = "v1"
}
