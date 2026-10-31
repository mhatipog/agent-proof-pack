terraform {
  required_version = ">= 1.8.0"
  required_providers {
    local = {
      source  = "hashicorp/local"
      version = "2.8.0"
    }
  }
}
# Local-only sandbox. No cloud account, external service or production secret.
resource "local_file" "proof" {
  filename = "${path.module}/proof.txt"
  content  = "agent-proof-v04-ok"
}
