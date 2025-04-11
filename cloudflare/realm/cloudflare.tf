#
# Best practice is to omit the api_token so that Terraform will pull it from the environment
# variable ${CLOUDFLARE_API_TOKEN}
#
# export CLOUDFLARE_API_TOKEN=your-api-token
#
provider "cloudflare" {
#  api_token = ""
}

provider "aws" {
  region = "eu-west-1"
}

variable "account_id" {
  default = "6016d21c1b1884e16254c3188a8dc0e6"
}

variable "team_name" {
  default = "palringo"
}

variable "demo_users" {
  default = [
             {
                description = "Al's Realm test user"
                value       = "chr0m4t1c@gmail.com"
             }
            ]
}

module "cloudflare_base" {
  source = "../modules/cloudflare_base"

  account_id = var.account_id
  team_name  = var.team_name
  tunnel_name = "realm-core-infra-dev"
  admin_site_users = var.demo_users
  ssh_users = var.demo_users
  titan_staging_users = var.demo_users
}

#
# Additional Tunnels/Routes
#

resource "cloudflare_tunnel_route" "wolf_legacy_management_vpc" {
  account_id         = var.account_id
  tunnel_id          = module.cloudflare_base.outputs.base_tunnel_id
  network            = "172.27.0.0/16"
  comment            = "Wolf legacy management"
  virtual_network_id = module.cloudflare_base.outputs.default_vnet_id
}

resource "cloudflare_tunnel_route" "wolf_legacy_staging_vpc" {
  account_id         = var.account_id
  tunnel_id          = module.cloudflare_base.outputs.base_tunnel_id
  network            = "172.28.0.0/16"
  comment            = "Wolf legacy staging"
  virtual_network_id = module.cloudflare_base.outputs.default_vnet_id
}

output "Cognito-Reminder" {
  value = format("AWS Cognito will need to be configured to allow the following callback URL: https://%s.cloudflareaccess.com/cdn-cgi/access/callback", var.team_name)
}

output "Google-Cloud-Reminder" {
  value = format("Google Cloud will need to be configured to allow the following Javascript origin URL and Redirect URL: https://%s.cloudflareaccess.com, https://%s.cloudflareaccess.com/cdn-cgi/access/callback", var.team_name, var.team_name)
}
