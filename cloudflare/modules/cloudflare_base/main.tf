#
#  Important notes
#
#  If you have created a new Cloudflare team domain, you must also add the relevant callback URL to the allowed callback URLs for your authentication provider
#

variable "account_id" {
    description = "The Cloudflare account ID this configuration is for"
    type        = string
}

variable "team_name" {
    description = "The team name to use when creating the Zero Trust configuration."
    type        = string
}

variable "tunnel_name" {
    description = "The name to give the initial Warp tunnel."
    type        = string
}

variable "create_wolf_google_workspace" {
  description = "Set to true if wolf_google_workspace should be created"
  type        = bool
  default     = true
}

variable "cognito_secret" {
  description = "ARN of AWS Cognito secret"
  type        = string
  default     = "arn:aws:secretsmanager:eu-west-1:211125575581:secret:CloudflareCognitoSecret-dqGIxM"
}

variable "gws_secret" {
  description = "ARN of Google Workspace secret"
  type        = string
  default     = "arn:aws:secretsmanager:eu-west-1:211125575581:secret:CloudflareGoogleWorkspaceAuth-bq0J6q"
}

variable "realm_admins" {
  description = "List of users who will be granted Realm admin permissions"
  type        = list(object({
                  description = string
                  value       = string
                }))
  default     = []
}

variable "ssh_users" {
  description = "List of users who will be granted global SSH access"
  type        = list(object({
                  description = string
                  value       = string
                }))
  default     = []
}

variable "rds_staging_users" {
  description = "List of users who will be granted staging RDS access"
  type        = list(object({
                  description = string
                  value       = string
                }))
  default     = []
}

variable "titan_staging_users" {
  description = "List of users who will be granted Titan access in staging"
  type        = list(object({
                  description = string
                  value       = string
                }))
  default     = []
}

variable "admin_site_users" {
  description = "List of users who will be granted admin-site access in staging"
  type        = list(object({
                  description = string
                  value       = string
                }))
  default     = []
}

variable "rabbitmq_admin_users" {
  description = "List of users who will be granted RabbitMQ admin site access in staging"
  type        = list(object({
                  description = string
                  value       = string
                }))
  default     = []
}

#
# Sensitive data stored in AWS SecretsManager
#

data "aws_secretsmanager_secret_version" "realm_aws_cognito" {
  secret_id = var.cognito_secret
}

data "aws_secretsmanager_secret_version" "google_workspace" {
  secret_id = var.gws_secret
}

#
# Local variables
#

locals {
  realm_cognito_secret = jsondecode(data.aws_secretsmanager_secret_version.realm_aws_cognito.secret_string)
  realm_google_workspace_secret = jsondecode(data.aws_secretsmanager_secret_version.google_workspace.secret_string)
}

#
# Zero Trust organization
#
# N.B. Organizarions cannot be created in with Terraform.
# They must be created in the console and then imported, use the following command to import:
#
# terraform import module.cloudflare_base.cloudflare_access_organization.org_config ${ACCOUNT_ID}
#

resource "cloudflare_access_organization" "org_config" {
  account_id                         = var.account_id
  auth_domain                        = "${var.team_name}.cloudflareaccess.com"
  name                               = "${var.team_name}.cloudflareaccess.com"
  user_seat_expiration_inactive_time = "4380h"
  warp_auth_session_duration         = "8h"
  allow_authenticate_via_warp        = false
  auto_redirect_to_identity          = false
  is_ui_read_only                    = false
  custom_pages {
                forbidden = ""
                identity_denied = ""
               }
  login_design {
                background_color = ""
                footer_text = ""
                header_text = ""
                logo_path = ""
                text_color = ""
              }
}

resource "cloudflare_teams_account" "wolf_teams_account" {
  account_id = var.account_id
  activity_log_enabled = true
  logging {
    redact_pii = false
    settings_by_rule_type {
      dns {
        log_all = true
        log_blocks = false
      }
      http {
        log_all = true
        log_blocks = false
      }
      l4 {
        log_all = true
        log_blocks = false
      }
    }
  }
  proxy {
          root_ca = false
          tcp = true
          udp = true
          virtual_ip = false
        }
}

#
# Identity providers
#

resource "cloudflare_access_identity_provider" "realm_aws_cognito" {
  account_id         = "${var.account_id}"
  type               = "oidc"
  name               = "Realm AWS Cognito for ${var.team_name}"
  config {
           auth_url      = local.realm_cognito_secret["AuthUrl"]
           certs_url     = local.realm_cognito_secret["CertsUrl"]
           token_url     = local.realm_cognito_secret["TokenUrl"]
           client_id     = local.realm_cognito_secret["ClientId"]
           client_secret = local.realm_cognito_secret["ClientSecret"]
           scopes        = [
                             "openid",
                             "email",
                             "profile"
                           ]
        }
}

resource "cloudflare_access_identity_provider" "wolf_google_workspace" {
  count = var.create_wolf_google_workspace ? 1 : 0

  account_id         = var.account_id
  type               = "google-apps"
  name               = "Google Workspace for ${var.team_name}"
  config {
           apps_domain   = local.realm_google_workspace_secret["AppsDomain"]
           client_id     = local.realm_google_workspace_secret["ClientId"]
           client_secret = local.realm_google_workspace_secret["ClientSecret"]
        }
}


#
#
#

resource "cloudflare_access_group" "wolf_staff" {
  count = var.create_wolf_google_workspace ? 1 : 0

  account_id = var.account_id
  name       = "Wolf-staff"
  include {
        login_method = [ cloudflare_access_identity_provider.wolf_google_workspace[count.index].id ]
  }
}

#
# Access policies for Warp
#

resource "cloudflare_access_policy" "wolf_gmail_policy" {
  count = var.create_wolf_google_workspace ? 1 : 0

  account_id         = var.account_id
  approval_required = false
  isolation_required = false
  purpose_justification_required = false
  name = "Wolf-Gmail"
  decision = "allow"
  include {
    gsuite {
             email = [
                "ops@palringo.com"
                ]
             identity_provider_id = cloudflare_access_identity_provider.wolf_google_workspace[count.index].id
           }
    login_method = [ cloudflare_access_identity_provider.wolf_google_workspace[count.index].id ]
    any_valid_service_token = false
    certificate = false
    common_names = []
    device_posture = []
    email = []
    email_domain = []
    email_list = []
    everyone = false
    geo = []
    group = [ cloudflare_access_group.wolf_staff[count.index].id ]
    ip = []
    ip_list = []
    service_token = []
  }
}

resource "cloudflare_access_policy" "realm_cognito_policy" {
  account_id                     = var.account_id
  name                           = "Wolf-cognito"
  approval_required              = false
  isolation_required             = false
  purpose_justification_required = false
  decision                       = "allow"
  include {
    login_method = [ cloudflare_access_identity_provider.realm_aws_cognito.id ]
    any_valid_service_token = false
    certificate = false
    common_names = []
    device_posture = []
    email = []
    email_domain = []
    email_list = []
    everyone = false
    geo = []
    group = []
    ip = []
    ip_list = []
    service_token = []
  }
}

#
# Cloudflare Warp application
#

locals {
  wolf_gmail_policy_id = var.create_wolf_google_workspace ? [cloudflare_access_policy.wolf_gmail_policy[0].id] : []
  wolf_idp_id          = var.create_wolf_google_workspace ? [cloudflare_access_identity_provider.wolf_google_workspace[0].id] : []
#  warp_allowed_idps    = concat(local.wolf_gmail_policy_id, [cloudflare_access_policy.realm_cognito_policy.id])
  warp_allowed_idps    = concat(local.wolf_idp_id, [cloudflare_access_identity_provider.realm_aws_cognito.id] )
  warp_policies        = concat(local.wolf_gmail_policy_id, [cloudflare_access_policy.realm_cognito_policy.id])
}

resource "cloudflare_access_application" "warp" {
  account_id                  = var.account_id
  name                        = "Warp Login App"
  app_launcher_visible        = false
  type                        = "warp"
  auto_redirect_to_identity   = false
  allow_authenticate_via_warp = false
  policies                    = local.warp_policies
  allowed_idps                = local.warp_allowed_idps
}

#
# Warp device setting policies
#

resource "cloudflare_device_settings_policy" "default_device_settings_policy" {
  account_id         = "${var.account_id}"
  default = true
  name = ""
  description = ""
  captive_portal = 180
  enabled = true
  allowed_to_leave = true
  service_mode_v2_mode = "warp"
}

#
# Default domains
#

resource "cloudflare_fallback_domain" "wolf_fallback_domain" {
  account_id = "${var.account_id}"
  policy_id  = "${var.account_id}"
  domains {
            description = ""
            dns_server = []
            suffix = "corp"
          }
  domains {
            description = ""
            dns_server  = []
            suffix      = "domain"
          }
  domains {
            description = ""
            dns_server = []
            suffix = "home"
          }
  domains {
            description = ""
            dns_server = []
            suffix = "home.arpa"
          }
  domains {
            description = ""
            dns_server = []
            suffix = "host"
          }
  domains {
            description = ""
            dns_server = []
            suffix = "internal"
          }
  domains {
            description = ""
            dns_server = []
            suffix = "intranet"
          }
  domains {
            description = ""
            dns_server = []
            suffix = "invalid"
          }
  domains {
            description = ""
            dns_server = []
            suffix = "lan"
          }
  domains {
            description = ""
            dns_server = []
            suffix = "local"
          }
  domains {
            description = ""
            dns_server = []
            suffix = "localdomain"
          }
  domains {
            description = ""
            dns_server = []
            suffix = "localhost"
          }
  domains {
            description = ""
            dns_server = []
            suffix = "private"
          }
  domains {
            description = ""
            dns_server = []
            suffix = "test"
          }
  domains {
            description = "AWS resolver in Wolf shared staging"
            dns_server = [ "172.24.0.2" ]
            suffix = "staging.wolf.live"
          }
  domains {
            description = "Legacy test domain"
            dns_server = [ "172.24.0.2" ]
            suffix = "test.palringo.aws"
          }
}

#
# Split tunnel config
#

resource "cloudflare_split_tunnel" "default_split_tunnel_config" {
  account_id = "${var.account_id}"
  policy_id  = "${var.account_id}"
  mode       = "include"
  tunnels {
           host        = "${var.team_name}.cloudflareaccess.com"
          }
  tunnels {
           description = "Shared staging domains"
           host        = "staging.wolf.live"
          }
  tunnels {
           description = "Legacy test domain"
           host        = "test.palringo.aws"
          }
  tunnels {
           description = "Admin site for test"
           host        = "admin-site.test.palringo.aws"
          }
  tunnels {
           description = "Legacy swagger docs"
           host        = "api.mng.palringo.aws"
          }
  tunnels {
           description = "RabbitMQ in staging"
           host        = "rabbitmq.staging.wolf.live"
          }
  tunnels {
           address     = "172.24.0.0/16"
           description = "Wolf shared staging"
          }
  tunnels {
           address     = "172.27.0.0/16"
           description = "Wolf legacy management"
          }
  tunnels {
           address     = "172.28.0.0/16"
           description = "Wolf legacy staging"
          }
}


#
# Virtual networks
#

resource "cloudflare_tunnel_virtual_network" "default_vnet" {
  account_id         = var.account_id
  name               = "default"
  is_default_network = true
  comment            = "This network was autogenerated because this account lacked a default one"
}

#
# My Team/Lists in Cloudflare
#

resource "cloudflare_teams_list" "wolf_staging_vpcs" {
  account_id             = var.account_id
  name                   = "Wolf VPCs"
  description            = ""
  type                   = "IP"
  items_with_description = [
                             {
                               "description": "Wolf legacy management",
                               "value": "172.27.0.0/16"
                             },
                             {
                               "description": "Wolf legacy staging",
                               "value": "172.28.0.0/16"
                             },
                             {
                               "description": "Wolf shared staging",
                               "value": "172.24.0.0/16"
                             }
                           ]
}

resource "cloudflare_teams_list" "titan_staging_ips" {
  account_id             = var.account_id
  name                   = "Titan IPs (Staging)"
  description            = "IP addresses for the Titan database in staging to be used in firewall rules.  We have to use IP addresses rather than SNI because MySQL traffic does not originate at network layer 7 where those conditions are matched."
  type                   = "IP"
  items_with_description = [
                             {
                               "description": "Titan reader (Staging)",
                               "value": "172.24.77.145"
                             },
                             {
                               "description": "Titan writer (Staging)",
                               "value": "172.24.56.182"
                             }
                           ]
}

#
# My Team/Lists in Cloudflare
#

resource "cloudflare_teams_list" "realm_admin_list" {
  account_id             = var.account_id
  name                   = "Realm Admins"
  description            = "Users who are allowed admin privileges and are not a member of the Google group \"Server Team\""
  type                   = "EMAIL"
  items_with_description = var.realm_admins
}

resource "cloudflare_teams_list" "ssh_user_list" {
  account_id             = var.account_id
  name                   = "SSH users"
  description            = "List of users who will be authorized to use SSH and are not a member of the Google group \"Server Team\""
  type                   = "EMAIL"
  items_with_description = var.ssh_users
}

resource "cloudflare_teams_list" "rds_staging_user_list" {
  account_id             = var.account_id
  name                   = "RDS users (Staging)"
  description            = "Users who will be allowed access to any RDS database in staging and are not a member of the Google group \"Server Team\""
  type                   = "EMAIL"
  items_with_description = var.rds_staging_users
}

resource "cloudflare_teams_list" "titan_staging_user_list" {
  account_id             = var.account_id
  name                   = "Titan users (Staging)"
  description            = "List of users who will be authorized to use Titan in staging"
  type                   = "EMAIL"
  items_with_description = var.titan_staging_users
}

resource "cloudflare_teams_list" "admin_user_list" {
  account_id             = var.account_id
  name                   = "Admin site users (Staging)"
  description            = "List of users who will be authorized to use admin-site in staging"
  type                   = "EMAIL"
  items_with_description = var.admin_site_users
}

resource "cloudflare_teams_list" "rabbitmq_admin_list" {
  account_id             = var.account_id
  name                   = "RabbitMQ admin site users (Staging)"
  description            = "List of users who will be authorized to use RabbitMQ admin interface in staging"
  type                   = "EMAIL"
  items_with_description = var.rabbitmq_admin_users
}

resource "cloudflare_teams_list" "admin_site_urls" {
  account_id             = var.account_id
  name                   = "Admin sites"
  description            = ""
  type                   = "URL"
  items_with_description = [
                             {
                               "description": "Primary URL for test admin site",
                               "value": "http://admin-site.test.palringo.aws/"
                             },
                             {
                               "description": "Seconday URL for test admin site",
                               "value": "http://admin-site-redis-6.test.palringo.aws/"
                             }
                           ]
}

#
# Networks/Tunnels
#
# If you declare a cloudflared tunnel through the console GUI then the tunnel is created with config_src = "cloudflare"
# but if you then import it then that setting is not imported so delaring it will cause the tunnel to be replaced.
# Only declare config_src = "cloudflare" when creating tunnels through terraform
#

resource "cloudflare_tunnel" "base_tunnel" {
  account_id   = var.account_id
  name         = var.tunnel_name
  config_src   = "cloudflare"
  secret       = "85f0af81d9e442e39de7aabac00935bc"
}

#
# Tunnels/Routes
#

resource "cloudflare_tunnel_route" "wolf_shared_staging_vpc" {
  account_id         = var.account_id
  tunnel_id          = cloudflare_tunnel.base_tunnel.id
  network            = "172.24.0.0/16"
  comment            = "Wolf shared staging"
  virtual_network_id = cloudflare_tunnel_virtual_network.default_vnet.id
}

#
# Gateway/Firewall Policies/DNS
#

resource "cloudflare_teams_rule" "allow_internal_dns" {
  account_id  = var.account_id
  action      = "allow"
  description = "Allow internal DNS"
  enabled     = true
  filters     = ["dns"]
  name        = "Allow internal DNS"
  precedence  = 8
  traffic     = "any(dns.domains[*] == \"staging.wolf.live\") or any(dns.domains[*] == \"palringo.aws\") or any(dns.domains[*] == \"amazonaws.com\")"
  rule_settings {
    block_page_enabled                 = false
    insecure_disable_dnssec_validation = false
    ip_categories                      = false
    notification_settings {
      enabled = false
    }
  }
}


#
# Gateway/Firewall Policies/Network
#

resource "cloudflare_teams_rule" "allow_dns_lookups" {
  account_id  = var.account_id
  action      = "allow"
  description = "Allow DNS lookups"
  enabled     = true
  filters     = ["l4"]
  name        = "AWS DNS"
  precedence  = 0
  traffic     = "net.dst.port == 53"
  rule_settings {
    block_page_enabled                 = false
    insecure_disable_dnssec_validation = false
    ip_categories                      = false
    notification_settings {
      enabled = false
    }
  }
}

resource "cloudflare_teams_rule" "aws_public_passthrough" {
  account_id  = var.account_id
  action      = "allow"
  description = "Pass through amazonaws traffic that's for external services"
  enabled     = true
  filters     = ["l4"]
  name        = "AWS public passthrough"
  precedence  = 1
  traffic     = format("any(net.sni.domains[*] == \"amazonaws.com\") and not(net.dst.ip in $%s)", cloudflare_teams_list.wolf_staging_vpcs.id)
  rule_settings {
    block_page_enabled                 = false
    insecure_disable_dnssec_validation = false
    ip_categories                      = false
    notification_settings {
      enabled = false
    }
  }
}

resource "cloudflare_teams_rule" "allow_all_grafana" {
  account_id  = var.account_id
  action      = "allow"
  description = "Give everyone access to Grafana"
  enabled     = true
  filters     = ["l4"]
  name        = "Allow Grafana"
  precedence  = 0
  traffic     = "net.sni.host == \"monitoring.staging.wolf.live\""
  rule_settings {
    block_page_enabled                 = false
    insecure_disable_dnssec_validation = false
    ip_categories                      = false
    notification_settings {
      enabled = false
    }
  }
}

resource "cloudflare_teams_rule" "allow_ssh_users" {
  account_id  = var.account_id
  action      = "allow"
  description = "Allow SSH for authorised users"
  enabled     = true
  filters     = ["l4"]
  identity    = format("identity.email in $%s or any(identity.groups.name[*] in {\"Server Team\"})", cloudflare_teams_list.ssh_user_list.id)
  name        = "SSH"
  precedence  = 0
  traffic     = "net.dst.ip in {172.27.0.0/16 172.28.0.0/16 172.24.0.0/16} and net.dst.port == 22"
  rule_settings {
    block_page_enabled                 = false
    insecure_disable_dnssec_validation = false
    ip_categories                      = false
    notification_settings {
      enabled = false
    }
  }
}

resource "cloudflare_teams_rule" "allow_all_staging_rds" {
  account_id  = var.account_id
  action      = "allow"
  description = "Allow All RDS traffic for people in the correct group"
  enabled     = true
  filters     = ["l4"]
  identity    = format("identity.email in $%s or any(identity.groups.name[*] in {\"Server Team\"})", cloudflare_teams_list.rds_staging_user_list.id)
  name        = "RDS (All)"
  precedence  = 4
  traffic     = format("net.dst.ip in $%s and net.dst.port == 3306", cloudflare_teams_list.wolf_staging_vpcs.id)
  rule_settings {
    block_page_enabled                 = false
    insecure_disable_dnssec_validation = false
    ip_categories                      = false
    notification_settings {
      enabled = false
    }
  }
}

resource "cloudflare_teams_rule" "allow_titan_staging" {
  account_id  = var.account_id
  action      = "allow"
  description = "Allow access to Titan in staging"
  enabled     = true
  filters     = ["l4"]
  identity    = format("identity.email in $%s or identity.email in $%s", cloudflare_teams_list.realm_admin_list.id, cloudflare_teams_list.titan_staging_user_list.id)
  name        = "RDS (Titan)"
  precedence  = 8
  traffic     = format("net.dst.ip in $%s and net.dst.port == 3306", cloudflare_teams_list.titan_staging_ips.id)
  rule_settings {
    block_page_enabled                 = false
    insecure_disable_dnssec_validation = false
    ip_categories                      = false
    notification_settings {
      enabled = false
    }
  }
}

resource "cloudflare_teams_rule" "admin_site_access" {
  account_id  = var.account_id
  action      = "allow"
  description = "Allow staging admin-site access"
  enabled     = true
  filters     = ["l4"]
  identity    = format("identity.email in $%s or any(identity.groups.name[*] in {\"Server Team\"})", cloudflare_teams_list.realm_admin_list.id)
  name        = "Allow admin site"
  precedence  = 13
  traffic     = "net.sni.host in {\"admin-site-redis-6.test.palringo.aws\" \"admin-site.test.palringo.aws\"}"
  rule_settings {
    block_page_enabled                 = false
    insecure_disable_dnssec_validation = false
    ip_categories                      = false
    notification_settings {
      enabled = false
    }
  }
}

resource "cloudflare_teams_rule" "allow_admin_rabbitmq" {
  account_id  = var.account_id
  action      = "allow"
  description = "Allow members of the RabbitMQ-Admins group to access RabbitMQ in staging"
  enabled     = true
  filters     = ["l4"]
  identity    = format("identity.email in $%s or any(identity.groups.name[*] in {\"Server Team\"})", cloudflare_teams_list.rabbitmq_admin_list.id)
  name        = "RabbitMQ staging"
  precedence  = 13
  traffic     = "net.sni.host matches \"rabbitmq.*.staging.wolf.live\""
  rule_settings {
    block_page_enabled                 = false
    insecure_disable_dnssec_validation = false
    ip_categories                      = false
    notification_settings {
      enabled = false
    }
  }
}

resource "cloudflare_teams_rule" "http_legacy_staging" {
  account_id  = var.account_id
  action      = "allow"
  description = "Allow HTTP traffic to legacy staging network"
  enabled     = true
  filters     = ["l4"]
  name        = "Allow HTTP traffic"
  precedence  = 14
  traffic     = "net.dst.ip in {172.28.0.0/16} and net.dst.port in {80}"
  rule_settings {
    block_page_enabled                 = false
    insecure_disable_dnssec_validation = false
    ip_categories                      = false
    notification_settings {
      enabled = false
    }
  }
}

resource "cloudflare_teams_rule" "block_private_zone_sni" {
  account_id  = var.account_id
  action      = "block"
  description = "Default fall-back rule to block any web traffic to internal sites that are not whilelisted anywhere."
  enabled     = true
  filters     = ["l4"]
  identity    = "not(any(identity.groups.name[*] in {\"Server Team\"}))"
  name        = "Block all private SNI traffic"
  precedence  = 9998
  traffic     = "any(net.sni.domains[*] in {\"test.palringo.aws\" \"staging.wolf.live\"})"
  rule_settings {
    block_page_enabled                 = false
    insecure_disable_dnssec_validation = false
    ip_categories                      = false
    notification_settings {
      enabled = true
    }
  }
}

resource "cloudflare_teams_rule" "block_all_traffic" {
  account_id  = var.account_id
  action      = "block"
  description = "This should be the last rule, to block anything not allowed above"
  enabled     = true
  filters     = ["l4"]
  identity    = "not(any(identity.groups.name[*] in {\"Server Team\"}))"
  name        = "Block all other traffic"
  precedence  = 9999
  traffic     = format("net.dst.ip in $%s", cloudflare_teams_list.wolf_staging_vpcs.id)
  rule_settings {
    block_page_enabled                 = false
    insecure_disable_dnssec_validation = false
    ip_categories                      = false
    notification_settings {
      enabled = true
    }
  }
}


#
# Gateway/Firewall Policies/HTTP
#

resource "cloudflare_teams_rule" "http_admin_site_access" {
  account_id  = var.account_id
  action      = "allow"
  description = "Allow access to admin site URLs from users in any of the authorised groups."
  enabled     = true
  filters     = ["http"]
  identity    = format("identity.email in $%s or identity.email in $%s", cloudflare_teams_list.realm_admin_list.id, cloudflare_teams_list.admin_user_list.id)
  name        = "Admin site access"
  precedence  = 7
  traffic     = format("http.request.uri in $%s", cloudflare_teams_list.admin_site_urls.id)
  rule_settings {
    block_page_enabled                 = false
    insecure_disable_dnssec_validation = false
    ip_categories                      = false
    notification_settings {
      enabled = false
    }
    untrusted_cert {
      action = "block"
    }
  }
}

resource "cloudflare_teams_rule" "block_all_http" {
  account_id  = var.account_id
  action      = "block"
  description = "Final rule to blacklist any unconfigured HTTP sites"
  enabled     = true
  filters     = ["http"]
  identity    = "not(any(identity.groups.name[*] in {\"Server Team\"}))"
  name        = "Block all"
  precedence  = 999
  traffic     = "http.request.uri matches \".*\""
  rule_settings {
    block_page_enabled                 = false
    insecure_disable_dnssec_validation = false
    ip_categories                      = false
    notification_settings {
      enabled = true
    }
  }
}

output "outputs" {
  value = {
    default_vnet_id = cloudflare_tunnel_virtual_network.default_vnet.id
    base_tunnel_id = cloudflare_tunnel.base_tunnel.id
  }
}