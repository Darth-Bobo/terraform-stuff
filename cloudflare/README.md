# Terraform setup for Cloudflare

## Install Terraform CLI

brew tap hashicorp/tap
brew install hashicorp/tap/terraform

## Add the cloudflare_base module to your Terraform config file
```
module "cloudflare_base" {
  source = "../modules/cloudflare_base"

  account_id = "0123456789"
  team_name  = "demo-team"
  tunnel_name = "demo-tunnel"
  admin_site_users = [
             {
                description = "Demo user name"
                value       = "demo.user@wolf.live"
             }
            ]
}
```
You must provide values for account_id, team_name and tunnel_name.  Arrays of users who can access various default services are optional.
The following are valid options:
admin_site_users
rabbitmq_admin_users
rds_staging_users
realm_admins
ssh_users
titan_staging_users

In addition, any users in the Google Group "Server Team" will be granted full access"

## Initialise terraform (download providers, must be run every time a new provider is added):
terraform init

## Initialise the Google Workspace identity provider
Because the Google IDP needs an additional authentication step performed that terraform does not support, we must create
it using the REST API for Cloudflare, import the resulting object and then open the authorisation link provded by the API.

The mkIDP.sh script does most of this, but will not open the link as it must be performed by someone with GWS administrator privileges.

CAUTION: The script (and the Cloudflare API) will allow this object to be created multiple times with the same name but different object IDs
         Do not run the script more than once without clearing out any existing object from Cloudflare and terraform.

```
../mkIDP.sh -a <account-id> -t <team-name>

```

e.g.
```
../mkIDP.sh -a 6016d21c1b1884e16254c3188a8dc0e6 -t palringo

```

## Show execution plan:
terraform plan


## Apply changes
terraform apply --auto-approve


## Deployment requirements
The environment must have an API access token with suitable permissions defined in CLOUDFLARE_API_TOKEN and AWS SecretsManager access sufficient to read the secrets defined for realm_aws_cognito and google_workspace in the code.


