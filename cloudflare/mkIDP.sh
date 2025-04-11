#!/bin/bash

help()
{
  echo "Usage: $0 -a <account id> -t <team-name> [-h|--help]"
}

if [[ $# != 4 ]]
then
  help
  exit 2
fi

#
# Parse command line options
#
shortOptions="a:t:h"
longOptions="account:,team-name:,help"

while getopts ${shortOptions} opt
do
  case $opt in
    a)
      CLOUDFLARE_ACCOUNT_ID=${OPTARG}
      ;;
    t)
      TeamName=${OPTARG}
      ;;
    h)
      help
      exit 1
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      help
      exit 1
      ;;
    :)
      help
      exit 1
      ;;
  esac
done

#CLOUDFLARE_ACCOUNT_ID="8b9acbe4be1894c087b051be91216f15"
#TeamName="star-one"

ObjectName="Google Workspace for ${TeamName}"
GWSSecret=$(aws secretsmanager get-secret-value --secret-id CloudflareGoogleWorkspaceAuth --query "SecretString" --output text)
AppsDomain=$(echo ${GWSSecret} | jq -r '.AppsDomain')
ClientId=$(echo ${GWSSecret} | jq -r '.ClientId')
ClientSecret=$(echo ${GWSSecret} | jq -r '.ClientSecret')


Result=$(curl --no-progress-meter --request POST \
  --url https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/access/identity_providers \
  --header 'Content-Type: application/json' \
  --header "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
  --header 'X-Auth-Email: ' \
  --data "{
  \"config\": {
    \"apps_domain\": \"${AppsDomain}\",
    \"client_id\": \"${ClientId}\",
    \"client_secret\": \"${ClientSecret}\",
    \"redirect_url\": \"https://${TeamName}.cloudflareaccess.com/cdn-cgi/access/callback\"
  },
  \"name\": \"${ObjectName}\",
  \"type\": \"google-apps\"
}")

returnCode=$(echo ${Result} | jq '.success')

if [[ ${returnCode} == "true" ]]
then
  echo "Google Workspace identity provider created successfully."
  echo ""
  echo ${Result} | jq -r '.messages[0].message'
  echo "(Must be performed as a Workspace Administrator)"
  echo ""
  echo "Importing identity provider..."
  terraform import 'module.cloudflare_base.cloudflare_access_identity_provider.wolf_google_workspace[0]' ${CLOUDFLARE_ACCOUNT_ID}/$(echo ${Result} | jq -r '.result.id')
  echo "Complete the authorisation of the GWS identity provider before proceeding with the terraform apply step."
 else
  echo "Google Workspace identity provider failed to create."
  echo ""
  echo "Result:"
  echo ${Result}
fi
echo ""
