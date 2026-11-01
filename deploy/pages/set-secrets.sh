#!/bin/bash
# Sets the Pages proxy secrets from SSM without printing them.
#   bash deploy/pages/set-secrets.sh <aws profile> <backend origin>
# PROXY_SECRET must equal CB_PROXY_SECRET in /configbridge/prod/env.
set -euo pipefail
export AWS_PROFILE="$1"; ORIGIN="$2"
export MSYS_NO_PATHCONV=1   # Git Bash would rewrite /configbridge/... into a Windows path
AWS="${AWS_CLI:-aws}"
sec=$("$AWS" ssm get-parameter --region ap-south-1 --name /configbridge/prod/env --with-decryption \
  --query Parameter.Value --output text | tr -d '\r' | sed -n 's/^CB_PROXY_SECRET=//p')
[ "${#sec}" -ge 32 ] || { echo "CB_PROXY_SECRET missing in SSM" >&2; exit 1; }
cd "$(dirname "$0")"
printf '%s' "$sec" | npx -y wrangler pages secret put PROXY_SECRET --project-name cyberforge
printf '%s' "$ORIGIN" | npx -y wrangler pages secret put BACKEND_ORIGIN --project-name cyberforge
