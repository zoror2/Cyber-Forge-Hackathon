# Builds the production settings and stores them in SSM Parameter Store
# (/configbridge/prod/env, SecureString). Never prints a value.
#   powershell -File deploy/aws/put-env.ps1 -EnvFile ..\..\..\.env -DbHost <rds endpoint>
# Generated secrets are created once and kept on later runs (sessions, the DB
# role password and the Pages proxy secret must not change underneath).
param([Parameter(Mandatory)][string]$EnvFile, [Parameter(Mandatory)][string]$DbHost, [string]$Region = 'ap-south-1')
$ErrorActionPreference = 'Stop'
$aws = 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
$name = '/configbridge/prod/env'

$local = @{}
foreach ($l in [IO.File]::ReadAllLines((Resolve-Path $EnvFile))) { if ($l -match '^([A-Z_]+)=(.*)$') { $local[$matches[1]] = $matches[2] } }
if (-not $env:AWS_PROFILE -and $local['AWS_PROFILE']) { $env:AWS_PROFILE = $local['AWS_PROFILE'] }

$current = @{}
# first run: the parameter doesn't exist yet (PowerShell 5.1 would treat the CLI's stderr as fatal)
$ErrorActionPreference = 'Continue'
$raw = & $aws ssm get-parameter --region $Region --name $name --with-decryption --query Parameter.Value --output text 2>$null
$ErrorActionPreference = 'Stop'
if ($LASTEXITCODE -eq 0 -and $raw) { foreach ($l in ($raw -split "`n")) { if ($l -match '^([A-Z_]+)=(.*)$') { $current[$matches[1]] = $matches[2] } } }

function New-Secret { $b = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); -join ($b | % { $_.ToString('x2') }) }
function Keep($k) { if ($current[$k]) { $current[$k] } else { New-Secret } }
function From-Local($k) { if (-not $local[$k]) { throw "$k missing in $EnvFile" }; $local[$k] }

$settings = [ordered]@{
  AWS_REGION              = $Region
  CB_DB_HOST              = $DbHost
  CB_APP_DB_PASSWORD      = Keep 'CB_APP_DB_PASSWORD'
  CB_JWT_SECRET           = Keep 'CB_JWT_SECRET'
  CB_OPERATOR_TOKEN       = Keep 'CB_OPERATOR_TOKEN'
  CB_PROXY_SECRET         = Keep 'CB_PROXY_SECRET'
  CB_OPENSEARCH_USERNAME  = 'configbridge'
  CB_OPENSEARCH_PASSWORD  = Keep 'CB_OPENSEARCH_PASSWORD'
  CB_OPENSEARCH_NAMESPACE = 'configbridge-prod'
  CB_AI_PROVIDER          = From-Local 'CB_AI_PROVIDER'
  CB_AI_MODEL             = From-Local 'CB_AI_MODEL'
  GEMINI_API_KEY          = From-Local 'GEMINI_API_KEY'
  CB_DOC_RENDERER         = 'off'
  CB_AI_DAILY_LIMIT       = From-Local 'CB_AI_DAILY_LIMIT'
  CB_AI_DAILY_TOKEN_LIMIT = From-Local 'CB_AI_DAILY_TOKEN_LIMIT'
  # AI is metered: production enables it only for the accounts that use SIEM
  CB_AI_ENABLED_TENANTS   = From-Local 'CB_SIEM_ENABLED_TENANTS'
  CB_SIEM_ENABLED_TENANTS = From-Local 'CB_SIEM_ENABLED_TENANTS'
  CB_TUNNEL_TOKEN         = From-Local 'CB_TUNNEL_TOKEN'
  CB_OPENSEARCH_IMAGE     = From-Local 'CB_OPENSEARCH_IMAGE'
  CB_NGINX_IMAGE          = 'nginx:1.27.3-alpine'
  CB_CLOUDFLARED_IMAGE    = 'cloudflare/cloudflared:2026.10.7'
  # public sign-up, hard-capped (total accounts; also caps KMS keys at ~$1/month each)
  CB_SIGNUP               = 'open'
  CB_SIGNUP_MAX_ACCOUNTS  = '25'
  # alert email: local SMTP_* names mapped to the app's CB_SMTP_*; alerts go to
  # each account's oldest active admin (no per-tenant routes needed)
  CB_SMTP_ADDR               = "$(From-Local 'SMTP_HOST'):$(From-Local 'SMTP_PORT')"
  CB_SMTP_FROM               = From-Local 'SMTP_USERNAME'
  CB_SMTP_USERNAME           = From-Local 'SMTP_USERNAME'
  CB_SMTP_PASSWORD           = (From-Local 'SMTP_PASSWORD') -replace '\s', ''   # Gmail app passwords are shown with spaces
  CB_SMTP_TLS_MODE           = From-Local 'CB_SMTP_TLS_MODE'
  CB_ALERT_USE_ACCOUNT_EMAIL = '1'
}
$body = ($settings.GetEnumerator() | % { "$($_.Key)=$($_.Value)" }) -join "`n"
$tmp = [IO.Path]::GetTempFileName()
try {
  [IO.File]::WriteAllText($tmp, $body, (New-Object Text.UTF8Encoding($false)))
  & $aws ssm put-parameter --region $Region --name $name --type SecureString --tier Standard --overwrite --value "file://$tmp" --output text | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'put-parameter failed' }
} finally { Remove-Item $tmp -Force }
"stored $name with $($settings.Count) settings (values not shown)"
