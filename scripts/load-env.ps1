# Sets process environment only; never evaluates .env text as PowerShell code.
param([switch]$Bootstrap)
$ErrorActionPreference='Stop'
$runtime=@('DATABASE_URL','CB_ENV','CB_LISTEN','CB_SECRETS_BACKEND','CB_DEV_TENANT_KEYS','CB_DEV_ALLOW_PRIVATE','CB_DEV_CA_FILE','MOCK_ADDR','MOCK_TLS_CERT','MOCK_TLS_KEY','AWS_REGION','GROQ_API_KEY','GEMINI_API_KEY','CB_AI_PROVIDER','CB_BEDROCK_REGION','AWS_PROFILE','CB_AI_ENABLED_TENANTS','CB_AI_MODEL','CB_AI_DAILY_LIMIT','CB_AI_DAILY_TOKEN_LIMIT','CB_SIEM_ENABLED_TENANTS','CB_OPENSEARCH_URL','CB_OPENSEARCH_USERNAME','CB_OPENSEARCH_PASSWORD','CB_OPENSEARCH_CA_FILE','CB_OPENSEARCH_NAMESPACE','CB_JWT_SECRET','CB_DEV_MASTER_KEY','CB_SIGNUP','CB_OPERATOR_TOKEN','CB_UI_ENABLED','CB_UI_ORIGIN','CB_SMTP_ADDR','CB_SMTP_FROM','CB_SMTP_USERNAME','CB_SMTP_PASSWORD','CB_SMTP_TLS_MODE','CB_ALERT_EMAIL_ROUTES','CB_CAPTURE_SMTP_ADDR','CB_CAPTURE_HTTP_ADDR')
foreach($line in [IO.File]::ReadAllLines((Join-Path (Get-Location) '.env'))){
 if($line -match '^([A-Z_]+)=(.*)$'){
  $name,$value=$matches[1],$matches[2]
  if($Bootstrap -or $runtime -contains $name){[Environment]::SetEnvironmentVariable($name,$value,'Process')}
  else{[Environment]::SetEnvironmentVariable($name,$null,'Process')}
 }
}
