# Sets process environment only; never evaluates .env text as PowerShell code.
param([switch]$Bootstrap)
$ErrorActionPreference='Stop'
$runtime=@('DATABASE_URL','CB_ENV','CB_LISTEN','CB_SECRETS_BACKEND','CB_DEV_TENANT_KEYS','CB_DEV_ALLOW_PRIVATE','CB_DEV_CA_FILE','MOCK_ADDR','MOCK_TLS_CERT','MOCK_TLS_KEY','AWS_REGION')
foreach($line in [IO.File]::ReadAllLines((Join-Path (Get-Location) '.env'))){
 if($line -match '^([A-Z_]+)=(.*)$'){
  $name,$value=$matches[1],$matches[2]
  if($Bootstrap -or $runtime -contains $name){[Environment]::SetEnvironmentVariable($name,$value,'Process')}
  else{[Environment]::SetEnvironmentVariable($name,$null,'Process')}
 }
}
