# Generates only local development credentials. Never overwrites an existing keyring.
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath '.env'){throw '.env exists. Preserve its tenant encryption keys; use .env.example to migrate settings.'}
function New-RandomValue { $b=New-Object byte[] 32;$rng=[Security.Cryptography.RandomNumberGenerator]::Create();try{$rng.GetBytes($b)}finally{$rng.Dispose()};return [Convert]::ToBase64String($b) }
$adminPassword=(New-RandomValue).Replace('+','a').Replace('/','b').TrimEnd('=')
$runtimePassword=(New-RandomValue).Replace('+','a').Replace('/','b').TrimEnd('=')
$apiKey=New-RandomValue
$keyring=@{'tenant-a'=(New-RandomValue)} | ConvertTo-Json -Compress
$lines=@("POSTGRES_PASSWORD=$adminPassword","CB_APP_DB_PASSWORD=$runtimePassword","MIGRATION_DATABASE_URL=postgres://configbridge:${adminPassword}@127.0.0.1:5432/configbridge?sslmode=disable","DATABASE_URL=postgres://configbridge_app:${runtimePassword}@127.0.0.1:5432/configbridge?sslmode=disable",'CB_CREATE_RUNTIME_ROLE=1','CB_BOOTSTRAP_TENANT=tenant-a',"CB_BOOTSTRAP_API_KEY=$apiKey",'CB_TENANT_KMS_KEY=','CB_ENV=dev','CB_SECRETS_BACKEND=local',"CB_DEV_TENANT_KEYS=$keyring",'CB_DEV_ALLOW_PRIVATE=127.0.0.1/32,::1/128','CB_DEV_CA_FILE=data/devcert/cert.pem','CB_LISTEN=127.0.0.1:8080','MOCK_ADDR=127.0.0.1:8081','MOCK_TLS_CERT=data/devcert/cert.pem','MOCK_TLS_KEY=data/devcert/key.pem')
[IO.File]::WriteAllLines((Join-Path (Get-Location) '.env'),$lines,[Text.UTF8Encoding]::new($false))
$go=(Get-Command go -ErrorAction SilentlyContinue).Source
if(-not $go){$go=Join-Path (Get-Location) '.tools/go/bin/go.exe'}
& $go run ./cmd/devcert
if($LASTEXITCODE -ne 0){throw 'Development certificate generation failed'}
Write-Host 'Created private .env and development TLS certificate. No credential values were printed.'
