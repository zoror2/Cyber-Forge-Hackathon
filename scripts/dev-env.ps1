# Creates development values without printing them. Refuses to replace secrets.
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath '.env') { throw '.env already exists; preserve its master key.' }
function New-RandomBase64 {
    $bytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return [Convert]::ToBase64String($bytes)
}
$dbPassword = (New-RandomBase64).Replace('+','a').Replace('/','b').TrimEnd('=')
$adminToken = New-RandomBase64
$masterKey = New-RandomBase64
$lines = @(
    "POSTGRES_PASSWORD=$dbPassword",
    "DATABASE_URL=postgres://configbridge:${dbPassword}@127.0.0.1:5432/configbridge?sslmode=disable",
    "CONFIGBRIDGE_ADMIN_TOKEN=$adminToken",
    "CONFIGBRIDGE_MASTER_KEY=$masterKey",
    'CONFIGBRIDGE_SECRETS_BACKEND=local',
    'CONFIGBRIDGE_FIXTURE_MODE=1',
    'CONFIGBRIDGE_LISTEN=127.0.0.1:8080'
)
[IO.File]::WriteAllLines((Join-Path (Get-Location) '.env'), $lines, [Text.UTF8Encoding]::new($false))
Write-Host 'Created .env with local development credentials. Keep it private and keep the master key.'
