# Run against a local, fixture-mode server. Reads private values from .env without echoing them.
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath '.env')) { throw 'Create .env with scripts/dev-env.ps1 first.' }
$settings = @{}
foreach ($line in [IO.File]::ReadAllLines((Join-Path (Get-Location) '.env'))) {
    if ($line -match '^([A-Z_]+)=(.*)$') { $settings[$matches[1]] = $matches[2] }
}
$headers = @{ Authorization = 'Bearer ' + $settings['CONFIGBRIDGE_ADMIN_TOKEN'] }
$base = 'http://127.0.0.1:8080'
$saved = Invoke-RestMethod "$base/configs" -Method Post -Headers $headers -ContentType 'application/yaml' -Body ([IO.File]::ReadAllText((Join-Path (Get-Location) 'configs/fixture_events.yaml')))
$null = Invoke-RestMethod "$base/configs/fixture_events/validate" -Method Post -Headers $headers
$null = Invoke-RestMethod "$base/configs/fixture_events/activate" -Method Post -Headers $headers -ContentType 'application/json' -Body (@{ revision = $saved.revision } | ConvertTo-Json)
$null = Invoke-RestMethod "$base/connectors/fixture_events/test" -Method Post -Headers $headers
foreach ($attempt in 1..2) {
    $result = Invoke-RestMethod "$base/connectors/fixture_events/run" -Method Post -Headers $headers
    if ($result.accepted -ne 3 -or $result.quarantined -ne 1 -or $result.mode -ne 'fixture') { throw 'Unexpected fixture result.' }
}
$records = Invoke-RestMethod "$base/records/events?source=fixture_events" -Headers $headers
if ($records.Count -ne 3) { throw 'Duplicate-prevention check failed.' }
Write-Host 'Fixture smoke passed: each run accepted 3 and quarantined 1; database contains 3 unique events.'
