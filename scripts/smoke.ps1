# Uses the native or Compose API and TLS mock. Values are read privately from .env.
$ErrorActionPreference='Stop'
$settings=@{}
foreach($line in [IO.File]::ReadAllLines((Join-Path (Get-Location) '.env'))){if($line -match '^([A-Z_]+)=(.*)$'){$settings[$matches[1]]=$matches[2]}}
$headers=@{Authorization='Bearer '+$settings['CB_BOOTSTRAP_API_KEY']}
$base='http://127.0.0.1:8080'
$config=[IO.File]::ReadAllText((Join-Path (Get-Location) 'configs/mock_users.json')) | ConvertFrom-Json
if($env:CB_SMOKE_VENDOR_URL){$config.request.url=$env:CB_SMOKE_VENDOR_URL.TrimEnd('/')+'/users'}
$saved=Invoke-RestMethod "$base/configs" -Method Post -Headers $headers -ContentType 'application/json' -Body ($config | ConvertTo-Json -Depth 15)
$null=Invoke-RestMethod "$base/configs/mock_users/validate" -Method Post -Headers $headers
$draftTest=Invoke-RestMethod "$base/configs/mock_users/test" -Method Post -Headers $headers -ContentType 'application/json' -Body (@{revision=$saved.revision}|ConvertTo-Json)
if($draftTest.accepted -ne 10 -or $draftTest.mode -ne 'test'){throw 'Draft revision sample failed'}
$null=Invoke-RestMethod "$base/configs/mock_users/activate" -Method Post -Headers $headers -ContentType 'application/json' -Body (@{revision=$saved.revision}|ConvertTo-Json)
$test=Invoke-RestMethod "$base/connectors/mock_users/test" -Method Post -Headers $headers
if($test.accepted -ne 10 -or $test.mode -ne 'test'){throw 'Connection sample failed'}
foreach($attempt in 1..2){$result=Invoke-RestMethod "$base/connectors/mock_users/run" -Method Post -Headers $headers;if($result.accepted -ne 25 -or $result.pages -ne 3 -or $result.outcome -ne 'success'){throw 'Paginated run failed'}}
$records=Invoke-RestMethod "$base/records/users?source=mock_users" -Headers $headers
if($records.Count -ne 25){throw 'Upsert uniqueness failed'}
$config.id='mock_malformed';$config.name='Malformed synthetic users';$config.request.url=$config.request.url.Replace('/users','/malformed');$config.pagination=@{type='none'}
$saved=Invoke-RestMethod "$base/configs" -Method Post -Headers $headers -ContentType 'application/json' -Body ($config | ConvertTo-Json -Depth 15)
$null=Invoke-RestMethod "$base/configs/mock_malformed/activate" -Method Post -Headers $headers -ContentType 'application/json' -Body (@{revision=$saved.revision}|ConvertTo-Json)
$result=Invoke-RestMethod "$base/connectors/mock_malformed/run" -Method Post -Headers $headers
if($result.accepted -ne 2 -or $result.quarantined -ne 2 -or $result.outcome -ne 'completed_with_errors'){throw 'Quarantine flow failed'}
Write-Host 'PASS: authenticated API + TLS vendor + PostgreSQL. Three pages, 25 unique users after two runs; malformed response accepted 2 and quarantined 2.'
