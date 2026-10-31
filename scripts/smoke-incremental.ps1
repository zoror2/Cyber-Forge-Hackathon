# B-1 demo: localhost TLS synthetic vendor -> authenticated API -> real Postgres.
param([string]$BaseUrl='http://127.0.0.1:8080',[string]$VendorUrl='https://127.0.0.1:8081')
$ErrorActionPreference='Stop'
$apiUri=[Uri]$BaseUrl;$vendorUri=[Uri]$VendorUrl
if(-not $apiUri.IsLoopback -or $vendorUri.Scheme -ne 'https' -or (-not $vendorUri.IsLoopback -and $vendorUri.Host -ne 'mockvendor')){throw 'This synthetic demo is restricted to the local API and TLS mock.'}
$settings=@{}
foreach($line in [IO.File]::ReadAllLines((Join-Path (Get-Location) '.env'))){if($line -match '^([A-Z_]+)=(.*)$'){$settings[$matches[1]]=$matches[2]}}
$headers=@{Authorization='Bearer '+$settings['CB_BOOTSTRAP_API_KEY']}
$base=$BaseUrl.TrimEnd('/');$vendor=$VendorUrl.TrimEnd('/')
$ca=(Resolve-Path -LiteralPath 'data/devcert/cert.pem').Path
function Set-SyntheticStage([string]$Action){
 & curl.exe --silent --show-error --fail --cacert $ca --request POST ($vendor+'/incremental/'+$Action) | Out-Null
 if($LASTEXITCODE -ne 0){throw 'TLS mock stage change failed'}
}
Set-SyntheticStage 'reset'
$cfg=Get-Content configs/mock_incremental_users.json -Raw|ConvertFrom-Json
$cfg.id='b1_demo_'+[Guid]::NewGuid().ToString('N').Substring(0,8)
$cfg.request.url=$vendor+'/incremental/users';$cfg.request.allowed_ports=@($vendorUri.Port)
$saved=Invoke-RestMethod "$base/configs" -Method Post -Headers $headers -ContentType 'application/json' -Body ($cfg|ConvertTo-Json -Depth 20)
$revision=@{revision=$saved.revision}|ConvertTo-Json
$preview=Invoke-RestMethod "$base/configs/$($cfg.id)/test" -Method Post -Headers $headers -ContentType 'application/json' -Body $revision
$state=Invoke-RestMethod "$base/connectors/$($cfg.id)/sync-state" -Headers $headers
if($preview.accepted -ne 2 -or $preview.incremental.checkpoint_committed -or $state.watermark){throw 'Preview wrote a checkpoint or failed its bounded first-page sample'}
$null=Invoke-RestMethod "$base/configs/$($cfg.id)/activate" -Method Post -Headers $headers -ContentType 'application/json' -Body $revision
$first=Invoke-RestMethod "$base/connectors/$($cfg.id)/run" -Method Post -Headers $headers
if($first.accepted -ne 3 -or -not $first.incremental.checkpoint_committed){throw 'Initial backfill failed'}
Set-SyntheticStage 'advance'
# Modified timestamps and query boundaries have one-second precision in this demo.
Start-Sleep -Milliseconds 1100
$second=Invoke-RestMethod "$base/connectors/$($cfg.id)/run" -Method Post -Headers $headers
$third=Invoke-RestMethod "$base/connectors/$($cfg.id)/run" -Method Post -Headers $headers
$rows=Invoke-RestMethod "$base/records/users?source=$($cfg.id)" -Headers $headers
$state=Invoke-RestMethod "$base/connectors/$($cfg.id)/sync-state" -Headers $headers
if($second.accepted -ne 2 -or $third.accepted -ne 0 -or $rows.Count -ne 4 -or -not $second.incremental.checkpoint_committed){throw 'Incremental count/upsert/no-change check failed'}
if(($rows|Where-Object id -eq '2').name -ne 'User Two (updated)'){throw 'Existing user was not updated'}
if([DateTimeOffset]::Parse($state.watermark.through) -lt [DateTimeOffset]::Parse($second.incremental.until)){throw 'Committed checkpoint is missing'}
@(
 [pscustomobject]@{Step='First pull';RecordsPulled=$first.accepted;TotalStored=3},
 [pscustomobject]@{Step='One update + one new user';RecordsPulled=$second.accepted;TotalStored=4},
 [pscustomobject]@{Step='No further changes';RecordsPulled=$third.accepted;TotalStored=4}
)|Format-Table -AutoSize
$rows|Select-Object id,name|Format-Table -AutoSize
$result=@{synthetic=$true;connector=$cfg.id;first_pulled=$first.accepted;second_pulled=$second.accepted;third_pulled=$third.accepted;unique_users=$rows.Count;first_checkpoint=$first.incremental.until;latest_checkpoint=$state.watermark.through}
[IO.File]::WriteAllText((Join-Path (Get-Location) 'data/b1-demo-result.json'),($result|ConvertTo-Json -Depth 5),(New-Object Text.UTF8Encoding($false)))
Write-Host "PASS: B-1 incremental sync. Connector: $($cfg.id). Preview saved nothing; progress is durable in PostgreSQL."
