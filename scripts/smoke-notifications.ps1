# Requires API/TLS mock plus the loopback mailcapture, with synthetic email routes.
param([string]$BaseUrl='http://127.0.0.1:8080',[string]$MailboxUrl='http://127.0.0.1:8025')
$ErrorActionPreference='Stop'
if(-not ([Uri]$BaseUrl).IsLoopback -or -not ([Uri]$MailboxUrl).IsLoopback){throw 'This smoke test uses localhost only.'}
$settings=@{}
foreach($line in [IO.File]::ReadAllLines((Join-Path (Get-Location) '.env'))){if($line -match '^([A-Z_]+)=(.*)$'){$settings[$matches[1]]=$matches[2]}}
$headers=@{Authorization='Bearer '+$settings['CB_BOOTSTRAP_API_KEY']};$base=$BaseUrl.TrimEnd('/');$mailbox=$MailboxUrl.TrimEnd('/')
$cfg=Get-Content configs/mock_users.json -Raw|ConvertFrom-Json
$cfg.id='b4_demo_'+[Guid]::NewGuid().ToString('N').Substring(0,8);$cfg.name='Synthetic repeated failure alert';$cfg.request.url='https://127.0.0.1:8081/flaky';$cfg.request|Add-Member -NotePropertyName params -NotePropertyValue @{scenario_id=$cfg.id;fail='100';code='500'} -Force
$cfg.pagination=@{type='none'};$cfg.retry.max_attempts=1;$cfg|Add-Member -NotePropertyName notifications -NotePropertyValue @{enabled=$true;failure_threshold=3;cooldown_seconds=3600} -Force
function Save-DemoConfig{
 $saved=Invoke-RestMethod "$base/configs" -Method Post -Headers $headers -ContentType 'application/json' -Body ($cfg|ConvertTo-Json -Depth 20)
 $null=Invoke-RestMethod "$base/configs/$($cfg.id)/activate" -Method Post -Headers $headers -ContentType 'application/json' -Body (@{revision=$saved.revision}|ConvertTo-Json)
}
function Run-FailedCollection{
 try{$null=Invoke-RestMethod "$base/connectors/$($cfg.id)/run" -Method Post -Headers $headers;throw 'Expected a failed synthetic collection'}
 catch{if(-not $_.Exception.Response -or [int]$_.Exception.Response.StatusCode -ne 502){throw 'Synthetic failure scenario did not return the expected safe 502'}}
}
Save-DemoConfig
foreach($n in 1..2){Run-FailedCollection;$outbox=Invoke-RestMethod "$base/alerts?connector=$($cfg.id)" -Headers $headers;if(@($outbox).Count -ne 0){throw 'Email queued before the threshold'}}
Run-FailedCollection
$sent=$false
foreach($n in 1..30){$outbox=@(Invoke-RestMethod "$base/alerts?connector=$($cfg.id)" -Headers $headers);if($outbox.Count -eq 1 -and $outbox[0].status -eq 'sent'){$sent=$true;break};Start-Sleep -Milliseconds 300}
if(-not $sent){throw 'Local email was not delivered. Check the loopback SMTP capture and API route settings.'}
Run-FailedCollection;Start-Sleep -Milliseconds 1100
$allMessages=Invoke-RestMethod "$mailbox/messages";$messages=@()
foreach($message in $allMessages){if($message.body.Contains('Connector: '+$cfg.id)){$messages+=$message}}
if($messages.Count -ne 1 -or -not $messages[0].body.Contains('Consecutive failed collections: 3')){throw 'Duplicate or missing captured email'}
$cfg.request.url='https://127.0.0.1:8081/users';$cfg.request.params=@{per_page='100'};Save-DemoConfig
$recovered=Invoke-RestMethod "$base/connectors/$($cfg.id)/run" -Method Post -Headers $headers
if($recovered.outcome -ne 'success'){throw 'Recovery failed'}
$cfg.notifications.enabled=$false;Save-DemoConfig
$result=@{synthetic=$true;connector=$cfg.id;threshold=3;emails_captured=1;fourth_failure_did_not_duplicate=$true;recovered=$true;external_email_sent=$false}
[IO.File]::WriteAllText((Join-Path (Get-Location) 'data/b4-demo-result.json'),($result|ConvertTo-Json),(New-Object Text.UTF8Encoding($false)))
Write-Host 'PASS: 3 failures triggered 1 local email; a fourth did not duplicate it; recovery succeeded. No external email was sent.'
Write-Host ('View the captured message at '+$mailbox)
