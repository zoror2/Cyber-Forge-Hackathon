# Native Go API/TLS mock against a Docker OpenSearch dependency. AI is explicit.
param([string]$BaseUrl='http://127.0.0.1:18080',[string]$VendorUrl='https://127.0.0.1:18081',[switch]$WithAI)
$ErrorActionPreference='Stop'
if(-not ([Uri]$BaseUrl).IsLoopback -or -not ([Uri]$VendorUrl).IsLoopback){throw 'This synthetic demo uses localhost only.'}
$settings=@{};foreach($line in [IO.File]::ReadAllLines((Join-Path (Get-Location) '.env'))){if($line -match '^([A-Z_]+)=(.*)$'){$settings[$matches[1]]=$matches[2]}}
$headers=@{Authorization='Bearer '+$settings['CB_BOOTSTRAP_API_KEY']};$base=$BaseUrl.TrimEnd('/')
$cfg=Get-Content configs/mock_security_events.json -Raw|ConvertFrom-Json;$cfg.id='siem_demo_'+[Guid]::NewGuid().ToString('N').Substring(0,8);$cfg.request.url=$VendorUrl.TrimEnd('/')+'/security-events';$cfg.request.allowed_ports=@(([Uri]$VendorUrl).Port)
$saved=Invoke-RestMethod "$base/configs" -Method Post -Headers $headers -ContentType 'application/json' -Body ($cfg|ConvertTo-Json -Depth 20)
$null=Invoke-RestMethod "$base/configs/$($cfg.id)/activate" -Method Post -Headers $headers -ContentType 'application/json' -Body (@{revision=$saved.revision}|ConvertTo-Json)
$run=Invoke-RestMethod "$base/connectors/$($cfg.id)/run" -Method Post -Headers $headers
if($run.accepted -ne 9 -or $run.outcome -ne 'success'){throw 'Synthetic event collection failed'}
$snapshot=Invoke-RestMethod "$base/siem/refresh" -Method Post -Headers $headers -ContentType 'application/json' -Body (@{connector=$cfg.id}|ConvertTo-Json)
$high=@($snapshot.findings|Where-Object {$_.rule -eq 'high_severity_events'});$auth=@($snapshot.findings|Where-Object {$_.rule -eq 'authentication_failures'})
if($high.Count -ne 1 -or $high[0].count -ne 1 -or $auth.Count -ne 1 -or $auth[0].count -ne 6){throw 'Incorrect rule counts or event-time window'}
$result=@{connector=$cfg.id;synthetic=$true;collected=9;high_events=1;auth_failures=6;ai_called=$false}
if($WithAI){
 $before=Invoke-RestMethod "$base/ai/usage" -Headers $headers
 $answer=Invoke-RestMethod "$base/siem/ask" -Method Post -Headers $headers -ContentType 'application/json' -Body (@{connector=$cfg.id;topic='security_findings';external_ai_consent=$true}|ConvertTo-Json)
 if($answer.status -ne 'explanation_requires_review' -or -not $answer.usage.known -or $answer.usage.total_tokens -le 0){throw 'AI response/usage verification failed'}
 $encoded=$answer|ConvertTo-Json -Depth 20
 foreach($private in @('SYNTHETIC_PRIVATE_DESCRIPTION','user@example.invalid','192.0.2.1',$settings['CB_BOOTSTRAP_API_KEY'])){if($encoded.Contains($private)){throw 'Private synthetic data or credential appeared in AI response'}}
 $after=Invoke-RestMethod "$base/ai/usage" -Headers $headers
 if(($after.reported_tokens-$before.reported_tokens) -ne $answer.usage.total_tokens){throw 'Usage was not recorded exactly once'}
 $result.ai_called=$true;$result.provider=$answer.provider;$result.model=$answer.model;$result.input_tokens=$answer.usage.input_tokens;$result.output_tokens=$answer.usage.output_tokens;$result.total_tokens=$answer.usage.total_tokens
}
[IO.File]::WriteAllText((Join-Path (Get-Location) 'data/siem-demo-result.json'),($result|ConvertTo-Json),(New-Object Text.UTF8Encoding($false)))
Write-Host 'PASS: 9 synthetic events collected; current-window findings are 6 authentication failures and 1 high-severity event.'
if($WithAI){Write-Host ('PASS: '+$result.provider+' explanation, citations and '+$result.total_tokens+' reported tokens recorded.')}else{Write-Host 'No AI call made. Use -WithAI explicitly to verify the hosted provider.'}
Write-Host ('View the local dashboard at '+$base+'/insights?connector='+$cfg.id)
