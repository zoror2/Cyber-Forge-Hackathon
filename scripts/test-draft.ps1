# Saves a draft revision and tests a bounded sample. Activation is a separate action.
param([Parameter(Mandatory=$true)][string]$ConfigFile)
$ErrorActionPreference='Stop'
$settings=@{}
foreach($line in [IO.File]::ReadAllLines((Join-Path (Get-Location) '.env'))){if($line -match '^([A-Z_]+)=(.*)$'){$settings[$matches[1]]=$matches[2]}}
$headers=@{Authorization='Bearer '+$settings['CB_BOOTSTRAP_API_KEY']}
$raw=[IO.File]::ReadAllText((Resolve-Path -LiteralPath $ConfigFile).Path)
$cfg=$raw|ConvertFrom-Json
try {
 $saved=Invoke-RestMethod 'http://127.0.0.1:8080/configs' -Method Post -Headers $headers -ContentType 'application/json' -Body $raw
 $body=@{revision=$saved.revision}|ConvertTo-Json
 $result=Invoke-RestMethod ('http://127.0.0.1:8080/configs/'+$cfg.id+'/test') -Method Post -Headers $headers -ContentType 'application/json' -Body $body -TimeoutSec 40
}catch{throw 'Draft save/test failed. Check the config, local credential and vendor connection; the draft has not been activated.'}
if($result.outcome -ne 'success'){throw 'Draft sample has errors. Review its mappings before activation.'}
$result|Select-Object connector,config_version,mode,outcome,pages,accepted,quarantined|Format-List
Write-Host 'Sample passed. No records or run history were stored. Review the result before explicitly activating this revision.'
