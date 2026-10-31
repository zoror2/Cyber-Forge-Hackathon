# Downloads a proposal only. Credentials and private connection settings stay local.
param(
 [Parameter(Mandatory=$true)][string]$Source,
 [Parameter(Mandatory=$true)][string]$ConnectorId,
 [Parameter(Mandatory=$true)][string]$OutFile,
 [switch]$ConsentToExternalAI
)
$ErrorActionPreference='Stop'
if(-not $ConsentToExternalAI){throw 'Add -ConsentToExternalAI to send the reviewed public source description to Groq.'}
if(Test-Path -LiteralPath $OutFile){throw 'Output file already exists; choose a new name.'}
if([IO.Path]::GetExtension($OutFile) -ne '.json'){throw 'Choose a .json output file.'}
$settings=@{}
foreach($line in [IO.File]::ReadAllLines((Join-Path (Get-Location) '.env'))){if($line -match '^([A-Z_]+)=(.*)$'){$settings[$matches[1]]=$matches[2]}}
$headers=@{Authorization='Bearer '+$settings['CB_BOOTSTRAP_API_KEY']}
$body=@{source_id=$Source;connector_id=$ConnectorId;external_ai_consent=$true}|ConvertTo-Json
try{$proposal=Invoke-RestMethod 'http://127.0.0.1:8080/ai/config-draft' -Method Post -Headers $headers -ContentType 'application/json' -Body $body -TimeoutSec 55}
catch{throw 'Draft request failed. Check AI enablement, source ID, quota and API health.'}
if($proposal.status -ne 'draft_proposal' -or -not $proposal.review_required){throw 'Unexpected proposal response.'}
$outputPath=[IO.Path]::GetFullPath($OutFile)
[IO.File]::WriteAllText($outputPath,($proposal.config|ConvertTo-Json -Depth 30),(New-Object Text.UTF8Encoding($false)))
Write-Host "Saved draft to $outputPath. Review it, fill connection details locally, then run scripts/test-draft.ps1."
