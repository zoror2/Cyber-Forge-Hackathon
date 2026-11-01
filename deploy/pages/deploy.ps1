# Builds the Pages site from the same UI files the Go server embeds and deploys it.
#   powershell -File deploy/pages/deploy.ps1 -Project configbridge
# Set once in the Pages project (dashboard or wrangler): BACKEND_ORIGIN, PROXY_SECRET.
param([Parameter(Mandatory)][string]$Project)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$dist = Join-Path $here 'dist'
if (Test-Path $dist) { Remove-Item -Recurse -Force $dist }
New-Item -ItemType Directory -Force (Join-Path $dist 'ui') | Out-Null
Copy-Item (Join-Path $here '..\..\internal\ui\static\*') (Join-Path $dist 'ui') -Recurse
Copy-Item (Join-Path $here '_routes.json'), (Join-Path $here '_headers') $dist
Push-Location $here
try { wrangler pages deploy dist --project-name $Project --branch main --commit-dirty=true } finally { Pop-Location }
