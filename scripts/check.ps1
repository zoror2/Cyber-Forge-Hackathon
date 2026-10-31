# Local push gate: requires a disposable Postgres admin URL and a C compiler for -race.
$ErrorActionPreference='Stop'
if(-not $env:TEST_DATABASE_URL){throw 'TEST_DATABASE_URL is required. Integration tests must not skip.'}
$go=(Get-Command go -ErrorAction SilentlyContinue).Source
if(-not $go){$go=Join-Path (Get-Location) '.tools/go/bin/go.exe'}
$portableCC=Join-Path (Get-Location) '.tools/w64devkit/bin/gcc.exe'
if(Test-Path -LiteralPath $portableCC){$env:CC=$portableCC;$env:PATH=(Split-Path $portableCC)+';'+$env:PATH}
$env:CGO_ENABLED='1'
$gofmt=Join-Path (Split-Path $go) 'gofmt.exe'
if(-not (Test-Path -LiteralPath $gofmt)){$gofmt='gofmt'}
$unformatted=& $gofmt -l cmd internal pkg tests
if($LASTEXITCODE -ne 0){throw 'gofmt check failed'}
if($unformatted){throw ('Run gofmt on: '+($unformatted -join ', '))}
& $go vet ./...
if($LASTEXITCODE -ne 0){throw 'go vet failed'}
& $go test -race -count=1 -timeout=120s ./...
if($LASTEXITCODE -ne 0){throw 'Go tests or race detection failed'}
foreach($cmd in @('api','bootstrap','mockvendor','devcert')){& $go build -o ('bin/'+$cmd+'.exe') ('./cmd/'+$cmd);if($LASTEXITCODE -ne 0){throw ('Build failed: '+$cmd)}}
Write-Host 'PASS: formatting, vet, full tests with real Postgres, race detector, and all native builds.'
