param(
    [Parameter(Mandatory=$true)][string]$Source,
    [Parameter(Mandatory=$true)][string]$Root,
    [Parameter(Mandatory=$true)][string]$OldBridge,
    [Parameter(Mandatory=$true)][string]$ServerUri,
    [Parameter(Mandatory=$true)][string]$NpmCli,
    [string]$Version='agent-v0.1.0'
)
$ErrorActionPreference='Stop'
$Source=(Resolve-Path -LiteralPath $Source).Path
$Root=(Resolve-Path -LiteralPath $Root).Path
$OldBridge=(Resolve-Path -LiteralPath $OldBridge).Path
if ($Version -notmatch '^agent-v\d+\.\d+\.\d+$') { throw 'Invalid version' }
$destination=Join-Path $Root ('versions\'+$Version)
if (Test-Path -LiteralPath $destination) { throw 'Version directory already exists' }
New-Item -ItemType Directory -Path $destination | Out-Null
foreach ($name in @('dist','agent_worker','agent_tools')) {
    & robocopy.exe (Join-Path $Source $name) (Join-Path $destination $name) /E /R:1 /W:1 /NFL /NDL /NJH /NJS /XF '*.test.js' '*.pyc' /XD '__pycache__' 'integration' | Out-Null
    if ($LASTEXITCODE -ge 8) { throw 'Artifact copy failed' }
}
foreach ($name in @('package.json','package-lock.json','LICENSE','AGENT_SAFE.md')) {
    Copy-Item -LiteralPath (Join-Path $Source $name) -Destination $destination
}
$env:PATH=(Join-Path $Root 'runtime')+';'+$env:PATH
Push-Location $destination
try {
    & (Join-Path $Root 'runtime\node.exe') $NpmCli ci --omit=dev --ignore-scripts --no-audit --no-fund
    if ($LASTEXITCODE -ne 0) { throw 'Runtime dependencies failed' }
} finally { Pop-Location }
$sourceCredential=Join-Path $OldBridge 'state\auth.dpapi'
$destinationCredential=Join-Path $Root 'state\auth.dpapi'
if (-not (Test-Path -LiteralPath $destinationCredential)) { Copy-Item -LiteralPath $sourceCredential -Destination $destinationCredential }
if ((Get-FileHash -LiteralPath $sourceCredential).Hash -ne (Get-FileHash -LiteralPath $destinationCredential).Hash) { throw 'Ciphertext differs; review enrollment before continuing' }
$known=Join-Path $OldBridge 'state\known_hosts'
if (Test-Path -LiteralPath $known) { Copy-Item -LiteralPath $known -Destination (Join-Path $Root 'state\known_hosts') }
$policy=Get-Content -LiteralPath (Join-Path $OldBridge 'access.json') -Raw | ConvertFrom-Json
@{enabled=[bool]$policy.enabled;allow_all=[bool]$policy.allow_all;items=@($policy.items)} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $Root 'access.json') -Encoding utf8NoBOM
@{
    server=$ServerUri;bw=(Join-Path $Root 'runtime\bw.exe');python=(Join-Path $Root '.venv\Scripts\python.exe');worker=(Join-Path $destination 'agent_worker\worker.py')
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Root 'config.json') -Encoding utf8NoBOM
$launcher='@echo off'+"`r`n"+'start "" "'+(Join-Path $Root '.venv\Scripts\pythonw.exe')+'" -B "'+(Join-Path $destination 'agent_worker\manage.py')+'" "'+$Root+'"'+"`r`n"
[IO.File]::WriteAllText((Join-Path $Root 'Manage-Access.cmd'),$launcher,[Text.Encoding]::ASCII)
$gitTree=& git -C $Source rev-parse 'HEAD^{tree}'
@{version=$Version;upstream='0.2.60';source_tree=$gitTree;node_sha256=(Get-FileHash -LiteralPath (Join-Path $Root 'runtime\node.exe')).Hash;bw_sha256=(Get-FileHash -LiteralPath (Join-Path $Root 'runtime\bw.exe')).Hash;credential_ciphertext_verified=$true} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $destination 'BUILD.json') -Encoding utf8NoBOM
Write-Output 'Version staged; Codex configuration not yet changed.'
