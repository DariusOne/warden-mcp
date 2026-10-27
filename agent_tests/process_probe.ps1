$ErrorActionPreference = 'Stop'
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$processes = @(Get-CimInstance Win32_Process)
$ids = [System.Collections.Generic.HashSet[int]]::new()
[void]$ids.Add([int]$request.root_pid)
$children = @()
do {
    $added = $false
    foreach ($entry in $processes) {
        if ($ids.Contains([int]$entry.ParentProcessId) -and $ids.Add([int]$entry.ProcessId)) {
            $children += $entry
            $added = $true
        }
    }
} while ($added)
$secretFound = $false
$sessionArgument = $false
foreach ($entry in $children) {
    $line = [string]$entry.CommandLine
    foreach ($secret in $request.markers) {
        if ($secret -and $line.Contains([string]$secret)) { $secretFound = $true }
    }
    if ($line -match '--session(?:\s|=)') { $sessionArgument = $true }
}
@{ secret_args = $secretFound; session_argument = $sessionArgument; children_observed = $children.Count } | ConvertTo-Json -Compress
