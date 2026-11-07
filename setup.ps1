param([string]$Python = '')
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
if (-not $Python) {
    $taskBundledPython = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
    if (Test-Path -LiteralPath $taskBundledPython) { $Python = $taskBundledPython }
    else { $Python = (Get-Command python -ErrorAction Stop).Source }
}
& $Python -c "import sys; assert sys.version_info >= (3, 10), 'Python 3.10+ required'"
if ($LASTEXITCODE -ne 0) { throw 'Provide a working Python installation with -Python.' }
$taskVenvPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $taskVenvPython)) {
    & $Python -m venv --without-pip .venv
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the local environment.' }
}
$taskRequirements = if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'requirements.lock.txt')) { 'requirements.lock.txt' } else { 'requirements.txt' }
& $Python -m pip --python $taskVenvPython install -r $taskRequirements
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
& $taskVenvPython -m scripts.bootstrap_models
if ($LASTEXITCODE -ne 0) { throw 'Detector download failed.' }
Write-Host 'Ready. Run codex login with ChatGPT sign-in, then run .\start.ps1. No API key is used.'
Write-Host 'Retained data is in data/. To acquire it again: install pyarrow==23.0.1 and run scripts/fetch_data.py.'
