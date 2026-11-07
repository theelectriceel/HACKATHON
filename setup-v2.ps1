param([string]$Python = '')
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
if (-not $Python) {
    $taskBundledPython = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
    if (Test-Path -LiteralPath $taskBundledPython) { $Python = $taskBundledPython }
    else { $Python = (Get-Command python -ErrorAction Stop).Source }
}
$taskV2Python = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $taskV2Python)) {
    & $Python -m venv --without-pip .venv
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the Python environment.' }
}
& $Python -m pip --python $taskV2Python install -r requirements-v2.lock.txt
if ($LASTEXITCODE -ne 0) { throw 'V2 dependency installation failed.' }
if (-not (Test-Path -LiteralPath 'models\guard\manifest.json') -or -not (Test-Path -LiteralPath 'models\guard\onnx\model_quantized.onnx')) {
    & $taskV2Python -m scripts.bootstrap_models
    if ($LASTEXITCODE -ne 0) { throw 'Horizon download failed.' }
}
& $taskV2Python -c "from promptguard.detector import Guard; g=Guard(); print('Local Horizon weights verified:', g.identity['revision'])"
if ($LASTEXITCODE -ne 0) { throw 'Horizon integrity or runtime verification failed.' }
Write-Host 'V2 ready. Use codex login with ChatGPT sign-in, then run .\start-v2.ps1.'
