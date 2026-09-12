param([int]$ParentId = 0)
$ErrorActionPreference = 'Stop'
$productRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $productRoot
$runtimeDir = Join-Path $productRoot '.runtime'
New-Item -ItemType Directory -Path $runtimeDir -Force | Out-Null
$pythonCommand = Get-Command python.exe -ErrorAction SilentlyContinue
if (-not $pythonCommand) { throw 'Please install Python 3.11 or later and enable Add Python to PATH.' }
& $pythonCommand.Source -c 'import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)'
if ($LASTEXITCODE -ne 0) { throw 'Python 3.11 or later is required.' }
function Invoke-SetupChild([string]$Executable, [string[]]$Arguments) {
    $child = Start-Process -FilePath $Executable -ArgumentList $Arguments -WorkingDirectory $productRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $runtimeDir 'setup-output.log') -RedirectStandardError (Join-Path $runtimeDir 'setup-error.log')
    try {
        while (-not $child.WaitForExit(500)) {
            if ($ParentId -and -not (Get-Process -Id $ParentId -ErrorAction SilentlyContinue)) { throw 'Desktop window closed; initialization cancelled.' }
        }
        if ($child.ExitCode -ne 0) { throw 'Runtime initialization failed. Check Python, network availability and .runtime/setup-error.log.' }
    } finally {
        if (-not $child.HasExited) { & taskkill.exe /PID $child.Id /T /F | Out-Null }
        $child.Dispose()
    }
}
$environmentPython = Join-Path $productRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $environmentPython)) {
    Invoke-SetupChild $pythonCommand.Source @('-m','venv','".venv"')
}
Invoke-SetupChild $environmentPython @('-m','pip','install','-r','"requirements.txt"')
Set-Content -LiteralPath (Join-Path $runtimeDir 'runtime-ready') -Value '1.7.2' -Encoding ASCII
