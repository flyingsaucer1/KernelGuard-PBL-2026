$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
if (-not (Test-Path '.venv/Scripts/python.exe')) {
    throw 'Create .venv and install requirements first; see README.md.'
}
$env:KERNELGUARD_DB_URL = 'sqlite:///data/kernelguard.db'
& ./.venv/Scripts/python.exe -m kernelguard demo
if ($LASTEXITCODE -ne 0) { throw 'Demo import failed.' }
& ./.venv/Scripts/python.exe -m kernelguard serve
