#Requires -Version 5.1
# Local checkout: open its own entry point. Pasted URL: download the full project.
if ($PSScriptRoot -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'src\Debloat.Core.psm1') -PathType Leaf)) {
    & (Join-Path $PSScriptRoot 'win11debloater.ps1') @args
} else {
    $bootstrap=Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/Matheus-TestUser1/Win11-Debloat/main/bootstrap.ps1' -TimeoutSec 60
    & ([scriptblock]::Create([string]$bootstrap))
}
