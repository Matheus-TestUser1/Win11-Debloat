#Requires -Version 5.1
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
foreach ($name in @('run.ps1','win11debloater.ps1')) {
    $source=Get-Content -LiteralPath (Join-Path $root $name) -Raw -Encoding UTF8
    & {
        param($Source,$Name)
        # An in-memory script must route to the full installer, not try importing
        # modules from the caller's working directory. No network or GUI is used here.
        function Invoke-RestMethod {
            param($Uri,$TimeoutSec)
            if ($Uri -ne 'https://raw.githubusercontent.com/Matheus-TestUser1/Win11-Debloat/main/bootstrap.ps1') { throw "Origem inesperada: $Uri" }
            return "Write-Output 'BOOTSTRAP_DISPATCHED'"
        }
        $result=& ([scriptblock]::Create($Source))
        if ($result -ne 'BOOTSTRAP_DISPATCHED') { throw "$Name não encaminhou o carregamento em memória para o iniciador." }
        Write-Host "PASS: $Name loaded in memory routes to the complete-project bootstrap."
    } $source $name
}
