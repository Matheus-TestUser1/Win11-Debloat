#Requires -Version 5.1
# Downloads an exact source revision and opens only its harmless GUI smoke test.
param([Parameter(Mandatory=$true)][string]$Ref)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('Win11Debloat download test '+[guid]::NewGuid().ToString('N'))
$before=[Net.ServicePointManager]::SecurityProtocol
try {
    # Load the bootstrap from GitHub as text, just like the pasted command.
    $online=Invoke-RestMethod -Uri "https://raw.githubusercontent.com/Matheus-TestUser1/Win11-Debloat/$Ref/bootstrap.ps1" -TimeoutSec 60
    $result=& ([scriptblock]::Create([string]$online)) -Ref $Ref -InstallRoot $fixture -DownloadOnly
    if ($result.Launched -or $result.Commit -ne $Ref) { throw 'O download não respeitou a revisão ou iniciou a GUI sem autorização.' }
    if ([Net.ServicePointManager]::SecurityProtocol -ne $before) { throw 'O protocolo TLS da sessão não foi restaurado.' }
    $downloaded=Join-Path $result.Path 'win11debloater.ps1'
    if (-not (Test-Path -LiteralPath $downloaded)) { throw 'Download sem ponto de entrada.' }
    $catalog=& $downloaded -List
    if (@($catalog).Count -ne 14) { throw 'O catálogo baixado não carregou.' }
    $null=& (Join-Path $result.Path 'src\Debloat.Gui.ps1') -SmokeTest
    if (-not (Test-Path -LiteralPath (Join-Path $result.Path 'gui-smoke.png'))) { throw 'A GUI baixada não gerou sua captura de teste.' }
    if (@(Get-ChildItem -LiteralPath $fixture -Directory | Where-Object Name -Like 'download-*').Count) { throw 'Pasta temporária do download não foi limpa.' }
    Write-Host 'PASS: exact-revision download, complete local entry point and downloaded WPF GUI smoke test (including a path with spaces).'
} finally {
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force }
}
