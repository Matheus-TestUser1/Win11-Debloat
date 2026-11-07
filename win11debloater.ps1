#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [switch]$Console,
    [switch]$List,
    [string[]]$Action,
    [string]$RestoreBackup,
    [switch]$CreateRestorePoint
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'src\Debloat.Core.psm1') -Force

if ($Console -or $List -or $Action -or $RestoreBackup -or $WhatIfPreference) {
    $common=@{WhatIf=[bool]$WhatIfPreference}
    if ($PSBoundParameters.ContainsKey('Confirm')) { $common.Confirm=$PSBoundParameters['Confirm'] }
    $logger={param($event) Write-Host "[$($event.Level)] $($event.Message)"}
    if ($RestoreBackup) { Restore-DebloatBackup -Path $RestoreBackup -OnEvent $logger @common }
    elseif ($Action) { Invoke-DebloatApply -ActionIds $Action -CreateRestorePoint:$CreateRestorePoint -OnEvent $logger @common }
    else { Get-DebloatCatalog | Select-Object Id,Category,Title,Description }
    return
}

if ([Environment]::OSVersion.Platform -ne 'Win32NT' -or [Environment]::OSVersion.Version.Major -lt 10) {
    throw 'A interface requer Windows 10 ou 11. Use -List para consultar o catálogo.'
}
if (-not [Environment]::Is64BitOperatingSystem) { throw 'A interface requer Windows de 64 bits.' }
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object Security.Principal.WindowsPrincipal($identity)
$admin=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$windowsPowerShell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if (-not $admin -or $PSVersionTable.PSEdition -ne 'Desktop' -or [Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA' -or -not [Environment]::Is64BitProcess) {
    if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
        $windowsPowerShell=Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    }
    $arguments='-NoProfile -STA -ExecutionPolicy Bypass -File "{0}"' -f $PSCommandPath
    try {
        if ($admin) { $null=Start-Process -FilePath $windowsPowerShell -ArgumentList $arguments -PassThru }
        else { $null=Start-Process -FilePath $windowsPowerShell -ArgumentList $arguments -Verb RunAs -PassThru }
    } catch { throw "Não foi possível abrir a interface elevada: $($_.Exception.Message)" }
    return
}
try { & (Join-Path $PSScriptRoot 'src\Debloat.Gui.ps1') }
catch {
    Add-Type -AssemblyName PresentationFramework
    $null=[Windows.MessageBox]::Show($_.Exception.Message,'Win11 Debloat — erro','OK','Error')
    throw
}
