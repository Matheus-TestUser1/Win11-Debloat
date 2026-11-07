#Requires -Version 5.1
# Tests real provider behavior ONLY in a unique disposable HKCU test key.
# No Windows settings, services, packages or catalog targets are changed.
$ErrorActionPreference='Stop'
$module=Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'src/Debloat.Core.psm1') -Force -PassThru
& $module {
    $relative='Software\Win11DebloatTests\'+[guid]::NewGuid().ToString('N')
    $path='HKCU:\'+$relative
    try {
        Set-DebloatRegistryValue -Path $path -Name Sentinel -Value 42 -Type DWord
        Set-DebloatRegistryValue -Path $path -Name MinAnimate -Value '1' -Type String
        Set-DebloatRegistryValue -Path $path -Name MinAnimate -Value '0' -Type String
        if ((Get-DebloatRegistrySnapshot $path Sentinel).Value -ne 42) { throw 'Valor vizinho apagado.' }
        $s=Get-DebloatRegistrySnapshot $path MinAnimate
        if ($s.Type -ne 'String' -or $s.Value -ne '0') { throw 'Tipo/valor não preservados.' }
        Set-DebloatRegistryValue -Path $path -Name Expand -Value '%TEMP%\fixture' -Type ExpandString
        if ((Get-DebloatRegistrySnapshot $path Expand).Value -ne '%TEMP%\fixture') { throw 'ExpandString expandida no snapshot.' }
        Set-DebloatRegistryValue -Path $path -Name Binary -Value ([byte[]]@(0,127,255)) -Type Binary
        $b=Get-DebloatRegistrySnapshot $path Binary
        if ($b.Type -ne 'Binary' -or ($b.Value -join ',') -ne '0,127,255') { throw 'Binário alterado.' }
        if ((Get-DebloatRegistrySnapshot $path Missing).Exists) { throw 'Ausência não detectada.' }
        Write-Host 'PASS: real Windows registry preserves siblings, value types, unexpanded strings and binary data.'
    } finally {
        [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($relative,$false)
    }
}
