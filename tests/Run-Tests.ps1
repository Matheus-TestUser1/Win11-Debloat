#Requires -Version 5.1
# Self-contained tests: no Pester install, no administrator and no Windows mutations.
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$parseFailures=@()
foreach ($file in Get-ChildItem -LiteralPath $root -Recurse -File -Include '*.ps1','*.psm1') {
    $tokens=$null; $errors=$null
    $null=[Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
    $parseFailures+=@($errors)
    if ($errors) { Write-Host "$($file.FullName): $errors" }
}
if ($parseFailures.Count) { throw 'Falha no parser PowerShell.' }
[xml]$xaml=Get-Content -LiteralPath (Join-Path $root 'ui/MainWindow.xaml') -Raw -Encoding UTF8
if ($xaml.DocumentElement.LocalName -ne 'Window') { throw 'XAML inválido.' }
$preview=& (Join-Path $root 'win11debloater.ps1') -Console -Action telemetry,ads -WhatIf
if (-not $preview.Simulation -or $preview.Plan.Count -ne 2) { throw 'A CLI não encaminhou WhatIf ao módulo.' }
$module=Import-Module (Join-Path $root 'src/Debloat.Core.psm1') -Force -PassThru
$testRoot=Join-Path ([IO.Path]::GetTempPath()) ('win11-debloat-tests-'+[guid]::NewGuid().ToString('N'))
try {
    & $module {
        param($TestRoot)
        $script:TestRoot=$TestRoot
        $script:TestCount=0
        function Assert($Condition,[string]$Message) { if (-not $Condition) { throw $Message } }
        function Assert-Throws([scriptblock]$Action,[string]$Pattern) {
            $caught=$false
            try { & $Action | Out-Null } catch { $caught=$true; Assert ($_.Exception.Message -like $Pattern) "Erro inesperado: $($_.Exception.Message)" }
            Assert $caught "Deveria falhar: $Pattern"
        }
        function Test-Case([string]$Name,[scriptblock]$Body) {
            $script:Registry=@{}; $script:Services=@{}; $script:Calls=New-Object 'System.Collections.Generic.List[string]'
            $script:Power='381b4222-f694-41f0-9685-ff5bb260df2e'
            $script:FailRegistry=$false; $script:FailPower=$false; $script:Packages=@()
            $script:TestRoot=Join-Path $TestRoot ([guid]::NewGuid().ToString('N'))
            & $Body
            $script:TestCount++
            Write-Host "PASS: $Name"
        }
        # Mock every mutation/query that could touch Windows; real journal I/O uses a temp fixture.
        function script:Assert-DebloatPlatform { $script:Calls.Add('Platform') }
        function script:Get-DebloatIdentity { [pscustomobject]@{Computer='TEST-PC'; UserSid='TEST-SID'} }
        function script:Get-DebloatDataPath { $script:TestRoot }
        function script:New-DebloatRestorePoint { $script:Calls.Add('Checkpoint'); 'Test checkpoint' }
        function script:Get-DebloatRegistrySnapshot {
            param([string]$Path,[string]$Name)
            $key="$Path|$Name"
            $exists=$script:Registry.ContainsKey($key)
            [pscustomobject]@{Kind='Registry'; Path=$Path; Name=$Name; Exists=$exists; Value=$(if($exists){$script:Registry[$key].Value}else{$null}); Type=$(if($exists){$script:Registry[$key].Type}else{'DWord'}); Restored=$false}
        }
        function script:Set-DebloatRegistryValue {
            param([string]$Path,[string]$Name,$Value,[string]$Type)
            $script:Calls.Add("Registry:$Name")
            if ($script:FailRegistry) { throw 'Mock registry access denied' }
            # Verify the snapshot is already on disk before each mutation.
            Assert (@(Get-DebloatBackups).Count -gt 0) 'Mutação antes do backup.'
            $script:Registry["$Path|$Name"]=@{Value=$Value; Type=$Type}
        }
        function script:Test-Path { param([string]$LiteralPath) $true }
        function script:Remove-ItemProperty { param($LiteralPath,$Name,$ErrorAction) $script:Registry.Remove("$LiteralPath|$Name") }
        function script:Get-Service { param($Name,$ErrorAction) if($script:Services.ContainsKey($Name)){ [pscustomobject]@{Name=$Name; Status=$script:Services[$Name].Status} } }
        function script:Get-DebloatServiceSnapshot {
            param($Name)
            $svc=$script:Services[$Name]
            [pscustomobject]@{Kind='Service';Name=$Name;Start=$svc.Start;DelayedExists=$true;DelayedValue=$svc.Delayed;Running=($svc.Status -eq 'Running');Restored=$false}
        }
        function script:Set-Service { param($Name,$StartupType,$ErrorAction) $script:Calls.Add("Service:$StartupType"); $script:Services[$Name].Start=switch($StartupType){Automatic{2} Manual{3} Disabled{4}} }
        function script:Stop-Service { param($Name,$ErrorAction) $script:Services[$Name].Status='Stopped' }
        function script:Start-Service { param($Name,$ErrorAction) $script:Services[$Name].Status='Running' }
        function script:Get-DebloatPowerPlan { $script:Power }
        function script:Invoke-DebloatNative {
            param($FilePath,$Arguments)
            if ($script:FailPower) { throw 'Mock native exit code 1' }
            $script:Power=$Arguments[1]
        }
        function script:Get-AppxPackage { param($Name,$ErrorAction) $script:Packages }
        function script:Remove-AppxPackage { param($Package,$ErrorAction) $script:Calls.Add("Remove:$Package") }

        Test-Case 'Catálogo sem remoção de componentes essenciais' {
            $catalog=@(Get-DebloatCatalog)
            Assert ($catalog.Count -eq @($catalog.Id | Select-Object -Unique).Count) 'IDs duplicados.'
            $apps=@($catalog | Where-Object Kind -EQ Appx | ForEach-Object Targets)
            Assert (@($apps | Where-Object { $_ -match 'Store|DesktopAppInstaller|WebView|Terminal|Framework|Advertising.Xaml|\*' }).Count -eq 0) 'Componente essencial ou wildcard no catálogo.'
            $services=@($catalog | Where-Object Kind -EQ Service | ForEach-Object Targets)
            Assert (@($services | Where-Object { $_ -match 'wuauserv|WinDefend|Spooler|WSearch|edgeupdate|SysMain' }).Count -eq 0) 'Serviço essencial no catálogo.'
        }
        Test-Case 'Simulação não grava arquivos nem chama APIs do sistema' {
            $r=Invoke-DebloatApply -ActionIds @('telemetry','solitaire','power') -WhatIf -CreateRestorePoint
            Assert $r.Simulation 'Simulação não identificada.'
            Assert ($script:Calls.Count -eq 0) 'Simulação chamou uma API do sistema.'
            Assert (-not [IO.Directory]::Exists($script:TestRoot)) 'Simulação criou diretórios.'
        }
        Test-Case 'ID inválido rejeita o plano inteiro antes de alterar' {
            Assert-Throws {Invoke-DebloatApply -ActionIds @('ads','unknown')} '*Opção desconhecida*'
            Assert ($script:Calls.Count -eq 0) 'Plano parcialmente aplicado.'
        }
        Test-Case 'Seleções repetidas são deduplicadas' {
            Assert (@(Get-DebloatPlan -ActionIds ads,ads).Count -eq 1) 'Plano duplicado.'
        }
        Test-Case 'Backup preserva tipo e valor e desfaz valores originalmente ausentes' {
            $path='HKCU:\Control Panel\Desktop\WindowMetrics'
            $script:Registry["$path|MinAnimate"]=@{Value='1';Type='String'}
            $r=Invoke-DebloatApply -ActionIds @('animations','ads') -Confirm:$false
            Assert ($r.Failed -eq 0 -and $r.Success -eq 4) 'Contagem de aplicação incorreta.'
            $j=Get-Content -LiteralPath $r.BackupPath -Raw | ConvertFrom-Json
            Assert ($j.Entries[0].Value -eq '1' -and $j.Entries[0].Type -eq 'String') 'Snapshot incorreto.'
            $restored=Restore-DebloatBackup -Path $r.BackupPath -Confirm:$false
            Assert ($restored.Restored -eq 4 -and $restored.Failed -eq 0) 'Restauração falhou.'
            Assert ($script:Registry["$path|MinAnimate"].Value -eq '1') 'Valor original não restaurado.'
            Assert ($script:Registry.Count -eq 1) 'Valores criados não removidos.'
            Assert ((Restore-DebloatBackup -Path $r.BackupPath -Confirm:$false).Restored -eq 0) 'Restauração não idempotente.'
        }
        Test-Case 'Falhas por alvo aparecem no resultado sem sucesso falso' {
            $script:FailRegistry=$true
            $r=Invoke-DebloatApply -ActionIds telemetry -Confirm:$false
            Assert ($r.Success -eq 0 -and $r.Failed -eq 2) 'Erro ocultado.'
            Assert ((Get-Content -LiteralPath $r.BackupPath -Raw | ConvertFrom-Json).Entries.Count -eq 2) 'Backup parcial perdido.'
        }
        Test-Case 'Falha de persistência impede qualquer mutação' {
            # A file where a directory is required makes the real journal writer fail.
            $null=[IO.Directory]::CreateDirectory((Split-Path -Parent $script:TestRoot))
            [IO.File]::WriteAllText($script:TestRoot,'blocked')
            Assert-Throws {Invoke-DebloatApply -ActionIds ads -Confirm:$false} '*'
            Assert (@($script:Calls | Where-Object {$_ -like 'Registry:*'}).Count -eq 0) 'Mutação sem backup persistido.'
        }
        Test-Case 'Serviço retorna ao modo manual e estado anterior' {
            $script:Services.MapsBroker=@{Start=3; Status='Stopped'; Delayed=0}
            $r=Invoke-DebloatApply -ActionIds 'maps-service' -Confirm:$false
            Assert ($script:Services.MapsBroker.Start -eq 4) 'Serviço não desativado.'
            $result=Restore-DebloatBackup -Path $r.BackupPath -Confirm:$false
            Assert ($result.Failed -eq 0 -and $script:Services.MapsBroker.Start -eq 3 -and $script:Services.MapsBroker.Status -eq 'Stopped') 'Serviço forçado para automático/em execução.'
        }
        Test-Case 'Serviço automático atrasado mantém flag e execução' {
            $script:Services.MapsBroker=@{Start=2; Status='Running'; Delayed=1}
            $r=Invoke-DebloatApply -ActionIds 'maps-service' -Confirm:$false
            $null=Restore-DebloatBackup -Path $r.BackupPath -Confirm:$false
            Assert ($script:Services.MapsBroker.Start -eq 2 -and $script:Services.MapsBroker.Status -eq 'Running') 'Estado de serviço incorreto.'
            Assert ($script:Registry['HKLM:\SYSTEM\CurrentControlSet\Services\MapsBroker|DelayedAutoStart'].Value -eq 1) 'Flag DelayedAutoStart perdida.'
        }
        Test-Case 'Aplicativo ausente é ignorado e nome similar não é removido' {
            $script:Packages=@([pscustomobject]@{Name='Microsoft.MicrosoftSolitaireCollection.Fake';PackageFullName='wrong'})
            $r=Invoke-DebloatApply -ActionIds solitaire -Confirm:$false
            Assert ($r.Skipped -eq 1 -and $r.Success -eq 0) 'Nome similar aceito.'
            Assert (@($script:Calls | Where-Object {$_ -like 'Remove:*'}).Count -eq 0) 'Pacote não autorizado removido.'
        }
        Test-Case 'Remoção registra pacote exato e não promete restauração' {
            $script:Packages=@([pscustomobject]@{Name='Microsoft.MicrosoftSolitaireCollection';PackageFullName='solitaire_exact'})
            $r=Invoke-DebloatApply -ActionIds solitaire -Confirm:$false
            Assert ($script:Calls -contains 'Remove:solitaire_exact') 'Pacote não removido.'
            $j=Get-Content -LiteralPath $r.BackupPath -Raw | ConvertFrom-Json
            Assert ($j.Entries.Count -eq 0 -and $j.Irreversible.Count -eq 1) 'Remoção tratada como reversível.'
        }
        Test-Case 'Falha do executável externo não vira sucesso' {
            $script:FailPower=$true
            $r=Invoke-DebloatApply -ActionIds power -Confirm:$false
            Assert ($r.Failed -eq 1 -and $r.Success -eq 0) 'Falha nativa ignorada.'
        }
        Test-Case 'Plano de energia volta ao GUID exato' {
            $original=$script:Power
            $r=Invoke-DebloatApply -ActionIds power -Confirm:$false
            Assert ($script:Power -ne $original) 'Plano não alterado.'
            $null=Restore-DebloatBackup -Path $r.BackupPath -Confirm:$false
            Assert ($script:Power -eq $original) 'Plano original perdido.'
        }
        Test-Case 'Backup de outro usuário e alvo injetado são rejeitados' {
            $r=Invoke-DebloatApply -ActionIds animations -Confirm:$false
            $j=Get-Content -LiteralPath $r.BackupPath -Raw | ConvertFrom-Json
            $j.UserSid='OTHER-SID'
            Assert-Throws {Test-DebloatJournal $j} '*não pertence*'
            $j.UserSid='TEST-SID'; $j.Entries[0].Path='HKLM:\arbitrary'
            Assert-Throws {Test-DebloatJournal $j} '*não permitido*'
        }
        Test-Case 'Restauração deve respeitar a ordem das sessões' {
            $r1=Invoke-DebloatApply -ActionIds ads -Confirm:$false
            $old=Join-Path (Split-Path -Parent $r1.BackupPath) '20000101-old.json'
            Move-Item -LiteralPath $r1.BackupPath -Destination $old
            $r2=Invoke-DebloatApply -ActionIds ads -Confirm:$false
            Assert-Throws {Restore-DebloatBackup -Path $old -Confirm:$false} '*mais recente*'
            $null=Restore-DebloatBackup -Path $r2.BackupPath -Confirm:$false
            $null=Restore-DebloatBackup -Path $old -Confirm:$false
            Assert ($script:Registry.Count -eq 0) 'Ordem de rollback incorreta.'
        }
        Test-Case 'Temporários: arquivo recente dentro de pasta antiga é preservado' {
            $fixture=Join-Path $script:TestRoot 'temp'
            $null=[IO.Directory]::CreateDirectory($fixture)
            $old=Join-Path $fixture 'old.tmp'; $recent=Join-Path $fixture 'recent.tmp'
            [IO.File]::WriteAllText($old,'old'); [IO.File]::WriteAllText($recent,'recent')
            [IO.File]::SetLastWriteTime($old,(Get-Date).AddDays(-10))
            $files=@(Get-DebloatTemporaryFiles -Root $fixture)
            Assert ($files.Count -eq 1 -and $files[0].FullName -eq $old) 'Scanner selecionou arquivos recentes.'
        }
        Write-Host "$script:TestCount tests passed; PowerShell parser and XAML XML passed."
    } $testRoot
} finally {
    Remove-Module $module -Force
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
