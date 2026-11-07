#Requires -Version 5.1
Set-StrictMode -Version Latest

function Get-DebloatCatalog {
    # Exact package/service names only. Security, Store and update components are excluded.
    @(
        [pscustomobject]@{ Id='telemetry'; Category='Privacidade'; Title='Reduzir diagnóstico opcional'; Description='Limita a coleta de diagnóstico conforme a edição do Windows. Não promete eliminar toda a telemetria.'; Recommended=$true; Kind='Registry'; Targets=@(
            @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name='AllowTelemetry'; Value=1; Type='DWord'},
            @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name='DoNotShowFeedbackNotifications'; Value=1; Type='DWord'}
        ) },
        [pscustomobject]@{ Id='ads'; Category='Privacidade'; Title='Reduzir anúncios e sugestões'; Description='Desativa o ID de publicidade e sugestões promocionais do Windows para este usuário.'; Recommended=$true; Kind='Registry'; Targets=@(
            @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'; Name='Enabled'; Value=0; Type='DWord'},
            @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name='SystemPaneSuggestionsEnabled'; Value=0; Type='DWord'},
            @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name='SubscribedContent-338388Enabled'; Value=0; Type='DWord'}
        ) },
        [pscustomobject]@{ Id='activity'; Category='Privacidade'; Title='Desativar histórico de atividades'; Description='Desativa as políticas de histórico e publicação de atividades. Recursos disponíveis variam com a versão do Windows.'; Recommended=$false; Kind='Registry'; Targets=@(
            @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name='EnableActivityFeed'; Value=0; Type='DWord'},
            @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name='PublishUserActivities'; Value=0; Type='DWord'},
            @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name='UploadUserActivities'; Value=0; Type='DWord'}
        ) },
        [pscustomobject]@{ Id='edge-background'; Category='Privacidade'; Title='Reduzir atividade do Edge em segundo plano'; Description='Desativa inicialização acelerada e execução em segundo plano do Edge. Mantém o navegador, o WebView2 e as atualizações.'; Recommended=$false; Kind='Registry'; Targets=@(
            @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='StartupBoostEnabled'; Value=0; Type='DWord'},
            @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='BackgroundModeEnabled'; Value=0; Type='DWord'}
        ) },
        [pscustomobject]@{ Id='animations'; Category='Desempenho'; Title='Reduzir animações das janelas'; Description='Reduz animações de minimizar e maximizar. Pode exigir sair e entrar na conta para surtir efeito.'; Recommended=$false; Kind='Registry'; Targets=@(
            @{Path='HKCU:\Control Panel\Desktop\WindowMetrics'; Name='MinAnimate'; Value='0'; Type='String'}
        ) },
        [pscustomobject]@{ Id='power'; Category='Desempenho'; Title='Usar plano de alto desempenho'; Description='Tenta ativar o plano Alto Desempenho. Pode aumentar consumo e temperatura; nem todo computador oferece esse plano.'; Recommended=$false; Kind='PowerPlan'; Targets=@('8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c') },
        [pscustomobject]@{ Id='maps-service'; Category='Serviços'; Title='Desativar serviço de mapas offline'; Description='Desativa MapsBroker. Mapas baixados deixam de ser atualizados automaticamente.'; Recommended=$false; Kind='Service'; Targets=@('MapsBroker') },
        [pscustomobject]@{ Id='xbox-services'; Category='Serviços'; Title='Desativar serviços Xbox Live'; Description='Pode afetar login, jogos e partidas online do Xbox. Se você usa esses recursos, mantenha desmarcado.'; Recommended=$false; Kind='Service'; Targets=@('XblAuthManager','XblGameSave','XboxNetApiSvc') },
        [pscustomobject]@{ Id='solitaire'; Category='Aplicativos'; Title='Microsoft Solitaire Collection'; Description='Remove somente da conta atual. Reinstalação pela Microsoft Store; o backup de ajustes não restaura aplicativos.'; Recommended=$false; Kind='Appx'; Targets=@('Microsoft.MicrosoftSolitaireCollection') },
        [pscustomobject]@{ Id='clipchamp'; Category='Aplicativos'; Title='Clipchamp'; Description='Remove o editor de vídeo da conta atual. Pode ser reinstalado pela Microsoft Store.'; Recommended=$false; Kind='Appx'; Targets=@('Clipchamp.Clipchamp') },
        [pscustomobject]@{ Id='news'; Category='Aplicativos'; Title='Microsoft Notícias'; Description='Remove o aplicativo Notícias da conta atual. Não altera os aplicativos de outros usuários.'; Recommended=$false; Kind='Appx'; Targets=@('Microsoft.BingNews') },
        [pscustomobject]@{ Id='feedback'; Category='Aplicativos'; Title='Hub de Comentários'; Description='Remove o Hub de Comentários da conta atual. Pode ser reinstalado pela Microsoft Store.'; Recommended=$false; Kind='Appx'; Targets=@('Microsoft.WindowsFeedbackHub') },
        [pscustomobject]@{ Id='temp'; Category='Manutenção'; Title='Limpar arquivos temporários antigos'; Description='Exclui arquivos com mais de 7 dias no TEMP do usuário. Ignora links, arquivos recentes e arquivos em uso. Exclusões não são desfeitas pelo backup.'; Recommended=$false; Kind='Temp'; Targets=@() },
        [pscustomobject]@{ Id='sfc'; Category='Manutenção'; Title='Verificar e reparar arquivos do Windows'; Description='Executa sfc /scannow. Pode levar vários minutos. O resultado completo aparece no registro de execução.'; Recommended=$false; Kind='Sfc'; Targets=@() }
    )
}

function Get-DebloatPlan {
    param([Parameter(Mandatory=$true)][string[]]$ActionIds)
    $catalog = @(Get-DebloatCatalog)
    foreach ($id in @($ActionIds | Select-Object -Unique)) {
        $action = $catalog | Where-Object Id -EQ $id
        if (-not $action) { throw "Opção desconhecida: $id" }
        $action
    }
}

function Assert-DebloatPlatform {
    if ([Environment]::OSVersion.Platform -ne 'Win32NT' -or [Environment]::OSVersion.Version.Major -lt 10) {
        throw 'Este programa requer Windows 10 ou 11.'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Execute como administrador para aplicar ou restaurar ajustes.'
    }
}

function Get-DebloatIdentity {
    [pscustomobject]@{ Computer=$env:COMPUTERNAME; UserSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value }
}

function Get-DebloatDataPath {
    Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Win11Debloat'
}

function Write-DebloatEvent {
    param([scriptblock]$OnEvent, [string]$Message, [string]$Level='Info', [int]$Percent=-1)
    if ($OnEvent) { & $OnEvent ([pscustomobject]@{Message=$Message; Level=$Level; Percent=$Percent}) | Out-Null }
}

function Save-DebloatJournal {
    param($Journal, [string]$Path)
    # Write-ahead journal: if saving fails, no following system mutation is allowed.
    try {
        $directory = Split-Path -Parent $Path
        $null = [IO.Directory]::CreateDirectory($directory)
        $temp = "$Path.tmp"
        $json = $Journal | ConvertTo-Json -Depth 12
        [IO.File]::WriteAllText($temp, $json, (New-Object Text.UTF8Encoding($false)))
        if ([IO.File]::Exists($Path)) { [IO.File]::Replace($temp, $Path, [NullString]::Value) }
        else { [IO.File]::Move($temp, $Path) }
    } catch {
        $_.Exception.Data['DebloatJournalFailure']=$true
        throw
    }
}

function Get-DebloatRegistrySnapshot {
    param([string]$Path, [string]$Name)
    $exists = $false; $value = $null; $type = 'DWord'
    if (Test-Path -LiteralPath $Path) {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        try {
            $exists = @($key.GetValueNames()) -contains $Name
            if ($exists) {
                $type = $key.GetValueKind($Name).ToString()
                $value = $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            }
        } finally { $key.Close() }
    }
    [pscustomobject]@{Kind='Registry'; Path=$Path; Name=$Name; Exists=$exists; Value=$value; Type=$type; Restored=$false}
}

function Set-DebloatRegistryValue {
    param([string]$Path, [string]$Name, $Value, [string]$Type)
    $null = New-Item -Path $Path -Force -ErrorAction Stop
    $null = New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop
}

function Get-DebloatServiceSnapshot {
    param([string]$Name)
    $service = Get-Service -Name $Name -ErrorAction Stop
    $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    $delayed = Get-DebloatRegistrySnapshot -Path $path -Name 'DelayedAutoStart'
    [pscustomobject]@{
        Kind='Service'; Name=$Name; Start=[int](Get-ItemPropertyValue -LiteralPath $path -Name Start -ErrorAction Stop)
        DelayedExists=$delayed.Exists; DelayedValue=$delayed.Value
        Running=($service.Status -eq 'Running'); Restored=$false
    }
}

function Invoke-DebloatNative {
    param([string]$FilePath, [string[]]$Arguments)
    $output = & $FilePath @Arguments 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "$FilePath retornou código $LASTEXITCODE. $output" }
    $output.Trim()
}

function Get-DebloatPowerPlan {
    $output = Invoke-DebloatNative -FilePath "$env:SystemRoot\System32\powercfg.exe" -Arguments @('/getactivescheme')
    $match = [regex]::Match($output, '[a-fA-F0-9]{8}-(?:[a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}')
    if (-not $match.Success) { throw 'Não foi possível identificar o plano de energia ativo.' }
    $match.Value
}

function New-DebloatRestorePoint {
    Assert-DebloatPlatform
    $before = @(Get-ComputerRestorePoint -ErrorAction Stop | Sort-Object SequenceNumber -Descending)
    $lastSequence = if ($before.Count) { $before[0].SequenceNumber } else { -1 }
    # Do not silently enable protection or claim that a skipped checkpoint succeeded.
    Checkpoint-Computer -Description 'Win11 Debloat - antes dos ajustes' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop -WarningAction Stop
    $after = @(Get-ComputerRestorePoint -ErrorAction Stop | Where-Object { $_.SequenceNumber -gt $lastSequence })
    if (-not $after.Count) { throw 'O Windows não criou um novo ponto. Verifique a Proteção do Sistema ou o intervalo entre pontos.' }
    $after[0].Description
}

function Get-DebloatTemporaryFiles {
    param([string]$Root, [datetime]$Cutoff=(Get-Date).AddDays(-7))
    # Traverse explicitly: never follow a junction and never recursively delete a parent
    # just because its timestamp is old (it can contain recent files).
    $directory = Get-Item -LiteralPath $Root -Force -ErrorAction Stop
    if ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) { return }
    foreach ($item in @(Get-ChildItem -LiteralPath $Root -Force -ErrorAction SilentlyContinue)) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
        if ($item.PSIsContainer) { Get-DebloatTemporaryFiles -Root $item.FullName -Cutoff $Cutoff }
        elseif ($item.LastWriteTime -lt $Cutoff) { $item }
    }
}

function Invoke-DebloatApply {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param(
        [Parameter(Mandatory=$true)][string[]]$ActionIds,
        [switch]$CreateRestorePoint,
        [scriptblock]$OnEvent
    )
    $plan = @(Get-DebloatPlan -ActionIds $ActionIds)
    if (-not $plan.Count) { throw 'Selecione pelo menos uma opção.' }
    if ($WhatIfPreference) {
        foreach ($action in $plan) { Write-DebloatEvent $OnEvent "SIMULAÇÃO: $($action.Title) — $($action.Description)" }
        return [pscustomobject]@{Simulation=$true; Plan=$plan; Success=0; Failed=0; Skipped=0; BackupPath=$null; Results=@()}
    }
    Assert-DebloatPlatform
    if (-not $PSCmdlet.ShouldProcess('Windows e conta atual', "Aplicar $($plan.Count) opção(ões)")) { return }
    if ($CreateRestorePoint) {
        Write-DebloatEvent $OnEvent 'Criando ponto de restauração...'
        $null = New-DebloatRestorePoint
        Write-DebloatEvent $OnEvent 'Ponto de restauração confirmado.'
    }
    $identity = Get-DebloatIdentity
    $journal = [pscustomobject]@{
        SchemaVersion=1; Computer=$identity.Computer; UserSid=$identity.UserSid
        Created=(Get-Date).ToString('o'); ActionIds=@($plan.Id); Entries=@(); Irreversible=@()
    }
    $sessionId = (Get-Date -Format 'yyyyMMdd-HHmmssfffffff') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8)
    $backupPath = Join-Path (Join-Path (Get-DebloatDataPath) 'Backups') "$sessionId.json"
    Save-DebloatJournal $journal $backupPath
    $results = New-Object 'System.Collections.Generic.List[object]'
    $index = 0
    foreach ($action in $plan) {
        $index++
        Write-DebloatEvent $OnEvent $action.Title 'Info' ([int](100 * ($index - 1) / $plan.Count))
        $targets = if ($action.Kind -in @('Temp','Sfc')) { @('system') } else { @($action.Targets) }
        foreach ($target in $targets) {
            $label = if ($action.Kind -eq 'Registry') { "$($target.Path)\$($target.Name)" } else { [string]$target }
            try {
                $status = 'Success'; $detail = ''
                switch ($action.Kind) {
                    Registry {
                        $entry = Get-DebloatRegistrySnapshot -Path $target.Path -Name $target.Name
                        $journal.Entries += $entry
                        Save-DebloatJournal $journal $backupPath
                        Set-DebloatRegistryValue -Path $target.Path -Name $target.Name -Value $target.Value -Type $target.Type
                    }
                    Service {
                        if (-not (Get-Service -Name $target -ErrorAction SilentlyContinue)) {
                            $status='Skipped'; $detail='Serviço não encontrado.'; break
                        }
                        $entry = Get-DebloatServiceSnapshot -Name $target
                        $journal.Entries += $entry
                        Save-DebloatJournal $journal $backupPath
                        Set-Service -Name $target -StartupType Disabled -ErrorAction Stop
                        Stop-Service -Name $target -ErrorAction Stop
                    }
                    PowerPlan {
                        $journal.Entries += [pscustomobject]@{Kind='PowerPlan'; Guid=(Get-DebloatPowerPlan); Restored=$false}
                        Save-DebloatJournal $journal $backupPath
                        $null = Invoke-DebloatNative -FilePath "$env:SystemRoot\System32\powercfg.exe" -Arguments @('/setactive', $target)
                    }
                    Appx {
                        $packages = @(Get-AppxPackage -Name $target -ErrorAction Stop | Where-Object { $_.Name -eq $target })
                        if (-not $packages.Count) { $status='Skipped'; $detail='Aplicativo não instalado nesta conta.'; break }
                        foreach ($package in $packages) {
                            $journal.Irreversible += "Remoção solicitada: $($package.PackageFullName)"
                            Save-DebloatJournal $journal $backupPath
                            Remove-AppxPackage -Package $package.PackageFullName -ErrorAction Stop
                        }
                        $detail='Removido da conta atual. Reinstalação pela Microsoft Store.'
                    }
                    Temp {
                        $journal.Irreversible += 'Limpeza solicitada: arquivos temporários com mais de 7 dias.'
                        Save-DebloatJournal $journal $backupPath
                        $removed=0; $busy=0
                        foreach ($file in @(Get-DebloatTemporaryFiles -Root ([IO.Path]::GetTempPath()))) {
                            try { Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop; $removed++ }
                            catch { $busy++ }
                        }
                        $detail="$removed arquivo(s) removido(s); $busy indisponível(is)."
                    }
                    Sfc {
                        $journal.Irreversible += 'Verificação/reparo solicitado: sfc /scannow. Reparos não são desfeitos pelo backup de ajustes.'
                        Save-DebloatJournal $journal $backupPath
                        $detail = Invoke-DebloatNative -FilePath "$env:SystemRoot\System32\sfc.exe" -Arguments @('/scannow')
                    }
                }
                $results.Add([pscustomobject]@{Id=$action.Id; Target=$label; Status=$status; Detail=$detail})
                Write-DebloatEvent $OnEvent "$($action.Title): $label. $detail" $status
            } catch {
                # Journal I/O failure is fatal, including failures after a partial mutation.
                if ($_.Exception.Data.Contains('DebloatJournalFailure')) { throw }
                $results.Add([pscustomobject]@{Id=$action.Id; Target=$label; Status='Failed'; Detail=$_.Exception.Message})
                Write-DebloatEvent $OnEvent "$($action.Title): $($_.Exception.Message)" 'Error'
            }
        }
    }
    Save-DebloatJournal $journal $backupPath
    [pscustomobject]@{
        Simulation=$false; Success=@($results | Where-Object Status -EQ Success).Count
        Failed=@($results | Where-Object Status -EQ Failed).Count; Skipped=@($results | Where-Object Status -EQ Skipped).Count
        BackupPath=$backupPath; Results=@($results.ToArray())
    }
}

function Test-DebloatJournal {
    param($Journal)
    $identity = Get-DebloatIdentity
    if ($Journal.SchemaVersion -ne 1 -or $Journal.Computer -ne $identity.Computer -or $Journal.UserSid -ne $identity.UserSid) {
        throw 'Este backup não pertence a este computador/usuário ou tem formato incompatível.'
    }
    # Only restore known targets, never arbitrary elevated registry/service instructions.
    $catalog = @(Get-DebloatCatalog)
    $registryTargets = @($catalog | Where-Object Kind -EQ Registry | ForEach-Object { $_.Targets })
    $serviceTargets = @($catalog | Where-Object Kind -EQ Service | ForEach-Object { $_.Targets })
    foreach ($entry in $Journal.Entries) {
        switch ($entry.Kind) {
            Registry {
                if (-not @($registryTargets | Where-Object { $_.Path -eq $entry.Path -and $_.Name -eq $entry.Name }).Count) { throw 'Alvo de registro não permitido no backup.' }
                if ($entry.Type -notin @('DWord','QWord','String','ExpandString','MultiString','Binary','None') -or $entry.Exists -isnot [bool]) { throw 'Valor de registro inválido no backup.' }
            }
            Service {
                if ($entry.Name -notin $serviceTargets -or $entry.Start -notin @(2,3,4) -or $entry.Running -isnot [bool]) { throw 'Estado de serviço inválido no backup.' }
            }
            PowerPlan {
                if ($entry.Guid -notmatch '^[a-fA-F0-9]{8}-(?:[a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$') { throw 'Plano de energia inválido no backup.' }
            }
            default { throw 'Tipo de entrada desconhecido no backup.' }
        }
        if ($entry.Restored -isnot [bool]) { throw 'Estado de restauração inválido.' }
    }
}

function Restore-DebloatBackup {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param([Parameter(Mandatory=$true)][string]$Path, [scriptblock]$OnEvent)
    $journal = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json
    Test-DebloatJournal $journal
    # Restore sessions newest-first so overlapping settings return to the right state.
    $backupFile = Get-Item -LiteralPath $Path -ErrorAction Stop
    foreach ($newer in @(Get-DebloatBackups | Where-Object { $_.Name -gt $backupFile.Name })) {
        $other = Get-Content -LiteralPath $newer.FullName -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json
        if (@($other.Entries | Where-Object { -not $_.Restored }).Count -gt 0) {
            throw 'Restaure primeiro o backup mais recente com ajustes pendentes.'
        }
    }
    if (-not $PSCmdlet.ShouldProcess($Path, 'Restaurar valores originais de registro, serviços e energia')) { return }
    Assert-DebloatPlatform
    $failed=0; $restored=0
    $entries = @($journal.Entries)
    for ($i=$entries.Count-1; $i -ge 0; $i--) {
        $entry = $entries[$i]
        if ($entry.Restored) { continue }
        try {
            switch ($entry.Kind) {
                Registry {
                    if ($entry.Exists) {
                        $value = $entry.Value
                        if ($entry.Type -in @('Binary','None')) { $value=[byte[]]$value }
                        if ($entry.Type -eq 'MultiString') { $value=[string[]]$value }
                        Set-DebloatRegistryValue -Path $entry.Path -Name $entry.Name -Value $value -Type $entry.Type
                    } elseif (Test-Path -LiteralPath $entry.Path) {
                        Remove-ItemProperty -LiteralPath $entry.Path -Name $entry.Name -ErrorAction SilentlyContinue
                        $check = Get-DebloatRegistrySnapshot -Path $entry.Path -Name $entry.Name
                        if ($check.Exists) { throw 'Não foi possível remover o valor criado.' }
                    }
                }
                Service {
                    $startup = switch ([int]$entry.Start) { 2 {'Automatic'} 3 {'Manual'} 4 {'Disabled'} }
                    Set-Service -Name $entry.Name -StartupType $startup -ErrorAction Stop
                    $servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($entry.Name)"
                    if ($entry.DelayedExists) {
                        Set-DebloatRegistryValue -Path $servicePath -Name DelayedAutoStart -Value ([int]$entry.DelayedValue) -Type DWord
                    } else {
                        Remove-ItemProperty -LiteralPath $servicePath -Name DelayedAutoStart -ErrorAction SilentlyContinue
                        if ((Get-DebloatRegistrySnapshot -Path $servicePath -Name DelayedAutoStart).Exists) { throw 'Não foi possível restaurar DelayedAutoStart.' }
                    }
                    if ($entry.Running) { Start-Service -Name $entry.Name -ErrorAction Stop }
                    else { Stop-Service -Name $entry.Name -ErrorAction Stop }
                }
                PowerPlan {
                    $null = Invoke-DebloatNative -FilePath "$env:SystemRoot\System32\powercfg.exe" -Arguments @('/setactive', $entry.Guid)
                }
            }
        } catch {
            $failed++
            Write-DebloatEvent $OnEvent "Falha na restauração: $($_.Exception.Message)" 'Error'
            # Stop here: otherwise a later retry could replay newer snapshots out of order.
            break
        }
        $entry.Restored=$true
        Save-DebloatJournal $journal $Path
        $restored++
        Write-DebloatEvent $OnEvent "Restaurado: $($entry.Kind)" 'Success'
    }
    foreach ($notice in $journal.Irreversible) { Write-DebloatEvent $OnEvent "Não desfeito pelo backup: $notice" 'Warning' }
    [pscustomobject]@{Restored=$restored; Failed=$failed; BackupPath=$Path}
}

function Get-DebloatBackups {
    $path = Join-Path (Get-DebloatDataPath) 'Backups'
    if (Test-Path -LiteralPath $path) {
        Get-ChildItem -LiteralPath $path -Filter '*.json' -File | Sort-Object Name -Descending
    }
}

function Get-DebloatSystemInfo {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $apps = @(Get-AppxPackage -ErrorAction Stop | Select-Object -ExpandProperty Name)
    [pscustomobject]@{
        Caption=$os.Caption; Build=$os.BuildNumber
        MemoryGB=[Math]::Round($os.TotalVisibleMemorySize/1MB,1)
        InstalledApps=$apps
    }
}

Export-ModuleMember -Function Get-DebloatCatalog,Get-DebloatPlan,Assert-DebloatPlatform,Get-DebloatDataPath,Invoke-DebloatApply,Restore-DebloatBackup,Get-DebloatBackups,Get-DebloatSystemInfo,New-DebloatRestorePoint
