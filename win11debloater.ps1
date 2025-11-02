# Windows 11 Debloater Script - Versão Melhorada e Corrigida
# Autor: Script Melhorado
# Versão: 2.0
# Compatibilidade: Windows 10/11

#Requires -RunAsAdministrator
#Requires -Version 5.1

# ============================================
# CONFIGURAÇÃO INICIAL E VERIFICAÇÕES
# ============================================

# Configurar encoding UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$PSDefaultParameterValues['*:Encoding'] = 'utf8'

# Verificar se está rodando como administrador
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Write-Host "ERRO: Este script precisa ser executado como Administrador!" -ForegroundColor Red
    Write-Host "Por favor, feche e execute novamente como Administrador." -ForegroundColor Yellow
    pause
    exit 1
}

# Importar assemblies necessários
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName PresentationFramework

# ============================================
# FUNÇÕES DE UTILIDADE
# ============================================

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logFile = "$env:TEMP\Win11Debloater_$(Get-Date -Format 'yyyyMMdd').log"
    $logEntry = "$timestamp [$Level] $Message"
    
    # Escrever no arquivo de log
    Add-Content -Path $logFile -Value $logEntry -Force
    
    # Mostrar no console com cores
    switch ($Level) {
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        "INFO" { Write-Host $logEntry -ForegroundColor Cyan }
        default { Write-Host $logEntry }
    }
}

function Test-RegistryValue {
    param(
        [string]$Path,
        [string]$Name
    )
    
    try {
        $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        $Value,
        [string]$Type = "DWord"
    )
    
    try {
        if (!(Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
            Write-Log "Criado caminho do registro: $Path" "INFO"
        }
        
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        Write-Log "Registro atualizado: $Path\$Name = $Value" "SUCCESS"
        return $true
    } catch {
        Write-Log "Erro ao definir registro: $Path\$Name - $_" "ERROR"
        return $false
    }
}

# ============================================
# FUNÇÃO DE PONTO DE RESTAURAÇÃO MELHORADA
# ============================================

function New-SystemRestorePoint {
    param(
        [string]$Description = "Windows Debloater - Antes das Modificações"
    )
    
    Write-Log "Verificando configuração de Restauração do Sistema..." "INFO"
    
    try {
        # Habilitar Restauração do Sistema se necessário
        $systemDrive = $env:SystemDrive
        $restoreStatus = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
        
        if ($null -eq $restoreStatus) {
            Write-Log "Habilitando Restauração do Sistema..." "WARNING"
            Enable-ComputerRestore -Drive "$systemDrive\" -Confirm:$false
            Start-Sleep -Seconds 2
        }
        
        # Verificar espaço em disco
        $drive = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$systemDrive'"
        $freeSpaceGB = [math]::Round($drive.FreeSpace / 1GB, 2)
        
        if ($freeSpaceGB -lt 2) {
            Write-Log "Espaço em disco insuficiente para ponto de restauração: $freeSpaceGB GB" "WARNING"
            $continue = Read-Host "Deseja continuar mesmo assim? (S/N)"
            if ($continue -notmatch '^[Ss]') {
                return $false
            }
        }
        
        # Criar ponto de restauração
        Write-Log "Criando ponto de restauração..." "INFO"
        Checkpoint-Computer -Description $Description -RestorePointType MODIFY_SETTINGS
        
        Start-Sleep -Seconds 3
        
        # Verificar se foi criado
        $newPoint = Get-ComputerRestorePoint | Sort-Object CreationTime -Descending | Select-Object -First 1
        if ($newPoint -and $newPoint.CreationTime -gt (Get-Date).AddMinutes(-5)) {
            Write-Log "Ponto de restauração criado com sucesso!" "SUCCESS"
            Write-Log "Descrição: $($newPoint.Description)" "INFO"
            return $true
        }
        
    } catch {
        Write-Log "Erro ao criar ponto de restauração: $_" "ERROR"
        return $false
    }
    
    return $false
}

# ============================================
# FUNÇÃO DE DESABILITAR TELEMETRIA MELHORADA
# ============================================

function Disable-WindowsTelemetry {
    Write-Log "========== Desabilitando Telemetria do Windows ==========" "INFO"
    
    $telemetrySettings = @{
        # Telemetria principal
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" = @{
            "AllowTelemetry" = 0
            "MaxTelemetryAllowed" = 0
            "AllowDeviceNameInTelemetry" = 0
        }
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" = @{
            "AllowTelemetry" = 0
            "DoNotShowFeedbackNotifications" = 1
            "AllowCommercialDataPipeline" = 0
        }
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" = @{
            "AllowTelemetry" = 0
        }
        # Compatibilidade de aplicativos
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" = @{
            "AITEnable" = 0
            "DisableUAR" = 1
            "DisableInventory" = 1
            "DisablePCA" = 1
        }
        # Edge telemetria
        "HKLM:\SOFTWARE\Policies\Microsoft\Edge" = @{
            "SendSiteInfoToImproveServices" = 0
            "MetricsReportingEnabled" = 0
        }
        # Windows Error Reporting
        "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" = @{
            "Disabled" = 1
            "DontSendAdditionalData" = 1
        }
        # Customer Experience Improvement Program
        "HKLM:\SOFTWARE\Microsoft\SQMClient\Windows" = @{
            "CEIPEnable" = 0
        }
        "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" = @{
            "CEIPEnable" = 0
        }
    }
    
    foreach ($regPath in $telemetrySettings.Keys) {
        foreach ($setting in $telemetrySettings[$regPath].GetEnumerator()) {
            Set-RegistryValue -Path $regPath -Name $setting.Key -Value $setting.Value
        }
    }
    
    # Desabilitar tarefas agendadas de telemetria
    $telemetryTasks = @(
        "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        "Microsoft\Windows\Application Experience\PcaPatchDbTask",
        "Microsoft\Windows\Application Experience\ProgramDataUpdater",
        "Microsoft\Windows\Application Experience\StartupAppTask",
        "Microsoft\Windows\Autochk\Proxy",
        "Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
        "Microsoft\Windows\PI\Sqm-Tasks",
        "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem",
        "Microsoft\Windows\Windows Error Reporting\QueueReporting",
        "Microsoft\Windows\Application Experience\AitAgent",
        "Microsoft\Windows\Device Information\Device",
        "Microsoft\Windows\Device Information\Device User"
    )
    
    foreach ($task in $telemetryTasks) {
        try {
            Disable-ScheduledTask -TaskName $task -ErrorAction Stop | Out-Null
            Write-Log "Tarefa desabilitada: $task" "SUCCESS"
        } catch {
            Write-Log "Não foi possível desabilitar tarefa: $task" "WARNING"
        }
    }
    
    Write-Log "Telemetria desabilitada com sucesso!" "SUCCESS"
}

# ============================================
# FUNÇÃO MELHORADA PARA DESABILITAR SERVIÇOS
# ============================================

function Disable-WindowsServices {
    Write-Log "========== Desabilitando Serviços Desnecessários ==========" "INFO"
    
    $servicesToDisable = @(
        @{Name = "DiagTrack"; DisplayName = "Diagnostics Tracking Service"},
        @{Name = "dmwappushservice"; DisplayName = "WAP Push Service"},
        @{Name = "WerSvc"; DisplayName = "Windows Error Reporting"},
        @{Name = "MapsBroker"; DisplayName = "Downloaded Maps Manager"},
        @{Name = "XblAuthManager"; DisplayName = "Xbox Live Auth Manager"},
        @{Name = "XblGameSave"; DisplayName = "Xbox Live Game Save"},
        @{Name = "XboxNetApiSvc"; DisplayName = "Xbox Live Networking Service"},
        @{Name = "XboxGipSvc"; DisplayName = "Xbox Accessory Management"},
        @{Name = "RetailDemo"; DisplayName = "Retail Demo Service"},
        @{Name = "RemoteRegistry"; DisplayName = "Remote Registry"},
        @{Name = "WSearch"; DisplayName = "Windows Search"; Optional = $true},
        @{Name = "WMPNetworkSvc"; DisplayName = "Windows Media Player Network"},
        @{Name = "wisvc"; DisplayName = "Windows Insider Service"},
        @{Name = "SysMain"; DisplayName = "Superfetch/SysMain"; Optional = $true},
        @{Name = "lfsvc"; DisplayName = "Geolocation Service"},
        @{Name = "PcaSvc"; DisplayName = "Program Compatibility Assistant"},
        @{Name = "OneSyncSvc"; DisplayName = "Sync Host"; Optional = $true},
        @{Name = "MessagingService"; DisplayName = "Messaging Service"},
        @{Name = "diagnosticshub.standardcollector.service"; DisplayName = "Diagnostics Hub"}
    )
    
    $disabledCount = 0
    $failedServices = @()
    
    foreach ($svc in $servicesToDisable) {
        try {
            $service = Get-Service -Name $svc.Name -ErrorAction Stop
            
            # Verificar se é um serviço opcional e perguntar ao usuário
            if ($svc.Optional) {
                Write-Host "`nServiço opcional encontrado: $($svc.DisplayName)" -ForegroundColor Yellow
                $choice = Read-Host "Deseja desabilitar? (S/N)"
                if ($choice -notmatch '^[Ss]') {
                    Write-Log "Serviço mantido: $($svc.DisplayName)" "INFO"
                    continue
                }
            }
            
            # Parar o serviço se estiver rodando
            if ($service.Status -eq 'Running') {
                Stop-Service -Name $svc.Name -Force -ErrorAction Stop
                Start-Sleep -Seconds 2
            }
            
            # Desabilitar o serviço
            Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction Stop
            $disabledCount++
            Write-Log "Serviço desabilitado: $($svc.DisplayName)" "SUCCESS"
            
        } catch {
            if ($_.Exception.Message -notlike "*não foi possível encontrar*") {
                $failedServices += $svc.DisplayName
                Write-Log "Falha ao desabilitar: $($svc.DisplayName) - $_" "WARNING"
            }
        }
    }
    
    Write-Log "Total de serviços desabilitados: $disabledCount" "SUCCESS"
    
    if ($failedServices.Count -gt 0) {
        Write-Log "Serviços que falharam: $($failedServices -join ', ')" "WARNING"
    }
}

# ============================================
# FUNÇÃO MELHORADA PARA REMOVER MICROSOFT EDGE
# ============================================

function Remove-MicrosoftEdge {
    Write-Log "========== Removendo Microsoft Edge ==========" "INFO"
    
    $confirmation = Read-Host "ATENÇÃO: Remover o Edge pode causar problemas em alguns apps. Continuar? (S/N)"
    if ($confirmation -notmatch '^[Ss]') {
        Write-Log "Remoção do Edge cancelada pelo usuário" "INFO"
        return
    }
    
    # Parar todos os processos do Edge
    $edgeProcesses = @("msedge", "msedgewebview2", "MicrosoftEdge", "MicrosoftEdgeCP", "MicrosoftEdgeSH")
    foreach ($process in $edgeProcesses) {
        Get-Process -Name $process -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    
    Start-Sleep -Seconds 3
    
    # Desabilitar serviços do Edge
    $edgeServices = @("edgeupdate", "edgeupdatem", "MicrosoftEdgeElevationService")
    foreach ($service in $edgeServices) {
        try {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($svc) {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Log "Serviço Edge desabilitado: $service" "SUCCESS"
            }
        } catch {
            Write-Log "Não foi possível desabilitar serviço: $service" "WARNING"
        }
    }
    
    # Remover Edge via PowerShell
    Write-Log "Removendo pacotes do Edge..." "INFO"
    
    # Remover Edge Chromium
    $edgePackages = Get-AppxPackage -AllUsers | Where-Object {$_.Name -like "*MicrosoftEdge*"}
    foreach ($package in $edgePackages) {
        try {
            Remove-AppxPackage -Package $package.PackageFullName -AllUsers -ErrorAction Stop
            Write-Log "Pacote removido: $($package.Name)" "SUCCESS"
        } catch {
            Write-Log "Falha ao remover pacote: $($package.Name)" "WARNING"
        }
    }
    
    # Remover provisioned packages
    $provisionedPackages = Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like "*Edge*"}
    foreach ($package in $provisionedPackages) {
        try {
            Remove-AppxProvisionedPackage -Online -PackageName $package.PackageName -ErrorAction Stop
            Write-Log "Provisioned package removido: $($package.DisplayName)" "SUCCESS"
        } catch {
            Write-Log "Falha ao remover provisioned package: $($package.DisplayName)" "WARNING"
        }
    }
    
    # Executar desinstalador do Edge se existir
    $edgePaths = @(
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application",
        "${env:ProgramFiles}\Microsoft\Edge\Application"
    )
    
    foreach ($path in $edgePaths) {
        if (Test-Path $path) {
            $setupExe = Get-ChildItem -Path $path -Recurse -Filter "setup.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
            
            if ($setupExe) {
                try {
                    Write-Log "Executando desinstalador do Edge..." "INFO"
                    $arguments = "--uninstall --system-level --force-uninstall"
                    $process = Start-Process -FilePath $setupExe.FullName -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden
                    
                    if ($process.ExitCode -eq 0) {
                        Write-Log "Edge desinstalado via setup.exe" "SUCCESS"
                    } else {
                        Write-Log "Setup.exe retornou código: $($process.ExitCode)" "WARNING"
                    }
                } catch {
                    Write-Log "Erro ao executar setup.exe: $_" "ERROR"
                }
            }
        }
    }
    
    # Bloquear reinstalação do Edge
    $blockEdgeRegistry = @{
        "HKLM:\SOFTWARE\Microsoft" = @{
            "EdgeUpdate" = 1
            "DoNotUpdateToEdgeWithChromium" = 1
        }
    }
    
    foreach ($regPath in $blockEdgeRegistry.Keys) {
        foreach ($setting in $blockEdgeRegistry[$regPath].GetEnumerator()) {
            Set-RegistryValue -Path $regPath -Name $setting.Key -Value $setting.Value
        }
    }
    
    # Remover atalhos do Edge
    $shortcuts = @(
        "$env:PUBLIC\Desktop\Microsoft Edge.lnk",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk",
        "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk"
    )
    
    foreach ($shortcut in $shortcuts) {
        if (Test-Path $shortcut) {
            Remove-Item -Path $shortcut -Force -ErrorAction SilentlyContinue
            Write-Log "Atalho removido: $shortcut" "SUCCESS"
        }
    }
    
    Write-Log "Processo de remoção do Edge concluído!" "SUCCESS"
    Write-Log "Recomenda-se reiniciar o sistema para completar a remoção." "WARNING"
}

# ============================================
# FUNÇÃO MELHORADA PARA REMOVER BLOATWARE
# ============================================

function Remove-WindowsBloatware {
    Write-Log "========== Removendo Bloatware do Windows ==========" "INFO"
    
    $bloatwareList = @(
        # Comunicação e Social
        "*Microsoft.People*",
        "*Microsoft.YourPhone*",
        "*Microsoft.Messaging*",
        "*Microsoft.GetHelp*",
        "*Microsoft.Getstarted*",
        "*Microsoft.WindowsFeedbackHub*",
        
        # Entretenimento
        "*Microsoft.BingNews*",
        "*Microsoft.BingWeather*",
        "*Microsoft.BingSports*",
        "*Microsoft.BingFinance*",
        "*Microsoft.BingTravel*",
        "*Microsoft.BingHealthAndFitness*",
        "*Microsoft.BingFoodAndDrink*",
        "*Microsoft.ZuneMusic*",
        "*Microsoft.ZuneVideo*",
        "*Microsoft.Music.Preview*",
        "*Microsoft.MicrosoftSolitaireCollection*",
        "*Microsoft.MixedReality.Portal*",
        "*Microsoft.Wallet*",
        
        # Produtividade (Opcional)
        "*Microsoft.MicrosoftOfficeHub*",
        "*Microsoft.Office.OneNote*",
        "*Microsoft.MicrosoftStickyNotes*",
        "*Microsoft.Todos*",
        "*Microsoft.PowerAutomateDesktop*",
        
        # Utilitários
        "*Microsoft.WindowsAlarms*",
        "*Microsoft.WindowsMaps*",
        "*Microsoft.WindowsSoundRecorder*",
        "*Microsoft.WindowsCamera*",
        "*Microsoft.ScreenSketch*",
        "*Microsoft.Windows.Photos*",
        
        # Xbox (se não for gamer)
        "*Microsoft.Xbox*",
        "*Microsoft.GamingApp*",
        "*Microsoft.GamingServices*",
        
        # Teams e comunicação corporativa
        "*MicrosoftTeams*",
        "*Microsoft.SkypeApp*",
        
        # Outros
        "*ClipChamp.ClipChamp*",
        "*Microsoft.WindowsTerminal*",
        "*Microsoft.HEIFImageExtension*",
        "*Microsoft.WebMediaExtensions*",
        "*Microsoft.WebpImageExtension*",
        "*Microsoft.Wind3DViewer*",
        "*Microsoft.RemoteDesktop*",
        "*Microsoft.NetworkSpeedTest*",
        "*Microsoft.News*",
        "*Microsoft.Lens*",
        "*Microsoft.Sway*",
        "*Microsoft.OneConnect*",
        "*Microsoft.Print3D*",
        "*Microsoft.SimpleMindMaps*",
        "*Microsoft.Whiteboard*",
        "*Microsoft.Advertising.Xaml*"
    )
    
    Write-Host "`nApps que serão removidos:" -ForegroundColor Yellow
    $installedBloatware = @()
    
    foreach ($bloat in $bloatwareList) {
        $apps = Get-AppxPackage -Name $bloat -AllUsers -ErrorAction SilentlyContinue
        if ($apps) {
            foreach ($app in $apps) {
                $installedBloatware += $app.Name
                Write-Host "  - $($app.Name)" -ForegroundColor Red
            }
        }
    }
    
    if ($installedBloatware.Count -eq 0) {
        Write-Log "Nenhum bloatware encontrado para remover!" "INFO"
        return
    }
    
    Write-Host "`nTotal de apps a remover: $($installedBloatware.Count)" -ForegroundColor Yellow
    $continue = Read-Host "Deseja continuar com a remoção? (S/N)"
    
    if ($continue -notmatch '^[Ss]') {
        Write-Log "Remoção de bloatware cancelada" "INFO"
        return
    }
    
    $removedCount = 0
    $failedCount = 0
    
    foreach ($bloat in $bloatwareList) {
        # Remover para todos os usuários
        Get-AppxPackage -Name $bloat -AllUsers -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction Stop
                $removedCount++
                Write-Log "Removido: $($_.Name)" "SUCCESS"
            } catch {
                $failedCount++
                Write-Log "Falha ao remover: $($_.Name) - $_" "WARNING"
            }
        }
        
        # Remover provisioned packages
        Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | 
            Where-Object {$_.DisplayName -like $bloat} | ForEach-Object {
            try {
                Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction Stop
                Write-Log "Removido (provisioned): $($_.DisplayName)" "SUCCESS"
            } catch {
                Write-Log "Falha ao remover (provisioned): $($_.DisplayName)" "WARNING"
            }
        }
    }
    
    Write-Log "Remoção de bloatware concluída!" "SUCCESS"
    Write-Log "Apps removidos: $removedCount | Falhas: $failedCount" "INFO"
}

# ============================================
# FUNÇÃO DE PRIVACIDADE MELHORADA
# ============================================

function Set-PrivacySettings {
    Write-Log "========== Configurando Privacidade ==========" "INFO"
    
    $privacySettings = @{
        # Desabilitar ID de publicidade
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" = @{
            "Enabled" = 0
        }
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" = @{
            "DisabledByGroupPolicy" = 1
        }
        
        # Desabilitar rastreamento de localização
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" = @{
            "Value" = "Deny"
        }
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" = @{
            "SensorPermissionState" = 0
        }
        
        # Desabilitar histórico de atividades
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" = @{
            "EnableActivityFeed" = 0
            "PublishUserActivities" = 0
            "UploadUserActivities" = 0
        }
        
        # Desabilitar sugestões e anúncios
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" = @{
            "ContentDeliveryAllowed" = 0
            "OemPreInstalledAppsEnabled" = 0
            "PreInstalledAppsEnabled" = 0
            "PreInstalledAppsEverEnabled" = 0
            "SilentInstalledAppsEnabled" = 0
            "SubscribedContent-338387Enabled" = 0
            "SubscribedContent-338388Enabled" = 0
            "SubscribedContent-338389Enabled" = 0
            "SubscribedContent-338393Enabled" = 0
            "SubscribedContent-353694Enabled" = 0
            "SubscribedContent-353696Enabled" = 0
            "SubscribedContent-353698Enabled" = 0
            "SystemPaneSuggestionsEnabled" = 0
            "SoftLandingEnabled" = 0
            "RotatingLockScreenEnabled" = 0
            "RotatingLockScreenOverlayEnabled" = 0
        }
        
        # Desabilitar Cortana
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" = @{
            "AllowCortana" = 0
            "AllowCortanaAboveLock" = 0
            "DisableWebSearch" = 1
            "AllowSearchToUseLocation" = 0
        }
        
        # Desabilitar feedback
        "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" = @{
            "NumberOfSIUFInPeriod" = 0
        }
        
        # Desabilitar sincronização
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" = @{
            "DisableSettingSync" = 1
            "DisableSettingSyncUserOverride" = 1
        }
        
        # Desabilitar entrada de dados personalizada
        "HKCU:\SOFTWARE\Microsoft\InputPersonalization" = @{
            "RestrictImplicitInkCollection" = 1
            "RestrictImplicitTextCollection" = 1
        }
        "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" = @{
            "HarvestContacts" = 0
        }
        
        # Desabilitar compartilhamento Wi-Fi
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" = @{
            "Value" = 0
        }
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" = @{
            "Value" = 0
        }
    }
    
    foreach ($regPath in $privacySettings.Keys) {
        foreach ($setting in $privacySettings[$regPath].GetEnumerator()) {
            Set-RegistryValue -Path $regPath -Name $setting.Key -Value $setting.Value
        }
    }
    
    Write-Log "Configurações de privacidade aplicadas!" "SUCCESS"
}

# ============================================
# FUNÇÃO DE OTIMIZAÇÃO DE DESEMPENHO
# ============================================

function Optimize-Performance {
    Write-Log "========== Otimizando Desempenho do Sistema ==========" "INFO"
    
    # Desabilitar animações desnecessárias
    Set-RegistryValue -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Value 0
    Set-RegistryValue -Path "HKCU:\Control Panel\Desktop" -Name "VisualFXSetting" -Value 2
    Set-RegistryValue -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value 0
    
    # Otimizar prioridade de CPU para programas
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 38
    
    # Desabilitar Superfetch/SysMain se SSD detectado
    $systemDrive = Get-PhysicalDisk | Where-Object {$_.MediaType -eq "SSD"}
    if ($systemDrive) {
        Write-Log "SSD detectado - desabilitando Superfetch" "INFO"
        Stop-Service -Name "SysMain" -Force -ErrorAction SilentlyContinue
        Set-Service -Name "SysMain" -StartupType Disabled -ErrorAction SilentlyContinue
    }
    
    # Configurar gerenciamento de energia para alto desempenho
    powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2>$null
    
    # Desabilitar hibernação para economizar espaço
    powercfg /h off
    
    # Limpar arquivos temporários
    try {
        Write-Log "Limpando arquivos temporários..." "INFO"
        $tempFolders = @(
            "$env:TEMP",
            "$env:SystemRoot\Temp",
            "$env:SystemRoot\Prefetch"
        )
        
        foreach ($folder in $tempFolders) {
            if (Test-Path $folder) {
                Get-ChildItem -Path $folder -Force -ErrorAction SilentlyContinue | 
                    Where-Object { ($_.LastWriteTime -lt (Get-Date).AddDays(-7)) } | 
                    Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
            }
        }
        Write-Log "Limpeza de arquivos temporários concluída" "SUCCESS"
    }
    catch {
        Write-Log "Erro na limpeza de arquivos temporários: $_" "ERROR"
    }
    
    Write-Log "Otimização de desempenho concluída!" "SUCCESS"
}

# ============================================
# MENU PRINCIPAL MELHORADO
# ============================================

function Show-MainMenu {
    do {
        Clear-Host
        Write-Host "=================================================================" -ForegroundColor Cyan
        Write-Host "                 WINDOWS 11/10 DEBLOATER SCRIPT                    " -ForegroundColor Yellow
        Write-Host "                         Versão 2.0                               " -ForegroundColor Yellow
        Write-Host "=================================================================" -ForegroundColor Cyan
        Write-Host ""
        
        # Menu Privacidade
        Write-Host "--- PRIVACIDADE & SEGURANÇA ---" -ForegroundColor Green
        Write-Host "  1. Desabilitar Telemetria" -ForegroundColor White
        Write-Host "  2. Configurar Privacidade" -ForegroundColor White
        Write-Host "  3. Desabilitar Cortana" -ForegroundColor White
        Write-Host ""
        
        # Menu Otimização
        Write-Host "--- OTIMIZAÇÃO ---" -ForegroundColor Magenta
        Write-Host "  4. Remover Bloatware" -ForegroundColor White
        Write-Host "  5. Desabilitar Serviços" -ForegroundColor White
        Write-Host "  6. Otimizar Desempenho" -ForegroundColor White
        Write-Host ""
        
        # Menu Manutenção
        Write-Host "--- MANUTENÇÃO ---" -ForegroundColor Blue
        Write-Host "  7. Criar Ponto de Restauração" -ForegroundColor White
        Write-Host "  8. Limpar Sistema" -ForegroundColor White
        Write-Host "  9. Verificar Integridade" -ForegroundColor White
        Write-Host ""
        
        # Menu Ferramentas
        Write-Host "--- FERRAMENTAS ---" -ForegroundColor Yellow
        Write-Host " 10. Remover Microsoft Edge" -ForegroundColor White
        Write-Host " 11. Instalar Programas" -ForegroundColor White
        Write-Host ""
        
        Write-Host "--- OUTROS ---" -ForegroundColor DarkGray
        Write-Host "  0. Sair" -ForegroundColor White
        Write-Host ""
        Write-Host "=================================================================" -ForegroundColor Cyan
        
        $choice = Read-Host "Digite sua escolha"
        
        switch ($choice) {
            "1" { 
                New-RestorePoint
                Disable-WindowsTelemetry
                pause
            }
            "2" { 
                New-RestorePoint
                Set-PrivacySettings
                pause
            }
            "3" { 
                Disable-Cortana
                pause
            }
            "4" { 
                New-RestorePoint
                Remove-WindowsBloatware
                pause
            }
            "5" { 
                New-RestorePoint
                Disable-WindowsServices
                pause
            }
            "6" { 
                New-RestorePoint
                Optimize-Performance
                pause
            }
            "7" { 
                New-RestorePoint
                pause
            }
            "8" { 
                Show-MaintenanceMenu
            }
            "9" { 
                Test-PCHealth
                pause
            }
            "10" { 
                New-RestorePoint
                Remove-MicrosoftEdge
                pause
            }
            "11" { 
                Install-Programs
            }
            "0" { 
                return 
            }
            default {
                Write-Host "`nOpção inválida. Pressione qualquer tecla para continuar..." -ForegroundColor Red
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
        }
    } while ($true)
}

# Iniciar o script
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Write-Host "Este script precisa ser executado como Administrador!" -ForegroundColor Red
    Write-Host "Por favor, execute novamente com privilégios administrativos." -ForegroundColor Yellow
    pause
    exit 1
}

# Criar ponto de restauração inicial
New-RestorePoint
Show-MainMenu
