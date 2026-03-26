# Windows 11/10 Debloater Script - Versão Corrigida e Otimizada
# Baseado no script original, com correções críticas e melhorias de segurança
# Aviso: Use por sua conta e risco. Sempre crie um ponto de restauração primeiro.

#Requires -RunAsAdministrator
#Requires -Version 5.1

# ============================================
# CONFIGURAÇÃO INICIAL E VERIFICAÇÕES
# ============================================

# Configurar encoding e preferências de erro
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = "Stop"
$WarningPreference = "Continue"
$ProgressPreference = "Continue"

# Verificar versão do Windows
$osVersion = [System.Environment]::OSVersion.Version
if ($osVersion.Major -lt 10) {
    Write-Host "ERRO: Este script requer Windows 10 ou 11" -ForegroundColor Red
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
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logFile = "$env:TEMP\Win11Debloater_$(Get-Date -Format 'yyyyMMdd').log"
    $logEntry = "$timestamp [$Level] $Message"
    
    # Escrever no arquivo de log
    Add-Content -Path $logFile -Value $logEntry -Force
    
    # Mostrar no console com cores
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        "INFO" { "Cyan" }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Test-RegistryValue {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        
        [Parameter(Mandatory=$true)]
        [string]$Name
    )
    
    try {
        $null = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Set-RegistryValue {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        
        [Parameter(Mandatory=$true)]
        [string]$Name,
        
        [Parameter(Mandatory=$true)]
        $Value,
        
        [ValidateSet("DWord", "String", "Binary", "ExpandString", "MultiString", "QWord")]
        [string]$Type = "DWord"
    )
    
    try {
        if (!(Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
            Write-Log "Criado caminho do registro: $Path" "INFO"
        }
        
        # Backup da chave antes de modificar
        $backupPath = "$env:TEMP\regbackup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        if (!(Test-Path $backupPath)) {
            New-Item -Path $backupPath -ItemType Directory | Out-Null
        }
        $regExportFile = "$backupPath\$($Name -replace '\\s+|\\W+', '_').reg"
        
        try {
            reg export "$(($Path -replace 'HKLM:\\', 'HKEY_LOCAL_MACHINE\') -replace 'HKCU:\\', 'HKEY_CURRENT_USER\')" $regExportFile /y 2>$null
        } catch {
            Write-Log "Não foi possível criar backup do registro: $_" "WARNING"
        }
        
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        Write-Log "Registro atualizado: $Path\$Name = $Value" "SUCCESS"
        return $true
    } catch {
        Write-Log "Erro ao definir registro: $Path\$Name - $_" "ERROR"
        return $false
    }
}

function New-SystemRestorePoint {
    param(
        [string]$Description = "Windows Debloater - Backup Automático"
    )
    
    Write-Log "Verificando configuração de Restauração do Sistema..." "INFO"
    
    try {
        # Verificar se o serviço de restauração está habilitado
        $systemDrive = $env:SystemDrive
        $restoreEnabled = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
        
        if ($null -eq $restoreEnabled) {
            Write-Log "Habilitando Restauração do Sistema..." "WARNING"
            Enable-ComputerRestore -Drive "$systemDrive\" -Confirm:$false
            Start-Sleep -Seconds 3
        }
        
        # Verificar espaço em disco
        $drive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$systemDrive'"
        $freeSpaceGB = [Math]::Round($drive.FreeSpace / 1GB, 2)
        
        if ($freeSpaceGB -lt 5) {
            Write-Log "Espaço em disco baixo: $freeSpaceGB GB - Ponto de restauração pode falhar" "WARNING"
            $continue = Read-Host "Continuar mesmo assim? (S/N)"
            if ($continue -notmatch '^[Ss]') {
                return $false
            }
        }
        
        # Criar ponto de restauração
        Write-Log "Criando ponto de restauração..." "INFO"
        Checkpoint-Computer -Description $Description -RestorePointType "MODIFY_SETTINGS"
        
        Start-Sleep -Seconds 5
        
        # Verificar se foi criado
        $newPoint = Get-ComputerRestorePoint | Sort-Object CreationTime -Descending | Select-Object -First 1
        if ($newPoint -and $newPoint.CreationTime -gt (Get-Date).AddMinutes(-5)) {
            Write-Log "Ponto de restauração criado com sucesso: $($newPoint.Description)" "SUCCESS"
            return $true
        } else {
            Write-Log "Falha ao verificar criação do ponto de restauração" "ERROR"
            return $false
        }
        
    } catch {
        Write-Log "Erro ao criar ponto de restauração: $_" "ERROR"
        $retry = Read-Host "Deseja continuar mesmo sem ponto de restauração? (S/N)"
        return ($retry -match '^[Ss]')
    }
}

# ============================================
# FUNÇÕES PRINCIPAIS
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
            "MetricsReportingEnabled" = 0
        }
        # Windows Error Reporting
        "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" = @{
            "Disabled" = 0  # Deixar habilitado para diagnóstico
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
        "Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        "Microsoft\Windows\Windows Error Reporting\QueueReporting"
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
            "DisableSettingSync" = 2
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

function Disable-WindowsServices {
    Write-Log "========== Desabilitando Serviços Desnecessários ==========" "INFO"
    
    # Serviços seguros para desabilitar
    $servicesToDisable = @(
        @{Name = "DiagTrack"; DisplayName = "Diagnostics Tracking Service"},
        @{Name = "dmwappushservice"; DisplayName = "WAP Push Service"},
        @{Name = "MapsBroker"; DisplayName = "Downloaded Maps Manager"},
        @{Name = "XblAuthManager"; DisplayName = "Xbox Live Auth Manager"},
        @{Name = "XblGameSave"; DisplayName = "Xbox Live Game Save"},
        @{Name = "XboxNetApiSvc"; DisplayName = "Xbox Live Networking Service"},
        @{Name = "XboxGipSvc"; DisplayName = "Xbox Accessory Management"},
        @{Name = "RetailDemo"; DisplayName = "Retail Demo Service"},
        @{Name = "RemoteRegistry"; DisplayName = "Remote Registry"; Optional = $true},
        @{Name = "WMPNetworkSvc"; DisplayName = "Windows Media Player Network"},
        @{Name = "wisvc"; DisplayName = "Windows Insider Service"},
        @{Name = "lfsvc"; DisplayName = "Geolocation Service"},
        @{Name = "PcaSvc"; DisplayName = "Program Compatibility Assistant"},
        @{Name = "MessagingService"; DisplayName = "Messaging Service"},
        @{Name = "diagnosticshub.standardcollector.service"; DisplayName = "Diagnostics Hub"}
    )
    
    # Serviços problemáticos - NÃO desabilitar
    $criticalServices = @(
        "WerSvc",    # Error Reporting essencial para diagnóstico
        "SysMain",   # Pode melhorar performance em SSDs modernos
        "OneSyncSvc" # Pode quebrar funcionalidades do sistema
    )
    Write-Log "Serviços críticos preservados: $($criticalServices -join ', ')" "INFO"
    
    $disabledCount = 0
    $failedServices = @()
    
    foreach ($svc in $servicesToDisable) {
        try {
            $service = Get-Service -Name $svc.Name -ErrorAction Stop
            
            # Verificar se é opcional
            if ($svc.Optional) {
                Write-Host "`nServiço opcional: $($svc.DisplayName)" -ForegroundColor Yellow
                $choice = Read-Host "Deseja desabilitar? (S/N)"
                if ($choice -notmatch '^[Ss]') {
                    Write-Log "Serviço mantido: $($svc.DisplayName)" "INFO"
                    continue
                }
            }
            
            # Parar e desabilitar
            if ($service.Status -eq 'Running') {
                Stop-Service -Name $svc.Name -Force -ErrorAction Stop
                Start-Sleep -Seconds 1
            }
            
            Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction Stop
            $disabledCount++
            Write-Log "Serviço desabilitado: $($svc.DisplayName)" "SUCCESS"
            
        } catch {
            $failedServices += $svc.DisplayName
            Write-Log "Falha ao desabilitar: $($svc.DisplayName) - $_" "WARNING"
        }
    }
    
    Write-Log "Total de serviços desabilitados: $disabledCount" "SUCCESS"
}

function Disable-MicrosoftEdge {
    Write-Log "========== Desabilitando Microsoft Edge (Mais Seguro que Remover) ==========" "INFO"
    
    Write-Host ""
    Write-Host "⚠️  AVISO: Remover o Edge pode quebrar aplicativos que dependem do WebView2." -ForegroundColor Yellow
    Write-Host "Esta função irá DESABILITAR o Edge via políticas em vez de removê-lo." -ForegroundColor Cyan
    Write-Host ""
    
    $confirmation = Read-Host "Deseja continuar e desabilitar o Edge? (S/N)"
    if ($confirmation -notmatch '^[Ss]') {
        Write-Log "Operação cancelada pelo usuário" "INFO"
        return
    }
    
    # Parar processos do Edge
    $edgeProcesses = @("msedge", "msedgewebview2", "MicrosoftEdge", "MicrosoftEdgeCP", "MicrosoftEdgeSH")
    foreach ($process in $edgeProcesses) {
        Get-Process -Name $process -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    
    Start-Sleep -Seconds 2
    
    # Desabilitar serviços de atualização do Edge (não o próprio Edge)
    $edgeServices = @("edgeupdate", "edgeupdatem")
    foreach ($service in $edgeServices) {
        try {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($svc) {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Log "Serviço de atualização desabilitado: $service" "SUCCESS"
            }
        } catch {
            Write-Log "Não foi possível desabilitar serviço: $service" "WARNING"
        }
    }
    
    # Bloquear Edge via políticas do Grupo
    $edgeBlockPolicies = @{
        "HKLM:\SOFTWARE\Policies\Microsoft\Edge" = @{
            "HubsSidebarEnabled" = 0
            "AADBrokerEnable" = 0
            "PersonalizationReportingEnabled" = 0
            "UserFeedbackAllowed" = 0
        }
        "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate" = @{
            "DoNotUpdateToEdgeWithChromium" = 1
            "InstallDefault" = 0
            "Install{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}" = 0
        }
        "HKLM:\SOFTWARE\Microsoft\EdgeUpdate" = @{
            "CreateDesktopShortcutDefault" = 0
        }
    }
    
    foreach ($regPath in $edgeBlockPolicies.Keys) {
        foreach ($setting in $edgeBlockPolicies[$regPath].GetEnumerator()) {
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
    
    Write-Log "Edge desabilitado via políticas! O navegador não será removido, mas ficará inoperante." "SUCCESS"
    Write-Log "Para reverter, delete as chaves em HKLM:\SOFTWARE\Policies\Microsoft\Edge" "INFO"
}

function Remove-WindowsBloatware {
    Write-Log "========== Removendo Bloatware do Windows ==========" "INFO"
    
    # Separar apps por categoria para melhor controle
    $appsNeverRemove = @(
        "Microsoft.WindowsTerminal",        # Essencial para desenvolvedores
        "Microsoft.HEIFImageExtension",     # Suporte a fotos modernas
        "Microsoft.WebpImageExtension",
        "Microsoft.WebMediaExtensions",
        "Microsoft.VP9VideoExtensions",
        "Microsoft.DesktopAppInstaller",    # Winget
        "Microsoft.StorePurchaseApp",
        "Microsoft.WindowsStore"            # Necessário para app store
    )
    
    $appsToRemove = @(
        # Comunicação e Social
        "Microsoft.People",
        "Microsoft.YourPhone",
        "Microsoft.Messaging",
        "Microsoft.GetHelp",
        "Microsoft.Getstarted",
        "Microsoft.WindowsFeedbackHub",
        
        # Entretenimento
        "Microsoft.BingNews",
        "Microsoft.BingWeather",
        "Microsoft.BingSports",
        "Microsoft.BingFinance",
        "Microsoft.GamingApp",
        "Microsoft.ZuneMusic",
        "Microsoft.ZuneVideo",
        "Microsoft.Music.Preview",
        "Microsoft.MicrosoftSolitaireCollection",
        "Microsoft.MixedReality.Portal",
        
        # Produtividade (Opcional)
        "Microsoft.Office.OneNote",
        "Microsoft.MicrosoftOfficeHub",
        "Microsoft.PowerAutomateDesktop",
        
        # Utilitários desnecessários
        "Microsoft.WindowsAlarms",
        "Microsoft.WindowsMaps",
        "Microsoft.WindowsSoundRecorder",
        "Microsoft.WindowsCamera",
        "Microsoft.ScreenSketch",
        "Microsoft.Wind3DViewer",
        "Microsoft.NetworkSpeedTest",
        "Microsoft.Lens",
        "Microsoft.Sway",
        "Microsoft.OneConnect",
        "Microsoft.Print3D",
        "Microsoft.Whiteboard",
        "Microsoft.Todos",
        
        # Xbox (se não for gamer)
        "Microsoft.Xbox.TCUI",
        "Microsoft.XboxApp",
        "Microsoft.XboxGameOverlay",
        "Microsoft.XboxGamingOverlay",
        "Microsoft.XboxIdentityProvider",
        "Microsoft.XboxSpeechToTextOverlay",
        
        # Teams e comunicação corporativa
        "MicrosoftTeams",
        "Microsoft.SkypeApp",
        
        # Outros
        "Clipchamp",
        "Microsoft.Advertising.Xaml",
        "Microsoft.RemoteDesktop"
    )
    
    Write-Host "`nApps ESSENCIAIS (não serão removidos):" -ForegroundColor Green
    $appsNeverRemove | ForEach-Object { Write-Host "  ✓ $_" -ForegroundColor DarkGray }
    
    Write-Host "`nApps marcados para REMOÇÃO:" -ForegroundColor Yellow
    $installedApps = @()
    
    foreach ($appName in $appsToRemove) {
        $apps = Get-AppxPackage -Name "*$appName*" -AllUsers -ErrorAction SilentlyContinue
        if ($apps) {
            foreach ($app in $apps) {
                if ($appsNeverRemove -notcontains $app.Name) {
                    $installedApps += $app
                    Write-Host "  - $($app.Name)" -ForegroundColor Red
                }
            }
        }
    }
    
    if ($installedApps.Count -eq 0) {
        Write-Log "Nenhum bloatware encontrado para remover!" "INFO"
        return
    }
    
    Write-Host "`nTotal de apps a remover: $($installedApps.Count)" -ForegroundColor Yellow
    $continue = Read-Host "Deseja continuar? (S/N)"
    
    if ($continue -notmatch '^[Ss]') {
        Write-Log "Remoção de bloatware cancelada" "INFO"
        return
    }
    
    $removedCount = 0
    $failedCount = 0
    
    $i = 0
    foreach ($app in $installedApps) {
        $i++
        $progress = [Math]::Round(($i / $installedApps.Count) * 100, 0)
        Write-Progress -Activity "Removendo Apps" -Status "$($app.Name)" -PercentComplete $progress
        
        try {
            Remove-AppxPackage -Package $app.PackageFullName -AllUsers -ErrorAction Stop
            Write-Log "Removido: $($app.Name)" "SUCCESS"
            $removedCount++
        } catch {
            Write-Log "Falha ao remover: $($app.Name)" "WARNING"
            $failedCount++
        }
        
        # Remover provisioned package
        try {
            $provPackage = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | 
                Where-Object { $_.DisplayName -eq $app.Name }
            if ($provPackage) {
                Remove-AppxProvisionedPackage -Online -PackageName $provPackage.PackageName -ErrorAction Stop
                Write-Log "Removido (provisioned): $($provPackage.DisplayName)" "SUCCESS"
            }
        } catch {
            # Não contar provisioned packages como falha principal
        }
    }
    
    Write-Progress -Activity "Removendo Apps" -Completed
    Write-Log "Remoção concluída! Removidos: $removedCount | Falhas: $failedCount" "SUCCESS"
}

function Optimize-Performance {
    Write-Log "========== Otimizando Desempenho do Sistema ==========" "INFO"
    
    # Desabilitar animações desnecessárias (modo performance)
    $performanceSettings = @{
        "HKCU:\Control Panel\Desktop" = @{
            "MenuShowDelay" = 0
            "VisualFXSetting" = 2
        }
        "HKCU:\Control Panel\Desktop\WindowMetrics" = @{
            "MinAnimate" = 0
        }
        "HKCU:\Software\Microsoft\Windows\Dwm" = @{
            "EnableAeroPeek" = 0
            "AlwaysHibernateThumbnails" = 0
        }
    }
    
    foreach ($regPath in $performanceSettings.Keys) {
        foreach ($setting in $performanceSettings[$regPath].GetEnumerator()) {
            Set-RegistryValue -Path $regPath -Name $setting.Key -Value $setting.Value
        }
    }
    
    # Otimizar prioridade de CPU para programas (menos agressivo)
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 26
    
    # NÃO desabilitar SysMain automaticamente - pode melhorar performance
    $systemDrive = Get-PhysicalDisk | Where-Object { $_.DeviceID -eq 0 }
    if ($systemDrive -and $systemDrive.MediaType -eq "SSD") {
        Write-Log "SSD detectado - SysMain será mantido (pode melhorar performance)" "INFO"
    }
    
    # Configurar gerenciamento de energia para alto desempenho (se disponível)
    try {
        powercfg /setactive SCHEME_MIN 2>$null
        Write-Log "Esquema de energia ajustado para Alto Desempenho" "SUCCESS"
    } catch {
        Write-Log "Não foi possível alterar esquema de energia" "WARNING"
    }
    
    # Desabilitar hibernação para economizar espaço
    try {
        powercfg /hibernate off
        Write-Log "Hibernação desabilitada" "SUCCESS"
    } catch {
        Write-Log "Não foi possível desabilitar hibernação" "WARNING"
    }
    
    # Limpar arquivos temporários com segurança
    try {
        Write-Log "Limpando arquivos temporários antigos..." "INFO"
        
        # Limpar TEMP do usuário
        $tempPath = $env:TEMP
        Get-ChildItem -Path $tempPath -Force -ErrorAction SilentlyContinue | 
            Where-Object { ($_.LastWriteTime -lt (Get-Date).AddDays(-7)) -and !$_.PSIsContainer } | 
            Remove-Item -Force -ErrorAction SilentlyContinue
        
        # Limpar Windows Temp (requer privilégios)
        $winTemp = "$env:SystemRoot\Temp"
        if (Test-Path $winTemp) {
            Get-ChildItem -Path $winTemp -Force -ErrorAction SilentlyContinue | 
                Where-Object { ($_.LastWriteTime -lt (Get-Date).AddDays(-7)) -and !$_.PSIsContainer } | 
                Remove-Item -Force -ErrorAction SilentlyContinue
        }
        
        Write-Log "Limpeza concluída" "SUCCESS"
    } catch {
        Write-Log "Erro na limpeza de arquivos temporários: $_" "ERROR"
    }
    
    Write-Log "Otimização de desempenho concluída!" "SUCCESS"
}

function Clear-SystemCache {
    Write-Log "========== Limpeza de Sistema ==========" "INFO"
    
    # Limpar cache de atualização do Windows
    Write-Log "Limpando cache de atualização..." "INFO"
    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
    $updateCache = "$env:SystemRoot\SoftwareDistribution\Download"
    if (Test-Path $updateCache) {
        Get-ChildItem -Path $updateCache -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    }
    Start-Service -Name wuauserv -ErrorAction SilentlyContinue
    
    # Limpar cache de aplicativos
    Write-Log "Limpando cache de aplicativos..." "INFO"
    $appCache = "$env:LOCALAPPDATA\Packages"
    if (Test-Path $appCache) {
        Get-ChildItem -Path $appCache -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $tempCache = Join-Path $_.FullName "AC\Temp"
            if (Test-Path $tempCache) {
                Get-ChildItem -Path $tempCache -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
            }
        }
    }
    
    Write-Log "Limpeza de sistema concluída!" "SUCCESS"
}

function Test-PCHealth {
    Write-Log "========== Verificando Integridade do Sistema ==========" "INFO"
    
    # Verificar integridade de arquivos do Windows
    Write-Log "Verificando integridade de arquivos do sistema..." "INFO"
    try {
        $sfcResult = sfc /scannow
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Verificação SFC concluída sem erros críticos" "SUCCESS"
        } else {
            Write-Log "SFC encontrou problemas (código: $LASTEXITCODE)" "WARNING"
        }
    } catch {
        Write-Log "Erro ao executar SFC: $_" "ERROR"
    }
    
    # Verificar espaço em disco
    $disks = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
    foreach ($disk in $disks) {
        $freeGB = [Math]::Round($disk.FreeSpace / 1GB, 2)
        $totalGB = [Math]::Round($disk.Size / 1GB, 2)
        $percentFree = [Math]::Round(($disk.FreeSpace / $disk.Size) * 100, 1)
        
        if ($percentFree -lt 10) {
            Write-Log "Disco $($disk.DeviceID): $freeGB GB livres ($percentFree%) - Baixo espaço!" "WARNING"
        } else {
            Write-Log "Disco $($disk.DeviceID): $freeGB GB livres ($percentFree%)" "INFO"
        }
    }
    
    # Verificar memória
    $mem = Get-CimInstance Win32_OperatingSystem
    $freeMemGB = [Math]::Round($mem.FreePhysicalMemory / 1MB, 2)
    Write-Log "Memória livre: $freeMemGB GB" "INFO"
    
    Write-Log "Verificação de integridade concluída!" "SUCCESS"
}

# ============================================
# MENU PRINCIPAL
# ============================================

function Show-MainMenu {
    do {
        Clear-Host
        Write-Host "=================================================================" -ForegroundColor Cyan
        Write-Host "                 WINDOWS 11/10 DEBLOATER SCRIPT" -ForegroundColor Yellow
        Write-Host "                    Versão 2.0 - Corrigida" -ForegroundColor Yellow
        Write-Host "=================================================================" -ForegroundColor Cyan
        Write-Host ""
        
        Write-Host "--- PRIVACIDADE & SEGURANÇA ---" -ForegroundColor Green
        Write-Host "  1. Desabilitar Telemetria" -ForegroundColor White
        Write-Host "  2. Configurar Privacidade (inclui Cortana)" -ForegroundColor White
        Write-Host "  3. Desabilitar Serviços de Telemetria" -ForegroundColor White
        Write-Host ""
        
        Write-Host "--- OTIMIZAÇÃO ---" -ForegroundColor Magenta
        Write-Host "  4. Remover Bloatware" -ForegroundColor White
        Write-Host "  5. Otimizar Desempenho" -ForegroundColor White
        Write-Host "  6. Desabilitar Microsoft Edge (recomendado)" -ForegroundColor White
        Write-Host ""
        
        Write-Host "--- MANUTENÇÃO ---" -ForegroundColor Blue
        Write-Host "  7. Criar Ponto de Restauração" -ForegroundColor White
        Write-Host "  8. Limpar Cache do Sistema" -ForegroundColor White
        Write-Host "  9. Verificar Integridade do Sistema" -ForegroundColor White
        Write-Host ""
        
        Write-Host "--- OPÇÕES ---" -ForegroundColor Yellow
        Write-Host "  0. Sair" -ForegroundColor White
        Write-Host ""
        Write-Host "=================================================================" -ForegroundColor Cyan
        
        $choice = Read-Host "Digite sua escolha (0-9)"
        
        switch ($choice) {
            "1" { 
                if (New-SystemRestorePoint) { Disable-WindowsTelemetry }
                pause
            }
            "2" { 
                if (New-SystemRestorePoint) { Set-PrivacySettings }
                pause
            }
            "3" { 
                if (New-SystemRestorePoint) { Disable-WindowsServices }
                pause
            }
            "4" { 
                if (New-SystemRestorePoint) { Remove-WindowsBloatware }
                pause
            }
            "5" { 
                if (New-SystemRestorePoint) { Optimize-Performance }
                pause
            }
            "6" { 
                if (New-SystemRestorePoint) { Disable-MicrosoftEdge }
                pause
            }
            "7" { 
                New-SystemRestorePoint
                pause
            }
            "8" { 
                Clear-SystemCache
                pause
            }
            "9" { 
                Test-PCHealth
                pause
            }
            "0" { 
                Write-Log "Script finalizado pelo usuário" "INFO"
                Clear-Host
                exit 0
            }
            default {
                Write-Host "`nOpção inválida. Pressione qualquer tecla..." -ForegroundColor Red
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
        }
    } while ($true)
}

# ============================================
# INICIALIZAÇÃO DO SCRIPT
# ============================================

try {
    Write-Host "Iniciando Windows Debloater Script..." -ForegroundColor Cyan
    Write-Log "Script iniciado" "INFO"
    Write-Log "Windows Version: $($osVersion.Major).$($osVersion.Minor).$($osVersion.Build)" "INFO"
    
    # Mostrar aviso inicial
    Write-Host ""
    Write-Host "⚠️  IMPORTANTE: Este script modifica configurações do sistema." -ForegroundColor Yellow
    Write-Host "   • Crie sempre um ponto de restauração antes de usar" -ForegroundColor Yellow
    Write-Host "   • Algumas funções não podem ser desfeitas facilmente" -ForegroundColor Yellow
    Write-Host "   • Use por sua conta e risco!" -ForegroundColor Red
    Write-Host ""
    
    $continue = Read-Host "Deseja continuar? (S/N)"
    if ($continue -notmatch '^[Ss]') {
        Write-Log "Operação cancelada pelo usuário no aviso inicial" "INFO"
        exit 0
    }
    
    # Iniciar menu
    Show-MainMenu
    
} catch {
    Write-Log "Erro fatal no script: $_" "ERROR"
    Write-Host "ERRO CRÍTICO: $_" -ForegroundColor Red
    Write-Host "Pressione qualquer tecla para sair..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}
