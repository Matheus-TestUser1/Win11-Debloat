# Ensure the script is running as an Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    [System.Windows.Forms.MessageBox]::Show(
        "Você não está executando este script como administrador! Execute-o como administrador para continuar.", 
        "Erro de Permissão", 
        [System.Windows.Forms.MessageBoxButtons]::OK, 
        [System.Windows.Forms.MessageBoxIcon]::Error
    )
    Exit
}

# Function to log messages with timestamp
function Log($message) {
    $timeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "$timeStamp - $message"
}

# Function to log errors
function Error($message) {
    Write-Host "ERRO: $message" -ForegroundColor Red
}

# Função melhorada para criar ponto de restauração
function New-RestorePoint {
    param(
        [string]$Description = "Ponto de restauração criado por script PowerShell"
    )
    
    # Verificar se está executando como administrador
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Error "Este script precisa ser executado como Administrador!"
        return $false
    }
    
    try {
        # Verificar se a proteção do sistema está habilitada
        $systemProtection = Get-WmiObject -Class Win32_SystemRestore -ErrorAction SilentlyContinue
        if ($null -eq $systemProtection) {
            Write-Warning "Proteção do sistema não está habilitada. Tentando habilitar..."
            try {
                Enable-ComputerRestore -Drive "C:\" -Confirm:$false
                Write-Host "Proteção do sistema habilitada para a unidade C:" -ForegroundColor Green
            } catch {
                Write-Error "Não foi possível habilitar a proteção do sistema: $_"
                return $false
            }
        }
        
        # Verificar pontos de restauração existentes
        $existingPoints = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
        $todayPoints = $existingPoints | Where-Object { $_.CreationTime.Date -eq (Get-Date).Date }
        
        if ($todayPoints.Count -gt 0) {
            Write-Host "Já existe(m) $($todayPoints.Count) ponto(s) de restauração criado(s) hoje."
            Write-Host "Deseja criar outro ponto de restauração? (S/N): " -NoNewline
            $choice = Read-Host
            if ($choice -notmatch '^[SsYy]') {
                Write-Host "Continuando sem criar um novo ponto de restauração..." -ForegroundColor Yellow
                return $true
            }
        }
        
        # Criar o ponto de restauração
        Write-Host "Criando ponto de restauração..." -ForegroundColor Cyan
        Write-Host "Isso pode levar alguns minutos. Aguarde..." -ForegroundColor Yellow
        
        Checkpoint-Computer -Description $Description -RestorePointType MODIFY_SETTINGS -Verbose
        
        # Verificar se foi criado com sucesso
        Start-Sleep -Seconds 5
        $newPoints = Get-ComputerRestorePoint | Sort-Object CreationTime -Descending | Select-Object -First 1
        
        if ($newPoints -and $newPoints.CreationTime -gt (Get-Date).AddMinutes(-10)) {
            Write-Host "Ponto de restauração criado com sucesso!" -ForegroundColor Green
            Write-Host "Data/Hora: $($newPoints.CreationTime)" -ForegroundColor Green
            Write-Host "Descrição: $($newPoints.Description)" -ForegroundColor Green
            return $true
        } else {
            Write-Warning "Não foi possível verificar se o ponto de restauração foi criado."
            return $false
        }
        
    } catch {
        Write-Error "Erro ao criar o ponto de restauração: $($_.Exception.Message)"
        
        # Diagnósticos adicionais
        Write-Host "`nInformações de diagnóstico:" -ForegroundColor Yellow
        Write-Host "- Versão do Windows: $((Get-WmiObject Win32_OperatingSystem).Caption)"
        Write-Host "- Espaço livre em C:: $([math]::Round((Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace/1GB, 2)) GB"
        
        return $false
    }
}

# Função auxiliar para verificar configurações
function Test-RestorePointConfiguration {
    Write-Host "Verificando configurações do sistema..." -ForegroundColor Cyan
    
    # Verificar se é administrador
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    Write-Host "Executando como Administrador: $isAdmin" -ForegroundColor $(if($isAdmin){"Green"}else{"Red"})
    
    # Verificar proteção do sistema
    try {
        $protection = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
        Write-Host "Proteção do sistema ativa: $($null -ne $protection)" -ForegroundColor $(if($null -ne $protection){"Green"}else{"Red"})
    } catch {
        Write-Host "Proteção do sistema ativa: Erro ao verificar" -ForegroundColor Red
    }
    
    # Verificar espaço em disco
    $freeSpace = [math]::Round((Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace/1GB, 2)
    Write-Host "Espaço livre em C:: $freeSpace GB" -ForegroundColor $(if($freeSpace -gt 2){"Green"}else{"Yellow"})
    
    # Verificar política de execução
    $executionPolicy = Get-ExecutionPolicy
    Write-Host "Política de execução: $executionPolicy" -ForegroundColor $(if($executionPolicy -ne "Restricted"){"Green"}else{"Yellow"})
}

# Exemplo de uso:
# Test-RestorePointConfiguration
# New-RestorePoint -Description "Backup antes de mudanças importantes"

# Function to disable telemetry
function Disable-Telemetry {
    Log "Disabling Telemetry..."

    $registrySettings = @{
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection\AllowTelemetry" = 0
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry" = 0
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection\AllowTelemetry" = 0
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\AITEnable" = 0
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\DisableUAR" = 1
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\DisableInventory" = 1
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\DisablePCA" = 1
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\DisableMonitoring" = 1
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\DisableProblemReports" = 1
        "HKLM:\SOFTWARE\Policies\Microsoft\EdgeWebView\AllowTelemetry" = 0
    }

    foreach ($setting in $registrySettings.GetEnumerator()) {
        $key = $setting.Key
        $value = $setting.Value
        try {
            if (-not (Test-Path $key)) {
                New-Item -Path $key -Force | Out-Null
            }
            Set-ItemProperty -Path $key -Name "(Default)" -Value $value -Type DWORD -Force
            Log "Configuração atualizada com sucesso: $key"
        } catch {
            Error "Ocorreu um erro ao tentar modificar o registro: $_"
        }
    }

    Log "Telemetry has been disabled!"
}

# Function to disable privacy settings
function Disable-PrivacySettings {
    Log "Disabling Activity History..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0

    Log "Disabling Location Tracking..."
    if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0

    Log "Disabling automatic Maps updates..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0

    Log "Disabling Feedback..."
    if (-not (Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null

    Log "Disabling Tailored Experiences..."
    if (-not (Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1

    Log "Disabling Advertising ID..."
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1

    Log "Disabling Error reporting..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null

    Log "Stopping and disabling Diagnostics Tracking Service..."
    Stop-Service "DiagTrack" -WarningAction SilentlyContinue
    Set-Service "DiagTrack" -StartupType Disabled

    Log "Stopping and disabling WAP Push Service..."
    Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
    Set-Service "dmwappushservice" -StartupType Disabled

    Log "Enabling F8 boot menu options..."
    bcdedit /set `{current`} bootmenupolicy Legacy | Out-Null

    Log "Disabling Remote Assistance..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
}

# Function to disable specific services
function Disable-Services {
    Log "Disabling specified services..."

    $Services = @(
        "*xbox*", "XboxNetApiSvc", "WSearch", "MixedRealityOpenXRSvc", "WerSvc",
        "SCPolicySvc", "ScDeviceEnum", "SCardSvr", "RetailDemo", "RemoteRegistry",
        "MapsBroker", "TrkWks", "WdiSystemHost", "WdiServiceHost", "DPS", "diagsvc"
    )

    foreach ($Service in $Services) {
        if (-not $Service.StartsWith("#")) {
            Get-Service -Name $Service -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled
            if ((Get-Service -Name $Service -ErrorAction SilentlyContinue).Status -eq "Running") {
                Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue | Out-Null
                Log "Trying to disable $($Service.DisplayName)"
            }
        }
    }

    Log "Specified services have been disabled."

    foreach ($Service in $Services) {
        if ((Get-Service -Name $Service -ErrorAction SilentlyContinue).Status -eq "Running") {
            Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue | Out-Null
            Log "Stopped $($Service.DisplayName) service."
        }
    }

    Log "All disabled services have been stopped."
}

# Function to remove bloatware
function Remove-Bloatware {
    Log "Removendo bloatware, aguarde..."

    $BloatwareList = @(
        "Microsoft.BingNews", "Microsoft.BingWeather", "Microsoft.GetHelp", "Microsoft.Getstarted",
        "Microsoft.MicrosoftOfficeHub", "Microsoft.MicrosoftSolitaireCollection", "Microsoft.PowerAutomateDesktop",
        "Microsoft.People", "Microsoft.Todos", "Microsoft.WindowsAlarms", "microsoft.windowscommunicationsapps",
        "Microsoft.WindowsFeedbackHub", "Microsoft.WindowsMaps", "Microsoft.WindowsSoundRecorder", "Microsoft.ZuneMusic",
        "Microsoft.ZuneVideo", "MicrosoftTeams", "ClipChamp.ClipChamp"
    )

    $removedCount = 0

    foreach ($Bloat in $BloatwareList) {
        Log "Tentando remover $Bloat"
        try {
            $app = Get-AppxPackage -Name $Bloat -ErrorAction SilentlyContinue
            if ($null -ne $app) {
                $app | Remove-AppxPackage -ErrorAction Stop | Out-Null
                $removedCount++
                Log "$Bloat foi removido com sucesso"
            } else {
                Log "$Bloat não está presente."
            }

            $provisionedApp = Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat -ErrorAction SilentlyContinue
            if ($null -ne $provisionedApp) {
                $provisionedApp | Remove-AppxProvisionedPackage -Online -ErrorAction Stop
                Log "$Bloat (provisioned) foi removido com sucesso"
            } else {
                Log "$Bloat (provisioned) não está presente."
            }
        } catch {
            Error "Falha ao remover $Bloat, exceção: $($_.Exception.Message)"
        }
    }

    if ($removedCount -gt 0) {
        Log "Total de $removedCount aplicativos de bloatware removidos."
    } else {
        Log "Nenhum aplicativo de bloatware encontrado para remoção."
    }

    Log "Bloatware foi removido."
}

# Function to disable background app access
function Disable-BackgroundAppAccess {
    Log "Disabling Background application access..."
    Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" | ForEach-Object {
        Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 1
        Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 1
    }
    if (-not (Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Type DWord -Value 1
    Log "Disabled Background application access"
}

# Function to disable Bing search in start menu
function Disable-BingSearchInStartMenu {
    Log "Disabling Bing Search in Start Menu..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
    Log "Stopping and disabling Windows Search indexing service..."
    Stop-Service "WSearch" -WarningAction SilentlyContinue
    Set-Service "WSearch" -StartupType Disabled
}

# Function to hide taskbar search
function Hide-Search {
    Log "Hiding Taskbar Search icon / box..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
}

# Function to disable Cortana
function Disable-Cortana {    
    Log "Disabling Cortana..."
    if (-not (Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
    if (-not (Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
    if (-not (Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
    Stop-Process -Name SearchApp -Force
    Stop-Process -Name explorer -Force
    Log "Disabled Cortana"
}

# Function to update tweaks
function Update-Tweaks {
    $scheduledTasksToDisable = @(
        "\Microsoft\Windows\ApplicationData\CleanupTemporaryState",
        "\Microsoft\Windows\ApplicationData\DsSvcCleanup",
        "\Microsoft\Windows\AppxDeploymentClient\Pre-stagedappcleanup",
        "\Microsoft\Windows\Autochk\Proxy",
        "\Microsoft\Windows\BrokerInfrastructure\BgTaskRegistrationMaintenanceTask",
        "\Microsoft\Windows\capabilityaccessmanager\maintenancetasks",
        "\Microsoft\Windows\Chkdsk\ProactiveScan",
        "\Microsoft\Windows\Chkdsk\SyspartRepair",
        "\Microsoft\Windows\Clip\LicenseValidation",
        "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask",
        "\Microsoft\Windows\CustomerExperienceImprovementProgram\Consolidator",
        "\Microsoft\Windows\CustomerExperienceImprovementProgram\UsbCeip",
        "\Microsoft\Windows\Defrag\ScheduledDefrag",
        "\Microsoft\Windows\DeviceInformation\Device",
        "\Microsoft\Windows\DeviceInformation\DeviceUser",
        "\Microsoft\Windows\DeviceSetup\MetadataRefresh",
        "\Microsoft\Windows\ExploitGuard\ExploitGuardMDMpolicyRefresh",
        "\Microsoft\Windows\Feedback\Siuf\DmClient",
        "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
        "\Microsoft\Windows\FileHistory\FileHistory*",
        "\Microsoft\Windows\Location\Notifications",
        "\Microsoft\Windows\Location\WindowsActionDialog",
        "\Microsoft\Windows\Maps\MapsToastTask",
        "\Microsoft\Windows\Maps\MapsUpdateTask",
        "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents",
        "\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic",
        "\Microsoft\Windows\MUI\LPRemove",
        "\Microsoft\Windows\Multimedia\SystemSoundsService",
        "\Microsoft\Windows\OfflineFiles\BackgroundSynchronization",
        "\Microsoft\Microsoft\Windows\OfflineFiles\LogonSynchronization",
        "\Microsoft\Windows\Printing\EduPrintProv",
        "\Microsoft\Windows\Printing\PrinterCleanupTask",
        "\Microsoft\Windows\PushToInstall\LoginCheck",
        "\Microsoft\Windows\PushToInstall\Registration",
        "\Microsoft\Windows\RetailDemo\CleanupOfflineContent",
        "\Microsoft\Windows\Servicing\StartComponentCleanup",
        "\Microsoft\Windows\Setup\SetupCleanupTask",
        "\Microsoft\Windows\SharedPC\AccountCleanup",
        "\Microsoft\Windows\UNP\RunUpdateNotificationMgr",
        "\Microsoft\Windows\WindowsErrorReporting\QueueReporting",
        "\Microsoft\XblGameSave\XblGameSaveTask"
    )

    foreach ($task in $scheduledTasksToDisable) {
        Disable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue | Out-Null
        Log "Task `"$task`" was disabled"
    }

    $registryKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling",
        "HKCU:\System\GameConfigStore",
        "HKCU:\Control Panel\Desktop",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
    )

    foreach ($key in $registryKeys) {
        if (-not (Test-Path $key)) {
            New-Item -Path $key -Force -ErrorAction SilentlyContinue
        }
    }

    $registryProperties = @(
        @{
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching';
            Name = 'SearchOrderConfig';
            Value = 0;
            Type = 'DWord';
        },
        @{
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power';
            Name = 'HiberbootEnabled';
            Value = 0;
            Type = 'DWord';
        },
        @{
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling';
            Name = 'PowerThrottlingOff';
            Value = 1;
            Type = 'DWord';
        },
        @{
            Key = 'HKCU:\System\GameConfigStore';
            Name = 'GameDVR_Enabled';
            Value = 0;
            Type = 'DWord';
        },
        @{
            Key = 'HKCU:\System\GameConfigStore';
            Name = 'GameDVR_FSEBehaviorMode';
            Value = 2;
            Type = 'DWord';
        },
        @{
            Key = 'HKCU:\System\GameConfigStore';
            Name = 'Win32_AutoGameModeDefaultProfile';
            Value = ([byte[]](0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)) -as [byte[]];
            Type = 'Binary';
        }
    )

    foreach ($prop in $registryProperties) {
        New-ItemProperty -LiteralPath $prop.Key -Name $prop.Name -Value $prop.Value -PropertyType $prop.Type -Force -ea SilentlyContinue
    }

    Stop-Process -Name explorer
    Log "Tweaks are done!"
}

# Function to remove Microsoft Edge
# Função melhorada para remover Microsoft Edge
function Remove-Edge {
    param(
        [switch]$Force,
        [switch]$KeepWebView2
    )
    
    # Verificar se está executando como administrador
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Error "Este script precisa ser executado como Administrador!"
        return $false
    }
    
    Write-Host "Iniciando remoção do Microsoft Edge..." -ForegroundColor Cyan
    $errorOccurred = $false
    
    try {
        # 1. Parar processos do Edge
        Write-Host "Encerrando processos do Microsoft Edge..." -ForegroundColor Yellow
        $edgeProcesses = @("msedge", "msedgewebview2", "MicrosoftEdgeUpdate")
        foreach ($process in $edgeProcesses) {
            Get-Process -Name $process -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        }
        Start-Sleep -Seconds 3
        
        # 2. Desabilitar serviços relacionados ao Edge
        Write-Host "Desabilitando serviços do Microsoft Edge..." -ForegroundColor Yellow
        $edgeServices = @("edgeupdate", "edgeupdatem", "MicrosoftEdgeElevationService")
        foreach ($service in $edgeServices) {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($svc) {
                try {
                    Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                    Set-Service -Name $service -StartupType Disabled -ErrorAction Stop
                    Write-Host "Serviço $service desabilitado." -ForegroundColor Green
                } catch {
                    Write-Warning "Falha ao desabilitar serviço $service`: $_"
                    $errorOccurred = $true
                }
            }
        }
        
        # 3. Remover Edge Legacy (UWP) - Windows 10 versões antigas
        Write-Host "Removendo Microsoft Edge Legacy..." -ForegroundColor Yellow
        $edgeLegacyPackages = Get-AppxPackage -Name "*Microsoft.MicrosoftEdge*" -AllUsers -ErrorAction SilentlyContinue
        if ($edgeLegacyPackages) {
            foreach ($package in $edgeLegacyPackages) {
                try {
                    Remove-AppxPackage -Package $package.PackageFullName -AllUsers -ErrorAction Stop
                    Write-Host "Edge Legacy removido: $($package.Name)" -ForegroundColor Green
                } catch {
                    Write-Warning "Falha ao remover Edge Legacy: $_"
                    $errorOccurred = $true
                }
            }
        }
        
        # Remover provisioned packages
        $provisionedPackages = Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*Microsoft.MicrosoftEdge*"
        if ($provisionedPackages) {
            foreach ($package in $provisionedPackages) {
                try {
                    Remove-AppxProvisionedPackage -Online -PackageName $package.PackageName -ErrorAction Stop
                    Write-Host "Provisioned package removido: $($package.DisplayName)" -ForegroundColor Green
                } catch {
                    Write-Warning "Falha ao remover provisioned package: $_"
                }
            }
        }
        
        # 4. Remover Edge Chromium moderno
        Write-Host "Removendo Microsoft Edge Chromium..." -ForegroundColor Yellow
        
        # Procurar instalações do Edge Chromium
        $edgePaths = @(
            "${env:ProgramFiles(x86)}\Microsoft\Edge\Application",
            "${env:ProgramFiles}\Microsoft\Edge\Application",
            "${env:LOCALAPPDATA}\Microsoft\Edge\Application"
        )
        
        foreach ($path in $edgePaths) {
            if (Test-Path $path) {
                # Procurar pelo setup.exe para desinstalação
                $setupPath = Get-ChildItem -Path $path -Recurse -Name "setup.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($setupPath) {
                    $fullSetupPath = Join-Path $path $setupPath
                    Write-Host "Executando desinstalador do Edge: $fullSetupPath" -ForegroundColor Yellow
                    try {
                        # Tentar desinstalação silenciosa
                        $process = Start-Process -FilePath $fullSetupPath -ArgumentList "--uninstall", "--force-uninstall", "--system-level" -Wait -PassThru -WindowStyle Hidden
                        if ($process.ExitCode -eq 0) {
                            Write-Host "Edge Chromium removido com sucesso!" -ForegroundColor Green
                        } else {
                            Write-Warning "Desinstalador retornou código de erro: $($process.ExitCode)"
                            $errorOccurred = $true
                        }
                    } catch {
                        Write-Warning "Falha ao executar desinstalador: $_"
                        $errorOccurred = $true
                    }
                }
            }
        }
        
        # 5. Limpeza manual de arquivos (se necessário)
        if ($Force) {
            Write-Host "Executando limpeza forçada de arquivos..." -ForegroundColor Red
            $cleanupPaths = @(
                "${env:ProgramFiles(x86)}\Microsoft\Edge",
                "${env:ProgramFiles}\Microsoft\Edge",
                "${env:LOCALAPPDATA}\Microsoft\Edge",
                "${env:APPDATA}\Microsoft\Edge"
            )
            
            foreach ($path in $cleanupPaths) {
                if (Test-Path $path) {
                    try {
                        Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                        Write-Host "Removido: $path" -ForegroundColor Green
                    } catch {
                        Write-Warning "Não foi possível remover: $path - $_"
                    }
                }
            }
        }
        
        # 6. Remover atalhos
        Write-Host "Removendo atalhos do Microsoft Edge..." -ForegroundColor Yellow
        $shortcutPaths = @(
            "${env:PUBLIC}\Desktop\Microsoft Edge.lnk",
            "${env:APPDATA}\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk",
            "${env:ALLUSERSPROFILE}\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk"
        )
        
        foreach ($shortcut in $shortcutPaths) {
            if (Test-Path $shortcut) {
                try {
                    Remove-Item -Path $shortcut -Force -ErrorAction Stop
                    Write-Host "Atalho removido: $shortcut" -ForegroundColor Green
                } catch {
                    Write-Warning "Falha ao remover atalho: $_"
                }
            }
        }
        
        # 7. Limpeza do registro (cuidadosamente)
        Write-Host "Limpando entradas do registro..." -ForegroundColor Yellow
        $registryPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Edge",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Edge",
            "HKCU:\Software\Microsoft\Edge"
        )
        
        foreach ($regPath in $registryPaths) {
            if (Test-Path $regPath) {
                try {
                    Remove-Item -Path $regPath -Recurse -Force -ErrorAction Stop
                    Write-Host "Entrada do registro removida: $regPath" -ForegroundColor Green
                } catch {
                    Write-Warning "Falha ao remover entrada do registro: $_"
                }
            }
        }
        
        # 8. Verificar se o WebView2 deve ser mantido
        if (-not $KeepWebView2) {
            Write-Host "Removendo Microsoft Edge WebView2..." -ForegroundColor Yellow
            $webview2Path = "${env:ProgramFiles(x86)}\Microsoft\EdgeWebView\Application"
            if (Test-Path $webview2Path) {
                try {
                    Remove-Item -Path $webview2Path -Recurse -Force -ErrorAction Stop
                    Write-Host "WebView2 removido." -ForegroundColor Green
                } catch {
                    Write-Warning "Falha ao remover WebView2: $_"
                }
            }
        }
        
        # Verificação final
        Write-Host "`nVerificando remoção..." -ForegroundColor Cyan
        $edgeStillExists = $false
        
        # Verificar processos
        $runningEdge = Get-Process -Name "msedge" -ErrorAction SilentlyContinue
        if ($runningEdge) {
            Write-Warning "Edge ainda está em execução."
            $edgeStillExists = $true
        }
        
        # Verificar arquivos
        foreach ($path in $edgePaths) {
            if (Test-Path $path) {
                Write-Warning "Arquivos do Edge ainda existem em: $path"
                $edgeStillExists = $true
            }
        }
        
        if (-not $edgeStillExists -and -not $errorOccurred) {
            Write-Host "`nMicrosoft Edge foi removido com sucesso!" -ForegroundColor Green
            Write-Host "Recomenda-se reiniciar o computador para completar a remoção." -ForegroundColor Yellow
            return $true
        } else {
            Write-Warning "`nA remoção pode não ter sido completamente bem-sucedida."
            if ($edgeStillExists) {
                Write-Host "Considere usar o parâmetro -Force para limpeza mais agressiva." -ForegroundColor Yellow
            }
            return $false
        }
        
    } catch {
        Write-Error "Erro geral durante a remoção do Edge: $_"
        return $false
    }
}

# Função auxiliar para verificar o status do Edge
function Get-EdgeStatus {
    Write-Host "Verificando status do Microsoft Edge..." -ForegroundColor Cyan
    
    # Verificar processos em execução
    $edgeProcesses = Get-Process -Name "msedge" -ErrorAction SilentlyContinue
    Write-Host "Processos do Edge em execução: $($edgeProcesses.Count)" -ForegroundColor $(if($edgeProcesses.Count -eq 0){"Green"}else{"Red"})
    
    # Verificar serviços
    $edgeServices = @("edgeupdate", "edgeupdatem", "MicrosoftEdgeElevationService")
    $activeServices = 0
    foreach ($service in $edgeServices) {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") {
            $activeServices++
        }
    }
    Write-Host "Serviços ativos do Edge: $activeServices" -ForegroundColor $(if($activeServices -eq 0){"Green"}else{"Red"})
    
    # Verificar instalações
    $edgePaths = @(
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application",
        "${env:ProgramFiles}\Microsoft\Edge\Application"
    )
    
    $installationsFound = 0
    foreach ($path in $edgePaths) {
        if (Test-Path $path) {
            $installationsFound++
            Write-Host "Instalação encontrada em: $path" -ForegroundColor Red
        }
    }
    
    if ($installationsFound -eq 0) {
        Write-Host "Nenhuma instalação do Edge encontrada." -ForegroundColor Green
    }
}

# Exemplos de uso:
# Get-EdgeStatus
# Remove-Edge
# Remove-Edge -Force
# Remove-Edge -Force -KeepWebView2

# Function to install programs using Chocolatey
function Install-Programs {
    if (-not (Test-Path 'C:\ProgramData\chocolatey\bin\choco.exe')) {
        Write-Host "Chocolatey não está instalado. Instalando Chocolatey..."

        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

        if (-not (Test-Path 'C:\ProgramData\chocolatey\bin\choco.exe')) {
            Write-Host "A instalação do Chocolatey falhou. Verifique as configurações do PowerShell e a política de execução."
            return
        }
        Write-Host "Chocolatey foi instalado com sucesso!"
    }

    do {
        Clear-Host
        Write-Host "Escolha um programa para baixar:"
        Write-Host "1. 7-Zip           2. Google Chrome"
        Write-Host "3. WinRAR          4. Firefox"
        Write-Host "5. SimpleWall      6. OOSO10 (ANTISPY)"
        Write-Host "7. Adobe Acrobat Reader DC      8. Visual Studio Code"
        Write-Host "9. VLC Media Player             10. Spotify"
        Write-Host "11. Microsoft Office            12. Adobe Creative Cloud"
        Write-Host "13. Skype                        14. Zoom"
        Write-Host "15. GIMP                         16. Audacity"
        Write-Host "17. Discord                      18. Python"
        Write-Host "19. Git                          20. Notepad++"
        Write-Host "21. WinSCP                       22. Steam"
        Write-Host "23. Java Development Kit (JDK)   24. Node.js"
        Write-Host "25. Docker                       26. VirtualBox"
        Write-Host "0. Voltar"

        $choice = Read-Host "Digite o número da opção e pressione Enter"

        switch ($choice) {
            "1" { choco install 7zip -y }
            "2" { choco install googlechrome -y }
            "3" { choco install winrar -y }
            "4" { choco install firefox -y }
            "5" { choco install simplewall -y }
            "6" {
                $url = "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe"
                $userProfile = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::UserProfile)
                $downloadPath = Join-Path $userProfile "Downloads"
                $localPath = Join-Path $downloadPath "OOSU10.exe"
                try {
                    Invoke-WebRequest -Uri $url -OutFile $localPath -ErrorAction Stop
                    if (Test-Path $localPath) {
                        Write-Host "Arquivo baixado com sucesso em $localPath."
                        Start-Process -FilePath $localPath -Wait
                    } else {
                        Write-Host "Falha ao baixar o arquivo."
                    }
                } catch {
                    Write-Host "Erro ao baixar ou executar o arquivo: $_"
                }
            }
            "7" { choco install adobereader -y }
            "8" { choco install vscode -y }
            "9" { choco install vlc -y }
            "10" { choco install spotify -y }
            "11" { choco install microsoft-office-deploy -y }
            "12" { choco install adobe-creative-cloud -y }
            "13" { choco install skype -y }
            "14" { choco install zoom -y }
            "15" { choco install gimp -y }
            "16" { choco install audacity -y }
            "17" { choco install discord -y }
            "18" { choco install python -y }
            "19" { choco install git -y }
            "20" { choco install notepadplusplus -y }
            "21" { choco install winscp -y }
            "22" { choco install steam -y }
            "23" { choco install jdk8 -y }
            "24" { choco install nodejs -y }
            "25" { choco install docker-desktop -y }
            "26" { choco install virtualbox -y }
            "0" { return }
            default { Write-Host "Opção inválida. Tente novamente." }
        }

        Write-Host ""
        Write-Host "Pressione Enter para continuar..."
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    } while ($true)
}

# Function to clean temporary folders
function Clear-Temp {
    Write-Output "Limpando pastas temporárias..."
    Remove-Item -Path "$env:TEMP\*" -Force -Recurse
    Remove-Item -Path "$env:windir\Temp\*" -Force -Recurse
    Write-Output "Pastas temporárias limpas com sucesso."
}

# Function to check PC health
function Test-PCHealth {
    Write-Output "Verificando a saúde do PC..."
    chkdsk /f /r
    sfc /scannow
    Write-Output "Verificação de saúde concluída."
}

# Function to create a system restore point
function New-RestorePoint {
    Write-Output "Criando um ponto de restauração do sistema..."
    $null = Checkpoint-Computer -Description "Ponto de restauração criado manualmente"
    Write-Output "Ponto de restauração criado com sucesso."
}

# Function to restore resources using DISM
function Restore-Resources {
    Write-Output "Restaurando recursos com DISM..."
    Start-Process -FilePath "DISM" -ArgumentList "/Online", "/Cleanup-Image", "/RestoreHealth" -NoNewWindow -Wait
    Write-Output "Recursos restaurados com sucesso."
}

# Submenu Maintenance
function Show-MaintenanceMenu {
    do {
        Clear-Host
        Write-Output "Menu de Manutenção:"
        Write-Output "1. Limpar Temp"
        Write-Output "2. Verificar Saúde"
        Write-Output "3. Criar Ponto de Restauração"
        Write-Output "4. Restaurar Recursos"
        Write-Output "0. Voltar"

        $option = Read-Host "Opção"

        switch ($option) {
            '1' { Clear-Temp }
            '2' { Test-PCHealth }
            '3' { New-RestorePoint }
            '4' { Restore-Resources }
            '0' { break }
            default { Write-Output "Opção inválida." }
        }

        Write-Output ""
        Write-Output "Pressione Enter para continuar..."
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    } while ($option -ne '0')
}

# Main menu
do {
    Clear-Host
    Write-Host "Windows Debloater Script WIN11/10" -ForegroundColor Cyan
    Write-Host "`nEscolha uma opção:"
    Write-Host "1. Desabilitar Telemetria"
    Write-Host "2. Desabilitar Histórico de Atividades e Rastreamento de Localização"
    Write-Host "3. Remover Bloatware"
    Write-Host "4. Desabilitar Serviços Específicos"
    Write-Host "5. Desabilitar Cortana"
    Write-Host "6. Desabilitar Bing No Menu Iniciar"
    Write-Host "7. Conclusão"
    Write-Host "8. Desabilitar Acesso de Aplicativos em Segundo Plano"
    Write-Host "9. Ocultar Pesquisa"
    Write-Host "10. Remover Edge"
    Write-Host "11. Instalar Programas"
    Write-Host "12. Manutenção De Pc"
    Write-Host "0. Sair`n"

    $choice = Read-Host "Digite o número da opção e pressione Enter"

    switch ($choice) {
        "1" { Disable-Telemetry }
        "2" { Disable-PrivacySettings }
        "3" { Remove-Bloatware }
        "4" { Disable-Services }
        "5" { Disable-Cortana }
        "6" { Disable-BingSearchInStartMenu }
        "7" { Update-Tweaks }
        "8" { Disable-BackgroundAppAccess }
        "9" { Hide-Search }
        "10" { Remove-Edge }
        "11" { Install-Programs }   
        "12" { Show-MaintenanceMenu } 
        "0" { break }
        default { Write-Host "Escolha inválida, tente novamente." }
    }

    Read-Host "Pressione Enter para continuar..."

} while ($choice -ne "0")
