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
    # Configura a codificação para UTF-8
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8

    Log "Iniciando processo de desativação de serviços..."
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Log "Executando como: $currentUser em $timestamp"

    # Lista de serviços para desativar
    $Services = @(
        "*xbox*",          # Todos os serviços Xbox
        "XboxNetApiSvc",   # Serviço específico do Xbox
        "WSearch",         # Windows Search
        "MixedRealityOpenXRSvc",
        "WerSvc",         # Windows Error Reporting
        "SCPolicySvc",    # Smart Card
        "ScDeviceEnum",   # Smart Card Device Enumeration
        "SCardSvr",       # Smart Card
        "RetailDemo",     # Modo de demonstração
        "RemoteRegistry", # Registro remoto
        "MapsBroker",     # Serviço de mapas
        "TrkWks",        # Distributed Link Tracking
        "WdiSystemHost", # Diagnostic System Host
        "WdiServiceHost", # Diagnostic Service Host
        "DPS",           # Diagnostic Policy Service
        "diagsvc"        # Diagnostic Service
    )

    # Contador para estatísticas
    $stats = @{
        Processed = 0
        Disabled = 0
        Stopped = 0
        Failed = 0
        NotFound = 0
    }

    foreach ($ServicePattern in $Services) {
        try {
            # Pula comentários
            if ($ServicePattern.StartsWith("#")) {
                continue
            }

            # Obtém serviços correspondentes ao padrão
            $matchingServices = Get-Service -Name $ServicePattern -ErrorAction SilentlyContinue
            
            if ($null -eq $matchingServices) {
                $stats.NotFound++
                Log "Serviço não encontrado: $ServicePattern"
                continue
            }

            # Processa cada serviço encontrado
            foreach ($svc in $matchingServices) {
                $stats.Processed++
                
                try {
                    # Verifica status atual do serviço
                    $currentStatus = $svc.Status
                    $currentStartType = (Get-Service -Name $svc.Name).StartType

                    # Tenta desabilitar o serviço
                    Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction Stop
                    $stats.Disabled++
                    Log "Serviço desativado: $($svc.DisplayName)"

                    # Se o serviço estiver em execução, tenta pará-lo
                    if ($currentStatus -eq "Running") {
                        Stop-Service -Name $svc.Name -Force -ErrorAction Stop
                        $stats.Stopped++
                        Log "Serviço interrompido: $($svc.DisplayName)"
                    }
                }
                catch {
                    $stats.Failed++
                    Error "Falha ao processar $($svc.DisplayName): $($_.Exception.Message)"
                }
            }
        }
        catch {
            $stats.Failed++
            Error "Erro ao processar padrão $ServicePattern: $($_.Exception.Message)"
        }
    }

    # Relatório final
    Log "`n=== Resumo da Operação ==="
    Log "Total processado: $($stats.Processed)"
    Log "Serviços desativados: $($stats.Disabled)"
    Log "Serviços interrompidos: $($stats.Stopped)"
    Log "Não encontrados: $($stats.NotFound)"
    Log "Falhas: $($stats.Failed)"
    Log "Operação concluída em $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"
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
function Remove-Edge {
    Write-Output "Removing Microsoft Edge..."
    $errorOccurred = $false

    $edgeUpdateService = Get-Service -Name "edgeupdate" -ErrorAction SilentlyContinue
    if ($null -ne $edgeUpdateService) {
        try {
            Set-Service -Name "edgeupdate" -StartupType Disabled -ErrorAction Stop
            Write-Output "Serviço de atualização do Microsoft Edge desativado com sucesso."
        } catch {
            Write-Error "Falha ao desativar o serviço de atualização do Microsoft Edge: $_"
            $errorOccurred = $true
        }
    } else {
        Write-Output "Microsoft Edge update service not found."
    }

    $job = Start-Job -ScriptBlock {
        param ($errorOccurred)
        $edgePackage = Get-AppxPackage -Name "*Microsoft.MicrosoftEdge*" -AllUsers -ErrorAction SilentlyContinue
        if ($edgePackage) {
            $edgePackage | Remove-AppxPackage -ErrorAction SilentlyContinue
            if ($?) {
                Write-Output "Microsoft Edge foi removido com sucesso!"
            } else {
                $errorOccurred = $true
            }
        } else {
            Write-Output "Microsoft Edge não foi encontrado."
        }

        $edgeProvisionedPackage = Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.MicrosoftEdge" -ErrorAction SilentlyContinue
        if ($edgeProvisionedPackage) {
            $edgeProvisionedPackage | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
            if (-not $?) {
                $errorOccurred = $true
            }
        }
    } -ArgumentList $errorOccurred

    Wait-Job $job -Timeout 300
    if ($errorOccurred) {
        Write-Error "Failed to remove Microsoft Edge."
    } else {
        Receive-Job $job
    }

    Remove-Job $job -Force
}

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



    Read-Host "Pressione Enter para continuar..."

} while ($choice -ne "0")
