If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    [Void] [System.Windows.Forms.MessageBox]::Show(
        "Você não está executando este script como administrador! Você deve usar um script em lote para iniciar este script!", 
        "", 
        [System.Windows.Forms.MessageBoxButtons]::OK, 
        [System.Windows.Forms.MessageBoxIcon]::Error
    )
    Exit
}

$description = "Ponto de restauração criado por script PowerShell"
$restorePoint = Get-ComputerRestorePoint
if ($restorePoint -eq $null)  {
    Write-Host "Criando um ponto de restauração para sua segurança..."
    Checkpoint-Computer -Description $description -RestorePointType MODIFY_SETTINGS
} else {
    Write-Host "Um ponto de restauração já existe. Deseja criar outro ponto de restauração? (S/N)"
    $choice = Read-Host
    if ($choice -eq "S" -or $choice -eq "s") {
        Write-Host "Criando um novo ponto de restauração..."
        Checkpoint-Computer -Description $description -RestorePointType MODIFY_SETTINGS
    } else {
        Write-Host "Continuando sem criar um novo ponto de restauração..."
    }
}



function Log($message) { 
     $timeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss" 
     Write-Host "$timeStamp - $message" }



# Função para exibir mensagens de log
function Log($message) {
    Write-Host $message
}
		
# Função para exibir mensagens de erro
function Error($message) {
 
    Write-Host "ERRO: $message" -ForegroundColor Red
}

# Função para desabilitar telemetria
function Disable-Telemetry() {
    Log("Disabling Telemetry...")
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
    Log("Telemetry has been disabled!")
}

# Função para desabilitar histórico de atividades e rastreamento de localização
function Disable-PrivacySettings() {
    Log("Disabling Activity History...")
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
    Log("Disabling Location Tracking...")
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
    Log("Disabling automatic Maps updates...")
    Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
    Log("Disabling Feedback...")
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
    Log("Disabling Tailored Experiences...")
    If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
    Log("Disabling Advertising ID...")
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
    Log("Disabling Error reporting...")
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
    Log("Stopping and disabling Diagnostics Tracking Service...")
    Stop-Service "DiagTrack" -WarningAction SilentlyContinue
    Set-Service "DiagTrack" -StartupType Disabled
    Log("Stopping and disabling WAP Push Service...")
    Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
    Set-Service "dmwappushservice" -StartupType Disabled
    Log("Enabling F8 boot menu options...")
    bcdedit /set `{current`} bootmenupolicy Legacy | Out-Null
    Log("Disabling Remote Assistance...")
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
}

# Função para desabilitar serviços específicos
function Disable-Services() {
    Log("Disabling specified services...")
    $Services = @(
	"*xbox*" # Xbox Services
        "*Xbl*" # Xbox Services
        "XboxNetApiSvc" # Xbox Services
        #"LanmanWorkstation" # Causes problems with Mapped Drives and File Sharing Programs!
        #"workfolderssvc" # Causes problems with Mapped Drives and File Sharing Programs!
        "WSearch" # Windows Search
        #"PushToInstall" # Needed for Microsoft Store
        #"icssvc" # Mobile Hotspot
        "MixedRealityOpenXRSvc" # Mixed Reality
        "WMPNetworkSvc" # Windows Media Player Sharing
        #"LicenseManager" # License Manager for Microsoft Store
        #"wisvc" # Insider Program
        "WerSvc" # Error Reporting
        #"WalletService" # Wallet Service
        #"lmhosts" # TCP/IP NetBIOS Helper
        "SysMain" # SuperFetch - Safe to disable if you have a SSD
        #"svsvc" # Spot Verifier
        #"sppsvc" # Software Protection
        "SCPolicySvc" # Smart Card Removal Policy
        "ScDeviceEnum" # Smart Card Device Enumeration Service
        "SCardSvr" # Smart Card
        "LanmanServer" # Server # Causes problems with Mapped Drives and File Sharing Programs!
        #"SensorService" # Sensor Service
        "RetailDemo" # Retail Demo Service
        "RemoteRegistry" # Remote Registry # Issue by V1ce
        #"UmRdpService" # Remote Desktop Services UserMode Port Redirector # Issue by V1ce
        #"TermService" # Remote Desktop Services # Issue by V1ce
        #"SessionEnv" # Remote Desktop Configuration # Issue by V1ce
        #"RasMan" # Remote Access Connection Manager # Issue by V1ce
        #"RasAuto" # Remote Access Auto Connection Manager # Issue by V1ce
        #"TroubleshootingSvc" # Recommended Troubleshooting Service
        #"RmSvc" # Radio Management Service (Might be needed for laptops)
        #"QWAVE" # Quality Windows Audio Video Experience
        #"wercplsupport" # Problem Reports Control Panel Support
        #"Spooler" # Print Spooler # Issue by V1ce
        #"PrintNotify" # Printer Extensions and Notifications # Issue by V1ce
        #"PhoneSvc" # Phone Service
        #"SEMgrSvc" # Payments and NFC/SE Manager
        "WpcMonSvc" # Parental Controls
        #"CscService" # Offline Files
        #"InstallService" # Microsoft Store Install Service
        #"SmsRouter" # Microsoft Windows SMS Router Service
        #"smphost" # Microsoft Storage Spaces SMP
        #"NgcCtnrSvc" # Microsoft Passport Container
        #"MsKeyboardFilter" # Microsoft Keyboard Filter ... thanks (.AtomRadar treasury #8267) for report. 
        #"cloudidsvc" # Microsoft Cloud Identity Service
        #"wlidsvc" # Microsoft Account Sign-in Assistant
        "*diagnosticshub*" # Microsoft (R) Diagnostics Hub Standard Collector Service
        #"iphlpsvc" # IP Helper - Might break some VPN Clients
        #"lfsvc" # Geolocation Service # Issue by V1ce
        #"fhsvc" # File History Service # Issue by V1ce
        #"Fax" # Fax # Issue by V1ce
        #"embeddedmode" # Embedded Mode
        "MapsBroker" # Downloaded Maps Manager
        "TrkWks" # Distributed Link Tracking Client
        "WdiSystemHost" # Diagnostic System Host
        "WdiServiceHost" # Diagnostic Service Host
        "DPS" # Diagnostic Policy Service
        "diagsvc" # Diagnostic Execution Service
        #"DusmSvc" # Data Usage
        #"VaultSvc" # Credential Manager
        #"AppReadiness" # App Readiness
    )
	
        # Adicione os serviços que você deseja desabilitar aqui
    

    # Desabilitar os serviços listados
    foreach ($Service in $Services) {
        Get-Service -Name $Service -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled
        if ($Service.Status -match "Running") {
            Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue | Out-Null
            Log("Trying to disable $($Service.DisplayName)")
        }
    }
    
    Log("Specified services have been disabled.")
}

# Função para remover bloatware
function Remove-Bloatware() {
    Log("Removendo bloatware, aguarde...")

    $BloatwareList = @(
        "Microsoft.BingNews"
        "Microsoft.BingWeather"
        "Microsoft.GetHelp"
        "Microsoft.Getstarted"
        "Microsoft.MicrosoftOfficeHub"
        "Microsoft.MicrosoftSolitaireCollection"
        #"Microsoft.MicrosoftStickyNotes" # Problema relatado por V1ce | Pode causar problemas com o sysprep
        "Microsoft.PowerAutomateDesktop" # Obrigado V1ce
        "Microsoft.SecHealthUI" # Obrigado V1ce
        "Microsoft.People"
        "Microsoft.Todos"
        #"Microsoft.Windows.Photos"
        "Microsoft.WindowsAlarms"
        #"Microsoft.WindowsCamera"
        "microsoft.windowscommunicationsapps"
        "Microsoft.WindowsFeedbackHub"
        "Microsoft.WindowsMaps"
        "Microsoft.WindowsSoundRecorder"
        #"Microsoft.YourPhone" # Realmente útil
        "Microsoft.ZuneMusic"
        "Microsoft.ZuneVideo"
        "MicrosoftTeams"
        "ClipChamp.ClipChamp"
        # Adicione mais aplicativos de bloatware à lista, se necessário
    )
    foreach ($Bloat in $BloatwareList) {
        if ((Get-AppxPackage -Name $Bloat).NonRemovable -eq $false) {
            Log("Tentando remover $Bloat")
            try {
                Get-AppxPackage -Name $Bloat | Remove-AppxPackage -ErrorAction Stop | Out-Null
                Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online -ErrorAction Stop
                Log("$Bloat foi removido com sucesso")
            } catch {
                Error("Falha ao remover $Bloat, exceção: $($_.Exception.Message)")
            }
        }
    }
    Log("Bloatware foi removido.")
}


	# Função para desabilitar o acesso de aplicativos em segundo plano
function DisableBackgroundAppAccess() {
    Log("Disabling Background application access...")
    Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" | ForEach-Object {
        Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 1
        Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 1
    }
    if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Type DWord -Value 1
    Log("Disabled Background application access")
}

# Função para desabilitar a pesquisa do Bing no Menu Iniciar
function DisableBingSearchInStartMenu() {
    Log("Disabling Bing Search in Start Menu...")
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
    Log("Stopping and disabling Windows Search indexing service...")
    Stop-Service "WSearch" -WarningAction SilentlyContinue
    Set-Service "WSearch" -StartupType Disabled
}

# Função para esconder a barra de pesquisa da barra de tarefas
function hidesearch() {
    Log("Hiding Taskbar Search icon / box...")
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
}

# Função para desabilitar Cortana
function disable-Cortana() {    
    Log("Disabling Cortana...")
    if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
    if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
    if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
    Stop-Process -Name SearchApp -Force
    Stop-Process -Name explorer -Force
    Log("Disabled Cortana")
}

function Apply-WindowsTweaks() {
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
        "\Microsoft\Windows\OfflineFiles\LogonSynchronization",
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
        Log("Task `"$task`" was disabled")
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
        if (!(Test-Path $key)) {
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
            Value = ([byte[]](0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)) -as [byte[]];
            Type = 'Binary';
        }
    )

    foreach ($prop in $registryProperties) {
        New-ItemProperty -LiteralPath $prop.Key -Name $prop.Name -Value $prop.Value -PropertyType $prop.Type -Force -ea SilentlyContinue
    }

    Stop-Process -Name explorer
    Log("Tweaks are done!")
}

function Remove-Edge() {
        Log("Removing Microsoft Edge...")
    Get-AppxPackage -AllUsers *Microsoft.MicrosoftEdge* | Remove-AppxPackage -ErrorAction SilentlyContinue
    Get-AppxProvisionedPackage -Online | where DisplayName -eq "Microsoft.MicrosoftEdge" | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    Log("Microsoft Edge has been removed!")
}
     
 
 # Função para mostrar o submenu com uma lista de programas para baixar
function programas {
    # Verificar se o Chocolatey já está instalado
    if (-Not (Test-Path 'C:\ProgramData\chocolatey\bin\choco.exe')) {
        Write-Host "Chocolatey não está instalado. Instalando Chocolatey..."
        Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
        if (-Not (Test-Path 'C:\ProgramData\chocolatey\bin\choco.exe')) {
            Write-Host "A instalação do Chocolatey falhou. Verifique as configurações do PowerShell e da política de execução."
            return
        }
        Write-Host "Chocolatey foi instalado com sucesso!"
    }

    do {
        Clear-Host
        Write-Host "Escolha um programa para baixar:"
        Write-Host "1. 7zip"
        Write-Host "2. Google Chrome"
        Write-Host "3. WinRar"
        Write-Host "4. Firefox"
        Write-Host "0. Voltar"

        $choice = Read-Host "Digite o número da opção e pressione Enter"

        switch ($choice) {
            "1" {
                choco install 7zip -y
                Write-Host "Baixando 7zip..."
                Write-Host "Programa 7Zip baixado e instalado com sucesso!"
                Read-Host "Pressione Enter para continuar..."
            }
            "2" {
                choco install googlechrome -y
                Write-Host "Baixando o Google Chrome..."
                Write-Host "Programa Google Chrome baixado e instalado com sucesso!"
                Read-Host "Pressione Enter para continuar..."
            }
            "3" {
                choco install winrar -y
                Write-Host "Baixando o WinRar..."
                Write-Host "Programa WinRar baixado e instalado com sucesso!"
                Read-Host "Pressione Enter para continuar..."
            }
            "4" {
                choco install firefox -y
                Write-Host "Baixando o Firefox..."
                Write-Host "Programa Firefox baixado e instalado com sucesso!"
                Read-Host "Pressione Enter para continuar..."
            }
            "0" { return }
            default {
                Write-Host "Escolha inválida, tente novamente."
                Read-Host "Pressione Enter para continuar..."
            }
        }
    } while ($true)
}


# Menu de opções
do {
    Clear-Host
    Write-Host "Escolha uma opção:"
    Write-Host "1. Desabilitar Telemetria"
    Write-Host "2. Desabilitar Histórico de Atividades e Rastreamento de Localização"
    Write-Host "3. Remover Bloatware"
    Write-Host "4. Desabilitar Serviços Específicos"
    Write-Host "5. Desabilitar Cortana"
    Write-Host "6. Desabilitar Bing No Menu Iniciar"
    Write-Host "7. conclusao"
    Write-Host "8. Desabilitar Acesso de Aplicativos em Segundo Plano"
    Write-Host "9. Hide Search"
    Write-Host "10.Remover Edge"
    Write-Host "11.Programas"
    Write-Host "0. Sair"
    
    $choice = Read-Host "Digite o número da opção e pressione Enter"
    
    switch ($choice) {
        "1" { Disable-Telemetry }
        "2" { Disable-PrivacySettings }
        "3" { Remove-Bloatware }
        "4" { Disable-Services }
        "5" { disable-Cortana }
        "6" { DisableBingSearchInStartMenu }
        "7" { Apply-WindowsTweaks }
        "8" { DisableBackgroundAppAccess }
        "9" { hidesearch }
        "10" { Remove-Edge }
        "11" { programas }
        "0" { break }
        default { Write-Host "Escolha inválida, tente novamente." }
    }
    
    Read-Host "Pressione Enter para continuar..."
} while ($choice -ne "0")
