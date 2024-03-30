# script para windows 11 e 10!
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    [System.Windows.Forms.MessageBox]::Show(
        "Você não está executando este script como administrador! Execute-o como administrador para continuar.", 
        "Erro de Permissão", 
        [System.Windows.Forms.MessageBoxButtons]::OK, 
        [System.Windows.Forms.MessageBoxIcon]::Error
    )
    Exit
}

$description = "Ponto de restauração criado por script PowerShell"
try {
    $restorePoint = Get-ComputerRestorePoint
    if ($null -eq $restorePoint)  {
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
} catch {
    Write-Host "Erro ao criar o ponto de restauração: $_"
}




function Log($message) {
    $timeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "$timeStamp - $message"
}

function Error($message) {
    Write-Host "ERRO: $message" -ForegroundColor Red
}


# FunÃ§Ã£o para desabilitar telemetria
function Disable-Telemetry() {
    Log("Disabling Telemetry...")

    # Define as chaves e valores do registro que você deseja modificar
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

    # Define um loop para percorrer as configurações e aplicá-las
    foreach ($setting in $registrySettings.GetEnumerator()) {
        $key = $setting.Key
        $value = $setting.Value
        # Verifica se a chave do registro existe, se não, cria-a
        if (-not (Test-Path $key)) {
            New-Item -Path $key -Force | Out-Null
        }
        # Tenta modificar o registro
        try {
            # Define o valor do registro
            Set-ItemProperty -Path $key -Name "(Default)" -Value $value -Type DWORD -Force
            Write-Host "Configuração atualizada com sucesso: $key"
        } catch {
            Write-Host "Ocorreu um erro ao tentar modificar o registro: $_" -ForegroundColor Red
        }
    }

    Log("Telemetry has been disabled!")
}


# FunÃ§Ã£o para desabilitar histÃ³rico de atividades e rastreamento de localizaÃ§Ã£o
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

# FunÃ§Ã£o para desabilitar serviÃ§os especÃ­ficos
function Disable-Services() {
    Log("Disabling specified services...")
    
    # Lista de serviços a serem desabilitados
    $Services = @(
        "*xbox*",              # Serviços do Xbox
        "*Xbl*",               # Serviços do Xbox
        "XboxNetApiSvc",       # Serviços do Xbox
        #"LanmanWorkstation",  # Causa problemas com unidades mapeadas e programas de compartilhamento de arquivos!
        #"workfolderssvc",     # Causa problemas com unidades mapeadas e programas de compartilhamento de arquivos!
        "WSearch",             # Pesquisa do Windows
        #"PushToInstall",      # Necessário para a Microsoft Store
        #"icssvc",             # Ponto de Acesso Móvel
        "MixedRealityOpenXRSvc", # Realidade Mista
        "WMPNetworkSvc",       # Compartilhamento do Windows Media Player
        #"LicenseManager",     # Gerenciador de Licenças para Microsoft Store
        #"wisvc",              # Programa Insider
        "WerSvc",              # Relatórios de erros
        #"WalletService",      # Serviço de Carteira
        #"lmhosts",            # Auxiliar TCP/IP NetBIOS
        "SysMain",             # SuperFetch - Seguro para desativar se você tiver um SSD
        #"svsvc",              # Verificador de Ponto
        #"sppsvc",             # Proteção de Software
        "SCPolicySvc",         # Política de Remoção de Cartão Inteligente
        "ScDeviceEnum",        # Enumeração de Dispositivos de Cartão Inteligente
        "SCardSvr",            # Cartão Inteligente
        #"LanmanServer",       # Servidor - Causa problemas com unidades mapeadas e programas de compartilhamento de arquivos!
        #"SensorService",      # Serviço de Sensores
        "RetailDemo",          # Serviço de Demonstração no Varejo
        "RemoteRegistry",      # Registro Remoto - Emitido por V1ce
        #"UmRdpService",       # Serviços de Desktop Remoto do Modo de Usuário - Emitido por V1ce
        #"TermService",        # Serviços de Desktop Remoto - Emitido por V1ce
        #"SessionEnv",         # Configuração de Desktop Remoto - Emitido por V1ce
        #"RasMan",             # Gerenciador de Conexão de Acesso Remoto - Emitido por V1ce
        #"RasAuto",            # Gerenciador de Conexão Automática de Acesso Remoto - Emitido por V1ce
        #"TroubleshootingSvc", # Serviço de Solução de Problemas Recomendado
        #"RmSvc",              # Serviço de Gerenciamento de Rádio (Pode ser necessário para laptops)
        #"QWAVE",              # Experiência de Áudio e Vídeo do Windows de Qualidade
        #"wercplsupport",      # Suporte ao Painel de Controle de Relatórios de Problemas
        #"Spooler",            # Spooler de Impressão - Emitido por V1ce
        #"PrintNotify",        # Extensões e Notificações de Impressora - Emitido por V1ce
        #"PhoneSvc",           # Serviço de Telefone
        #"SEMgrSvc",           # Gerenciador de Pagamentos e NFC/SE
        "WpcMonSvc",           # Controles Parentais
        #"CscService",         # Arquivos Offline
        #"InstallService",     # Serviço de Instalação da Microsoft Store
        #"SmsRouter",          # Roteador de SMS do Windows Microsoft
        #"smphost",            # Serviço SMP de Espaços de Armazenamento Microsoft
        #"NgcCtnrSvc",         # Contêiner de Passaporte Microsoft
        #"MsKeyboardFilter",   # Filtro de Teclado Microsoft ... obrigado (.AtomRadar treasury #8267) pelo relatório. 
        #"cloudidsvc",         # Serviço de Identidade na Nuvem da Microsoft
        #"wlidsvc",            # Assistente de Logon da Conta Microsoft
        "*diagnosticshub*",   # Coletor Padrão de Serviços de Diagnóstico do Microsoft (R)
        #"iphlpsvc",           # Assistente de IP - Pode quebrar alguns Clientes VPN
        #"lfsvc",              # Serviço de Geolocalização - Emitido por V1ce
        #"fhsvc",              # Serviço de Histórico de Arquivos - Emitido por V1ce
        #"Fax",                # Fax - Emitido por V1ce
        #"embeddedmode",       # Modo Incorporado
        "MapsBroker",          # Gerenciador de Mapas Baixados
        "TrkWks",              # Cliente de Rastreamento de Link Distribuído
        "WdiSystemHost",       # Host do Sistema de Diagnóstico
        "WdiServiceHost",      # Host do Serviço de Diagnóstico
        "DPS",                 # Serviço de Política de Diagnóstico
        "diagsvc"              # Serviço de Execução de Diagnóstico
        #"DusmSvc",            # Uso de Dados
        #"VaultSvc",           # Gerenciador de Credenciais
        #"AppReadiness",       # Preparo do Aplicativo
    )

    # Desabilitar os serviços listados
    foreach ($Service in $Services) {
        if (-not $Service.StartsWith("#")) {
            Get-Service -Name $Service -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled
            if ((Get-Service -Name $Service).Status -eq "Running") {
                Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue | Out-Null
                Log("Trying to disable $($Service.DisplayName)")
            }
        }
    }
    
    Log("Specified services have been disabled.")
}

# FunÃ§Ã£o para remover bloatware
function Remove-Bloatware() {
    Log("Removendo bloatware, aguarde...")

    $BloatwareList = @(
        "Microsoft.BingNews",
        "Microsoft.BingWeather",
        "Microsoft.GetHelp",
        "Microsoft.Getstarted",
        "Microsoft.MicrosoftOfficeHub",
        "Microsoft.MicrosoftSolitaireCollection",
        #"Microsoft.MicrosoftStickyNotes", # Problema relatado por V1ce | Pode causar problemas com o sysprep
        "Microsoft.PowerAutomateDesktop", # Obrigado V1ce
        "Microsoft.SecHealthUI", # Obrigado V1ce
        "Microsoft.People",
        "Microsoft.Todos",
        #"Microsoft.Windows.Photos",
        "Microsoft.WindowsAlarms",
        #"Microsoft.WindowsCamera",
        "microsoft.windowscommunicationsapps",
        "Microsoft.WindowsFeedbackHub",
        "Microsoft.WindowsMaps",
        "Microsoft.WindowsSoundRecorder",
        #"Microsoft.YourPhone", # Realmente útil
        "Microsoft.ZuneMusic",
        "Microsoft.ZuneVideo",
        "MicrosoftTeams",
        "ClipChamp.ClipChamp"
        # Adicione mais aplicativos de bloatware à lista, se necessário
    )

    $removedCount = 0

    foreach ($Bloat in $BloatwareList) {
        Log("Tentando remover $Bloat")
        try {
            $app = Get-AppxPackage -Name $Bloat -ErrorAction SilentlyContinue
            if ($app -ne $null) {
                $app | Remove-AppxPackage -ErrorAction Stop | Out-Null
                $removedCount++
                Log("$Bloat foi removido com sucesso")
            } else {
                Log("$Bloat não está presente.")
            }

            $provisionedApp = Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat -ErrorAction SilentlyContinue
            if ($provisionedApp -ne $null) {
                $provisionedApp | Remove-AppxProvisionedPackage -Online -ErrorAction Stop
                Log("$Bloat (provisioned) foi removido com sucesso")
            } else {
                Log("$Bloat (provisioned) não está presente.")
            }
        } catch {
            Error("Falha ao remover $Bloat, exceção: $($_.Exception.Message)")
        }
    }

    if ($removedCount -gt 0) {
        Log("Total de $removedCount aplicativos de bloatware removidos.")
    } else {
        Log("Nenhum aplicativo de bloatware encontrado para remoção.")
    }
    
    Log("Bloatware foi removido.")

    # Limpar o trabalho após a remoção do bloatware
    Remove-Job -Name "Remove-Bloatware" -ErrorAction SilentlyContinue
}

	# FunÃ§Ã£o para desabilitar o acesso de aplicativos em segundo plano
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

# FunÃ§Ã£o para desabilitar a pesquisa do Bing no Menu Iniciar
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

# FunÃ§Ã£o para esconder a barra de pesquisa da barra de tarefas
function Hide-Search() {
    Log("Hiding Taskbar Search icon / box...")
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
}

# FunÃ§Ã£o para desabilitar Cortana
function Disable-Cortana() {    
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

function Update-Tweaks() {
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
    Write-Output "Removing Microsoft Edge..."
    $errorOccurred = $false

    # Desabilita o serviço de atualização automática do Microsoft Edge, se presente
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
        $edgePackage = Get-AppxPackage -AllUsers *Microsoft.MicrosoftEdge* -ErrorAction SilentlyContinue
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

    # Espera até que o trabalho termine
    Wait-Job $job

    # Exibe mensagem de erro, se houver
    if ($errorOccurred) {
        Write-Error "Failed to remove Microsoft Edge."
    } else {
        # Obtém o resultado do trabalho
        $result = Receive-Job $job
    }

    # Limpa o trabalho
    Remove-Job $job
}



 # Função para mostrar o submenu com uma lista de programas para baixar
# Verificar se o Chocolatey já está instalado

function install-programs() {
    # Verificar se o Chocolatey já está instalado
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
        Write-Host "1. 7-Zip"
        Write-Host "2. Google Chrome"
        Write-Host "3. WinRAR"
        Write-Host "4. Firefox"
        Write-Host "5. SimpleWall"
        Write-Host "6. OOSO10 (ANTISPY)"
        Write-Host "0. Voltar"

        $choice = Read-Host "Digite o número da opção e pressione Enter"

        switch ($choice) {
            "1" {
                choco install 7zip -y
            }
            "2" {
                choco install googlechrome -y
            }
            "3" {
                choco install winrar -y
            }
            "4" {
                choco install firefox -y
            }
            "5" {
                choco install simplewall -y
            }
            "6" {
                $url = "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe"

                # Construir o caminho completo para a pasta de Downloads do usuário
                $userProfile = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::UserProfile)
                $downloadPath = Join-Path $userProfile "Downloads"
                $localPath = Join-Path $downloadPath "OOSU10.exe"

                # Baixar o arquivo
                try {
                    Invoke-WebRequest -Uri $url -OutFile $localPath -ErrorAction Stop

                    # Verificar se o arquivo foi baixado corretamente
                    if (Test-Path $localPath) {
                        Write-Host "Arquivo baixado com sucesso em $localPath."
                        
                        # Executar o arquivo
                        Start-Process -FilePath $localPath -Wait
                    } else {
                        Write-Host "Falha ao baixar o arquivo."
                    }
                } catch {
                    Write-Host "Erro ao baixar ou executar o arquivo: $_"
                }
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
    Write-Host "Windows Debloater Script WIN11/10" -ForegroundColor Cyan
    Write-Host "Escolha uma opção:"
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
    Write-Host "11. Programas"
    Write-Host "0. Sair"

    $choice = Read-Host "Digite o número da opção e pressione Enter"

    switch ($choice) {
        "1" { Disable-Telemetry }
        "2" { Disable-PrivacySettings }
        "3" { Remove-Bloatware }
        "4" { Disable-Services }
        "5" { disable-Cortana }
        "6" { DisableBingSearchInStartMenu }
        "7" { Update-Tweaks }
        "8" { DisableBackgroundAppAccess }
        "9" { Hide-Search }
        "10" { Remove-Edge }
        "11" { install-programs }   
        "0" { break }
        default { Write-Host "Escolha invalida, tente novamente." }
    }

    Read-Host "Pressione Enter para continuar..."

} while ($choice -ne "0") {}
