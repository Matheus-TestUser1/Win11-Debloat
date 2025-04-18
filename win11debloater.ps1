# Windows Tweaker GUI - Interface gráfica para o script de otimização do Windows
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Verificar se está executando como administrador
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    [System.Windows.Forms.MessageBox]::Show(
        "Você não está executando este script como administrador! Execute-o como administrador para continuar.", 
        "Erro de Permissão", 
        [System.Windows.Forms.MessageBoxButtons]::OK, 
        [System.Windows.Forms.MessageBoxIcon]::Error
    )
    Exit
}

# Função para registrar mensagens com timestamp
function Log($message) {
    $timeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timeStamp - $message"
    $logTextBox.AppendText("$logMessage`r`n")
    $logTextBox.ScrollToCaret()
}

# Função para registrar erros
function Error($message) {
    $logTextBox.SelectionColor = [System.Drawing.Color]::Red
    Log "ERRO: $message"
    $logTextBox.SelectionColor = $logTextBox.ForeColor
}

# Função para limpar o log
function Clear-Log {
    $logTextBox.Clear()
}

# Função para desativar telemetria
function Disable-Telemetry {
    Log "Desativando Telemetria..."

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

    Log "Telemetria foi desativada!"
    $progressBar.Value = 100
}

# Função para desativar configurações de privacidade
function Disable-PrivacySettings {
    Log "Desativando Histórico de Atividades..."
    $progressBar.Value = 10
    
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0

    $progressBar.Value = 30
    Log "Desativando Rastreamento de Localização..."
    if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0

    $progressBar.Value = 40
    Log "Desativando atualizações automáticas de Mapas..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0

    $progressBar.Value = 50
    Log "Desativando Feedback..."
    if (-not (Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null

    $progressBar.Value = 60
    Log "Desativando Experiências Personalizadas..."
    if (-not (Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1

    $progressBar.Value = 70
    Log "Desativando ID de Publicidade..."
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1

    $progressBar.Value = 80
    Log "Desativando Relatório de erros..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null

    $progressBar.Value = 90
    Log "Parando e desativando Serviço de Diagnóstico..."
    Stop-Service "DiagTrack" -WarningAction SilentlyContinue
    Set-Service "DiagTrack" -StartupType Disabled

    Log "Parando e desativando Serviço WAP Push..."
    Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
    Set-Service "dmwappushservice" -StartupType Disabled

    $progressBar.Value = 95
    Log "Habilitando opções de menu de inicialização F8..."
    bcdedit /set {current} bootmenupolicy Legacy | Out-Null

    $progressBar.Value = 100
    Log "Desativando Assistência Remota..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
    
    Log "Configurações de privacidade desativadas com sucesso!"
}

# Função para desativar serviços específicos
function Disable-Services {
    Log "Iniciando processo de desativação de serviços..."
    $progressBar.Value = 10
    
    # Lista de serviços para desativar
    $Services = @(
        "xbox",          # Todos os serviços Xbox
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

    $totalServices = $Services.Count
    $servicesProcessed = 0

    foreach ($ServicePattern in $Services) {
        try {
            # Pula comentários
            if ($ServicePattern.StartsWith("#")) {
                continue
            }

            # Atualizando a barra de progresso
            $servicesProcessed++
            $progressValue = [int](($servicesProcessed / $totalServices) * 90)
            $progressBar.Value = $progressValue

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

    $progressBar.Value = 100

    # Relatório final
    Log "`n=== Resumo da Operação ==="
    Log "Total processado: $($stats.Processed)"
    Log "Serviços desativados: $($stats.Disabled)"
    Log "Serviços interrompidos: $($stats.Stopped)"
    Log "Não encontrados: $($stats.NotFound)"
    Log "Falhas: $($stats.Failed)"
    Log "Operação concluída em $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"
}

# Função para remover bloatware
function Remove-Bloatware {
    Log "Removendo bloatware, aguarde..."
    $progressBar.Value = 10

    $BloatwareList = @(
        "Microsoft.BingNews", "Microsoft.BingWeather", "Microsoft.GetHelp", "Microsoft.Getstarted",
        "Microsoft.MicrosoftOfficeHub", "Microsoft.MicrosoftSolitaireCollection", "Microsoft.PowerAutomateDesktop",
        "Microsoft.People", "Microsoft.Todos", "Microsoft.WindowsAlarms", "microsoft.windowscommunicationsapps",
        "Microsoft.WindowsFeedbackHub", "Microsoft.WindowsMaps", "Microsoft.WindowsSoundRecorder", "Microsoft.ZuneMusic",
        "Microsoft.ZuneVideo", "MicrosoftTeams", "ClipChamp.ClipChamp"
    )

    $removedCount = 0
    $totalApps = $BloatwareList.Count
    $appsProcessed = 0

    foreach ($Bloat in $BloatwareList) {
        $appsProcessed++
        $progressValue = 10 + [int](($appsProcessed / $totalApps) * 80)
        $progressBar.Value = $progressValue
        
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

    $progressBar.Value = 100

    if ($removedCount -gt 0) {
        Log "Total de $removedCount aplicativos de bloatware removidos."
    } else {
        Log "Nenhum aplicativo de bloatware encontrado para remoção."
    }

    Log "Bloatware foi removido."
}

# Função para desativar acesso de aplicativos em segundo plano
function Disable-BackgroundAppAccess {
    Log "Desativando acesso de aplicativos em segundo plano..."
    $progressBar.Value = 20
    
    Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" | ForEach-Object {
        Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 1
        Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 1
    }
    
    $progressBar.Value = 70
    
    if (-not (Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Type DWord -Value 1
    
    $progressBar.Value = 100
    Log "Acesso de aplicativos em segundo plano desativado"
}

# Função para desativar Bing no Menu Iniciar
function Disable-BingSearchInStartMenu {
    Log "Desativando Bing no Menu Iniciar..."
    $progressBar.Value = 20
    
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
    
    $progressBar.Value = 50
    
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
    
    $progressBar.Value = 70
    
    Log "Parando e desativando o serviço de indexação de pesquisa do Windows..."
    Stop-Service "WSearch" -WarningAction SilentlyContinue
    Set-Service "WSearch" -StartupType Disabled
    
    $progressBar.Value = 100
    Log "Bing no Menu Iniciar desativado"
}

# Função para ocultar pesquisa
function Hide-Search {
    Log "Ocultando ícone/caixa de Pesquisa na Barra de Tarefas..."
    $progressBar.Value = 50
    
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
    
    $progressBar.Value = 100
    Log "Ícone/caixa de Pesquisa na Barra de Tarefas ocultado"
}

# Função para desativar Cortana
function Disable-Cortana {    
    Log "Desativando Cortana..."
    $progressBar.Value = 10
    
    if (-not (Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
    
    $progressBar.Value = 30
    
    if (-not (Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
    
    $progressBar.Value = 50
    
    if (-not (Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
    
    $progressBar.Value = 70
    
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
    
    try {
        Stop-Process -Name SearchApp -Force -ErrorAction SilentlyContinue
        Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
    } catch {
        Error "Erro ao reiniciar processos: $($_.Exception.Message)"
    }
    
    $progressBar.Value = 100
    Log "Cortana desativada"
}

# Função para finalizar ajustes
function Update-Tweaks {
    Log "Aplicando ajustes finais..."
    $progressBar.Value = 10
    
    # Desativando tarefas agendadas
    $scheduledTasksToDisable = @(
        "\Microsoft\Windows\ApplicationData\CleanupTemporaryState",
        "\Microsoft\Windows\ApplicationData\DsSvcCleanup",
        "\Microsoft\Windows\AppxDeploymentClient\Pre-stagedappcleanup",
        "\Microsoft\Windows\Autochk\Proxy",
        "\Microsoft\Windows\BrokerInfrastructure\BgTaskRegistrationMaintenanceTask"
    )

    $totalTasks = $scheduledTasksToDisable.Count
    $tasksProcessed = 0

    foreach ($task in $scheduledTasksToDisable) {
        $tasksProcessed++
        $progressValue = 10 + [int](($tasksProcessed / $totalTasks) * 40)
        $progressBar.Value = $progressValue
        
        try {
            Disable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue | Out-Null
            Log "Tarefa "$task" foi desativada"
        } catch {
            Error "Erro ao desativar tarefa $task: $($_.Exception.Message)"
        }
    }

    $progressBar.Value = 60
    
    # Configurando chaves de registro para otimização
    $registryKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling",
        "HKCU:\System\GameConfigStore"
    )

    foreach ($key in $registryKeys) {
        if (-not (Test-Path $key)) {
            New-Item -Path $key -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }
    
    $progressBar.Value = 80

    # Configurando propriedades para melhor desempenho
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Name "PowerThrottlingOff" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Type DWord
    } catch {
        Error "Erro ao configurar registro: $($_.Exception.Message)"
    }
    
    $progressBar.Value = 95
    
    # Reiniciando o explorador de arquivos para aplicar as mudanças
    try {
        Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
    } catch {
        Error "Erro ao reiniciar o explorador: $($_.Exception.Message)"
    }
    
    $progressBar.Value = 100
    Log "Ajustes concluídos com sucesso!"
}

# Função para remover Microsoft Edge
function Remove-Edge {
    Log "Removendo Microsoft Edge..."
    $progressBar.Value = 10
    
    $edgeUpdateService = Get-Service -Name "edgeupdate" -ErrorAction SilentlyContinue
    if ($null -ne $edgeUpdateService) {
        try {
            Set-Service -Name "edgeupdate" -StartupType Disabled -ErrorAction Stop
            Log "Serviço de atualização do Microsoft Edge desativado com sucesso."
        } catch {
            Error "Falha ao desativar o serviço de atualização do Microsoft Edge: $_"
        }
    } else {
        Log "Serviço de atualização do Microsoft Edge não encontrado."
    }
    
    $progressBar.Value = 30
    
    $edgePackage = Get-AppxPackage -Name "Microsoft.MicrosoftEdge" -AllUsers -ErrorAction SilentlyContinue
    if ($edgePackage) {
        try {
            $edgePackage | Remove-AppxPackage -ErrorAction SilentlyContinue
            Log "Microsoft Edge foi removido com sucesso!"
        } catch {
            Error "Falha ao remover o Microsoft Edge: $_"
        }
    } else {
        Log "Microsoft Edge não foi encontrado."
    }
    
    $progressBar.Value = 70
    
    $edgeProvisionedPackage = Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "Microsoft.MicrosoftEdge" -ErrorAction SilentlyContinue
    if ($edgeProvisionedPackage) {
        try {
            $edgeProvisionedPackage | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
            Log "Pacote provisionado do Microsoft Edge removido com sucesso."
        } catch {
            Error "Falha ao remover o pacote provisionado do Microsoft Edge: $_"
        }
    }
    
    $progressBar.Value = 100
    Log "Processo de remoção do Microsoft Edge concluído."
}

# Função para instalar programas usando Chocolatey
function Install-Programs {
    if (-not (Test-Path 'C:\ProgramData\chocolatey\bin\choco.exe')) {
        Log "Chocolatey não está instalado. Instalando Chocolatey..."
        $progressBar.Value = 10

        try {
            Set-ExecutionPolicy Bypass -Scope Process -Force
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
            
            $progressBar.Value = 80
            
            if (-not (Test-Path 'C:\ProgramData\chocolatey\bin\choco.exe')) {
                Error "A instalação do Chocolatey falhou. Verifique as configurações do PowerShell e a política de execução."
                return
            }
            
            $progressBar.Value = 100
            Log "Chocolatey foi instalado com sucesso!"
        } catch {
            $progressBar.Value = 100
            Error "Erro durante a instalação do Chocolatey: $_"
            return
        }
    }

    # Abrir um formulário de seleção de programas
    $installForm = New-Object System.Windows.Forms.Form
    $installForm.Text = "Selecione os programas para instalar"
    $installForm.Size = New-Object System.Drawing.Size(450, 500)
    $installForm.StartPosition = "CenterScreen"
    $installForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $installForm.MaximizeBox = $false

    $programs = @(
        @{Name="7-Zip"; ID="7zip"},
        @{Name="Google Chrome"; ID="googlechrome"},
        @{Name="WinRAR"; ID="winrar"},
        @{Name="Firefox"; ID="firefox"},
        @{Name="SimpleWall"; ID="simplewall"},
        @{Name="OOSO10 (AntiSpy)"; ID="ooso"},
        @{Name="Adobe Acrobat Reader DC"; ID="adobereader"},
        @{Name="Visual Studio Code"; ID="vscode"},
        @{Name="VLC Media Player"; ID="vlc"},
        @{Name="Spotify"; ID="spotify"},
        @{Name="Microsoft Office"; ID="microsoft-office-deployment"},
        @{Name="Adobe Creative Cloud"; ID="adobe-creative-cloud"},
        @{Name="Skype"; ID="skype"},
        @{Name="Zoom"; ID="zoom"},
        @{Name="GIMP"; ID="gimp"},
        @{Name="Audacity"; ID="audacity"},
        @{Name="Discord"; ID="discord"},
        @{Name="Python"; ID="python"},
        @{Name="Git"; ID="git"},
        @{Name="Notepad++"; ID="notepadplusplus"},
        @{Name="WinSCP"; ID="winscp"},
        @{Name="Steam"; ID="steam"},
        @{Name="Java (JDK)"; ID="jdk8"},
        @{Name="Node.js"; ID="nodejs"},
        @{Name="Docker Desktop"; ID="docker-desktop"},
        @{Name="VirtualBox"; ID="virtualbox"}
    )

    $checkboxes = @()
    $y = 20

    foreach ($program in $programs) {
        $checkbox = New-Object System.Windows.Forms.CheckBox
        $checkbox.Text = $program.Name
        $checkbox.Tag = $program.ID
        $checkbox.Location = New-Object System.Drawing.Point(20, $y)
        $checkbox.Size = New-Object System.Drawing.Size(180, 20)
        $installForm.Controls.Add($checkbox)
        $checkboxes += $checkbox
        $y += 25
    }

    $buttonInstall = New-Object System.Windows.Forms.Button
    $buttonInstall.Text = "Instalar Selecionados"
    $buttonInstall.Location = New-Object System.Drawing.Point(130, $y + 10)
    $buttonInstall.Size = New-Object System.Drawing.Size(180, 30)
    $installForm.Controls.Add($buttonInstall)

        $installationLog = New-Object System.Windows.Forms.TextBox
    }
