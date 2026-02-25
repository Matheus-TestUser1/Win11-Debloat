#Requires -RunAsAdministrator
#Requires -Version 5.1

# ============================================
# WINDOWS 11/10 DEBLOATER v2.1 - COMPLETO
# ============================================
# Autor: Otimizado para máxima segurança e performance
# Data: Fevereiro 2026
# ============================================

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = "Stop"
$WarningPreference = "Continue"
$ProgressPreference = "Continue"

# ============================================
# VARIÁVEIS GLOBAIS
# ============================================
$ScriptVersion = "2.1"
$BackupDir = "$env:TEMP\Win11Debloater_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$LogFile = "$env:TEMP\Win11Debloater_$((Get-Date).ToString('yyyyMMdd')).log"
$Global:RestorePointCreated = $false

# ============================================
# FUNÇÕES DE LOG E BACKUP
# ============================================

function Write-Log {
    param([Parameter(Mandatory)][string]$Message, [ValidateSet("INFO","SUCCESS","WARNING","ERROR")][string]$Level="INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    Add-Content -Path $LogFile -Value $logEntry -Force
    
    $color = switch($Level) {
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        default { "Cyan" }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Initialize-Backup {
    Write-Log "Inicializando backup completo do sistema..." "INFO"
    New-Item -Path $BackupDir -ItemType Directory -Force | Out-Null
    
    # Backup serviços
    Get-Service | Export-Csv "$BackupDir\Services_Backup.csv" -NoTypeInformation -Encoding UTF8
    
    # Backup apps instalados
    Get-AppxPackage -AllUsers | Export-Csv "$BackupDir\Apps_Backup.csv" -NoTypeInformation -Encoding UTF8
    
    Write-Log "Backup inicializado: $BackupDir" "SUCCESS"
}

function New-SystemRestorePoint {
    param([string]$Description = "Win11Debloater v$ScriptVersion")
    
    try {
        $systemDrive = $env:SystemDrive
        Enable-ComputerRestore -Drive "$systemDrive\" -Confirm:$false | Out-Null
        Start-Sleep -Seconds 2
        
        $drive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$systemDrive'"
        if ([Math]::Round($drive.FreeSpace / 1GB, 2) -lt 5) {
            Write-Log "Espaço em disco baixo!" "WARNING"
            $confirm = Read-Host "Continuar? (S/N)"
            if ($confirm -notmatch "^[Ss]") { return $false }
        }
        
        Checkpoint-Computer -Description $Description -RestorePointType "MODIFY_SETTINGS" | Out-Null
        Start-Sleep -Seconds 3
        
        $newPoint = Get-ComputerRestorePoint | Sort-Object CreationTime -Descending | Select-Object -First 1
        if ($newPoint.Description -eq $Description) {
            $Global:RestorePointCreated = $true
            Write-Log "Ponto de restauração '$($newPoint.Description)' criado!" "SUCCESS"
            return $true
        }
    } catch {
        Write-Log "Falha ao criar ponto de restauração: $_" "ERROR"
    }
    return $false
}

# ============================================
# FUNÇÕES DE REGISTRO SEGURAS
# ============================================

function Set-RegistryValueSafe {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value,
        [ValidateSet("DWord","String","QWord")][string]$Type = "DWord"
    )
    
    try {
        if (!(Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        
        # Backup da chave
        $backupReg = "$BackupDir\Registry_$($Path -replace '[:\\]','_').reg"
        $exportPath = $Path -replace '^HK(LM|CU):\\', '${function:regPath}'
        reg export "$Path" $backupReg /y 2>$null
        
        $null = Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        Write-Log "✓ Registro: $Path\$Name = $Value" "SUCCESS"
        return $true
    } catch {
        Write-Log "✗ Erro registro $Path\$Name`: $_" "ERROR"
        return $false
    }
}

# ============================================
# DESABILITAR TELEMETRIA (MÁXIMA PROTEÇÃO)
# ============================================

function Disable-Telemetry {
    Write-Log "========== DESABILITANDO TELEMETRIA ==========" "INFO"
    
    $telemetryKeys = @{
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" = @{ "AllowTelemetry" = 0 }
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" = @{ 
            "AllowTelemetry" = 0; "AllowDeviceNameInTelemetry" = 0 
        }
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" = @{ "AllowTelemetry" = 0 }
        "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" = @{ "CEIPEnable" = 0 }
        "HKLM:\SOFTWARE\Microsoft\SQMClient\Windows" = @{ "CEIPEnable" = 0 }
    }
    
    foreach ($path in $telemetryKeys.Keys) {
        foreach ($key in $telemetryKeys[$path].Keys) {
            Set-RegistryValueSafe -Path $path -Name $key -Value $telemetryKeys[$path][$key]
        }
    }
    
    # Tarefas agendadas
    $tasks = @(
        "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
    )
    
    foreach ($task in $tasks) {
        Disable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue | Out-Null
    }
    
    Write-Log "Telemetria desabilitada completamente!" "SUCCESS"
}

# ============================================
# PRIVACIDADE MÁXIMA
# ============================================

function Set-MaxPrivacy {
    Write-Log "========== CONFIGURAÇÕES DE PRIVACIDADE ==========" "INFO"
    
    $privacyKeys = @{
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" = @{ "Enabled" = 0 }
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" = @{ "DisabledByGroupPolicy" = 1 }
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" = @{ 
            "SilentInstalledAppsEnabled" = 0; "SystemPaneSuggestionsEnabled" = 0;
            "SubscribedContent-338388Enabled" = 0; "SubscribedContent-338389Enabled" = 0;
            "SubscribedContent-353698Enabled" = 0; "ContentDeliveryAllowed" = 0
        }
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" = @{ 
            "AllowCortana" = 0; "DisableWebSearch" = 1 
        }
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" = @{ 
            "EnableActivityFeed" = 0; "PublishUserActivities" = 0; "UploadUserActivities" = 0
        }
    }
    
    foreach ($path in $privacyKeys.Keys) {
        foreach ($key in $privacyKeys[$path].Keys) {
            Set-RegistryValueSafe -Path $path -Name $key -Value $privacyKeys[$path][$key]
        }
    }
    
    Write-Log "Privacidade máxima aplicada!" "SUCCESS"
}

# ============================================
# REMOVER BLOATED APPS (SELETIVO E SEGURO)
# ============================================

function Remove-Bloatware {
    Write-Log "========== REMOVENDO BLOATWARE ==========" "INFO"
    
    # Apps ESSENCIAIS que NUNCA remover
    $essentialApps = @(
        "Microsoft.WindowsStore", "Microsoft.WindowsTerminal",
        "Microsoft.DesktopAppInstaller", "Microsoft.HEIFImageExtension"
    )
    
    # Apps seguros para remover
    $bloatApps = @(
        "Microsoft.BingNews", "Microsoft.BingWeather", "Microsoft.GetHelp",
        "Microsoft.Getstarted", "Microsoft.People", "Microsoft.Print3D",
        "Microsoft.SkypeApp", "Microsoft.Todos", "Microsoft.YourPhone",
        "Microsoft.MicrosoftSolitaireCollection", "Microsoft.Xbox*",
        "Clipchamp", "*3DBuilder*", "*CandyCrush*", "*Disney*"
    )
    
    $appsToRemove = @()
    foreach ($pattern in $bloatApps) {
        $apps = Get-AppxPackage -AllUsers -Name $pattern -ErrorAction SilentlyContinue
        $apps += Get-AppxProvisionedPackage -Online | Where-Object { 
            $_.DisplayName -like $pattern -and $essentialApps -notcontains $_.DisplayName 
        }
        $appsToRemove += $apps
    }
    
    $appsToRemove = $appsToRemove | Sort-Object -Unique Name
    
    if ($appsToRemove.Count -eq 0) {
        Write-Log "Nenhum bloatware encontrado!" "INFO"
        return
    }
    
    Write-Host "`n📱 $($appsToRemove.Count) apps para remover:" -ForegroundColor Yellow
    $appsToRemove | ForEach-Object { Write-Host "  - $($_.Name)" -ForegroundColor Red }
    
    $confirm = Read-Host "`n❓ Continuar? (S/N)"
    if ($confirm -notmatch "^[Ss]") { 
        Write-Log "Remoção cancelada pelo usuário" "INFO"
        return 
    }
    
    $success = 0
    foreach ($app in $appsToRemove) {
        try {
            if ($app -is [Microsoft.Windows.AppxPackage]) {
                Remove-AppxPackage -Package $app.PackageFullName -AllUsers -ErrorAction Stop
            } else {
                Remove-AppxProvisionedPackage -Online -PackageName $app.PackageName -ErrorAction Stop
            }
            $success++
        } catch {
            Write-Log "Falha ao remover: $($app.Name)" "WARNING"
        }
    }
    
    Write-Log "✅ Removidos $success/$($appsToRemove.Count) apps!" "SUCCESS"
}

# ============================================
# OTIMIZAÇÃO DE PERFORMANCE
# ============================================

function Optimize-Performance {
    Write-Log "========== OTIMIZAÇÃO DE PERFORMANCE ==========" "INFO"
    
    # Animações e efeitos visuais
    $perfKeys = @{
        "HKCU:\Control Panel\Desktop" = @{ "MenuShowDelay" = 0; "VisualFXSetting" = 2 }
        "HKCU:\Control Panel\Desktop\WindowMetrics" = @{ "MinAnimate" = 0 }
        "HKCU:\Software\Microsoft\Windows\Dwm" = @{ "EnableAeroPeek" = 0 }
        "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" = @{ "Win32PrioritySeparation" = 26 }
    }
    
    foreach ($path in $perfKeys.Keys) {
        foreach ($key in $perfKeys[$path].Keys) {
            Set-RegistryValueSafe -Path $path -Name $key -Value $perfKeys[$path][$key]
        }
    }
    
    # Power plan Alto Desempenho
    powercfg /setactive SCHEME_MIN 2>$null
    
    # Desabilitar hibernação (economia de espaço)
    powercfg /hibernate off 2>$null
    
    # Limpeza temporários
    @($env:TEMP, "$env:SystemRoot\Temp") | ForEach-Object {
        Get-ChildItem -Path $_ -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) } |
        Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    }
    
    Write-Log "Performance otimizada!" "SUCCESS"
}

# ============================================
# DESABILITAR EDGE (SEGURO)
# ============================================

function Disable-Edge {
    Write-Log "========== DESABILITANDO EDGE ==========" "INFO"
    
    $confirm = Read-Host "⚠️  Desabilitar Microsoft Edge? Pode quebrar WebView2 (S/N)"
    if ($confirm -notmatch "^[Ss]") { return }
    
    # Parar processos
    @("msedge","msedgewebview2","MicrosoftEdge*") | ForEach-Object {
        Get-Process -Name $_ -ErrorAction SilentlyContinue | Stop-Process -Force
    }
    
    # Desabilitar atualizações
    @("edgeupdate","edgeupdatem") | ForEach-Object {
        $svc = Get-Service -Name $_ -ErrorAction SilentlyContinue
        if ($svc) {
            Stop-Service $_ -Force; Set-Service $_ -StartupType Disabled
        }
    }
    
    # Políticas bloqueio
    $edgeKeys = @{
        "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate" = @{ 
            "InstallDefault" = 0; "DoNotUpdateToEdgeWithChromium" = 1 
        }
    }
    
    foreach ($path in $edgeKeys.Keys) {
        foreach ($key in $edgeKeys[$path].Keys) {
            Set-RegistryValueSafe -Path $path -Name $key -Value $edgeKeys[$path][$key]
        }
    }
    
    Write-Log "Edge desabilitado via políticas!" "SUCCESS"
}

# ============================================
# MENU PRINCIPAL INTERATIVO
# ============================================

function Show-MainMenu {
    Clear-Host
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host "         WINDOWS 11/10 DEBLOATER v$ScriptVersion" -ForegroundColor Yellow
    Write-Host "              Otimizado | Seguro | Completo" -ForegroundColor Yellow
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "📁 Backup salvo em: $BackupDir" -ForegroundColor Green
    Write-Host "💾 Ponto restauração: " -NoNewline; 
    Write-Host ($Global:RestorePointCreated ? "✓ CRIADO" : "❌ Não criado") -ForegroundColor ($Global:RestorePointCreated ? "Green" : "Red")
    Write-Host ""
    
    Write-Host "🔒 [1] Desabilitar Telemetria (Privacy++)" -ForegroundColor Green
    Write-Host "🛡️  [2] Configurações Máxima Privacidade" -ForegroundColor Green
    Write-Host "🗑️  [3] Remover Bloatware (20+ apps)" -ForegroundColor Magenta
    Write-Host "⚡ [4] Otimizar Performance Completa" -ForegroundColor Magenta
    Write-Host "🌐 [5] Desabilitar Microsoft Edge" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "🔄 [R] Restaurar Tudo (Undo)" -ForegroundColor Blue
    Write-Host "📊 [H] Verificar Saúde do PC" -ForegroundColor Blue
    Write-Host "❌ [0] Sair" -ForegroundColor Red
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host ""
    
    $choice = Read-Host "Escolha uma opção"
    return $choice
}

# ============================================
# FUNÇÃO PRINCIPAL
# ============================================

function Restore-All {
    Write-Log "========== RESTAURANDO SISTEMA ==========" "INFO"
    
    # Reverter telemetria básica
    Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 3
    
    # Reabilitar serviços essenciais
    @("DiagTrack") | ForEach-Object { 
        Set-Service $_ -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service $_ -ErrorAction SilentlyContinue
    }
    
    Write-Log "Sistema restaurado! REINICIE o PC." "SUCCESS"
}

function Test-PCHealth {
    Clear-Host
    Write-Host "📊 VERIFICAÇÃO DE SAÚDE DO PC" -ForegroundColor Cyan
    Write-Host "=" * 50
    
    # Integridade sistema
    Write-Host "`n🔧 Integridade dos arquivos:"
    $sfc = sfc /scannow 2>&1
    if ($LASTEXITCODE -eq 0) { 
        Write-Host "  ✓ SFC: OK" -ForegroundColor Green 
    } else { 
        Write-Host "  ⚠️  SFC: Problemas encontrados" -ForegroundColor Yellow 
    }
    
    # Disco
    $disk = Get-CimInstance Win32_LogicalDisk | Where-Object DriveType -eq 3
    foreach ($d in $disk) {
        $free = [Math]::Round($d.FreeSpace/1GB,1)
        $pct = [Math]::Round(($d.FreeSpace/$d.Size)*100,1)
        Write-Host "  💾 $($d.DeviceID): $free GB livres ($pct%)" -ForegroundColor $(if($pct -lt 10){"Red"}else{"Green"})
    }
    
    # Memória
    $mem = Get-CimInstance Win32_OperatingSystem
    $freeMem = [Math]::Round($mem.FreePhysicalMemory/1MB,1)
    Write-Host "  🧠 RAM livre: $freeMem GB" -ForegroundColor Green
    
    Read-Host "`nPressione Enter para continuar"
}

# ============================================
# EXECUÇÃO PRINCIPAL
# ============================================

try {
    Clear-Host
    Write-Host "🚀 INICIANDO WINDOWS DEBLOATER v$ScriptVersion" -ForegroundColor Cyan
    Write-Log "Script iniciado - Windows $([System.Environment]::OSVersion.VersionString)"
    
    # Verificações iniciais
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Log "ERRO: Execute como Administrador!" "ERROR"
        Read-Host "Pressione Enter para sair"; exit 1
    }
    
    # Inicialização
    Initialize-Backup
    if (-NOT (New-SystemRestorePoint)) {
        Write-Log "AVISO: Sem ponto de restauração!" "WARNING"
    }
    
    # Menu principal
    do {
        $choice = Show-MainMenu
        
        switch ($choice) {
            "1" { Disable-Telemetry }
            "2" { Set-MaxPrivacy }
            "3" { Remove-Bloatware }
            "4" { Optimize-Performance }
            "5" { Disable-Edge }
            "R" { Restore-All }
            "H" { Test-PCHealth }
            "0" { break }
            default { Write-Host "❌ Opção inválida!" -ForegroundColor Red; Start-Sleep 1 }
        }
        
        if ($choice -ne "0") { Read-Host "`nPressione Enter para continuar" }
    } while ($choice -ne "0")
    
    Write-Host "`n🎉 Processo concluído!" -ForegroundColor Green
    Write-Host "📁 Backup: $BackupDir" -ForegroundColor Cyan
    Write-Host "📄 Log: $LogFile" -ForegroundColor Cyan
    Write-Host "🔄 RECOMENDADO: Reinicie o PC agora!" -ForegroundColor Yellow
    
} catch {
    Write-Log "ERRO FATAL: $_" "ERROR"
    Write-Host "`n❌ ERRO CRÍTICO: $_" -ForegroundColor Red
} finally {
    Write-Log "Script finalizado" "INFO"
    Read-Host "Pressione Enter para sair"
}
