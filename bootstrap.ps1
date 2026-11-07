#Requires -Version 5.1
# ASCII by design: compatible with both Windows PowerShell 5.1 files and IEX input.
[CmdletBinding()]
param(
    [ValidatePattern('^[a-zA-Z0-9_./-]+$')][string]$Ref='main',
    [string]$InstallRoot,
    [switch]$DownloadOnly
)

# Keep preferences, helper variables and TLS changes out of the caller's session.
& {
    param($Ref,$InstallRoot,$DownloadOnly)
    $ErrorActionPreference='Stop'
    $ProgressPreference='SilentlyContinue'
    if (-not $DownloadOnly -and ([Environment]::OSVersion.Platform -ne 'Win32NT' -or [Environment]::OSVersion.Version.Major -lt 10 -or -not [Environment]::Is64BitOperatingSystem)) {
        throw 'Use Windows 10 ou 11 de 64 bits para abrir a interface.'
    }
    if ([string]::IsNullOrWhiteSpace($InstallRoot)) {
        $InstallRoot=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Win11Debloat\Versions'
    }
    $InstallRoot=[IO.Path]::GetFullPath($InstallRoot)
    $null=[IO.Directory]::CreateDirectory($InstallRoot)
    $stage=Join-Path $InstallRoot ('download-'+[guid]::NewGuid().ToString('N'))
    $null=[IO.Directory]::CreateDirectory($stage)
    $previousProtocol=[Net.ServicePointManager]::SecurityProtocol
    $installedPath=$null
    try {
        [Net.ServicePointManager]::SecurityProtocol=$previousProtocol -bor [Net.SecurityProtocolType]::Tls12
        $repository='Matheus-TestUser1/Win11-Debloat'
        $headers=@{'User-Agent'='Win11Debloat-Launcher'; 'Accept'='application/vnd.github+json'}
        $encodedRef=[Uri]::EscapeDataString($Ref)
        # Resolve once and download the complete tree at that exact commit. This avoids
        # mixing a new entry point with an old module if main changes during download.
        $commit=Invoke-RestMethod -Uri "https://api.github.com/repos/$repository/commits/$encodedRef" -Headers $headers -TimeoutSec 60
        $revision=[string]$commit.sha
        if ($revision -notmatch '^[0-9a-f]{40}$') { throw 'O GitHub retornou um SHA fora do formato esperado.' }
        Write-Host "Baixando Win11 Debloat: $repository ($revision)" -ForegroundColor Cyan
        $archive=Join-Path $stage 'source.zip'
        Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/$repository/archive/$revision.zip" -OutFile $archive -TimeoutSec 120
        $extracted=Join-Path $stage 'extracted'
        Expand-Archive -LiteralPath $archive -DestinationPath $extracted -ErrorAction Stop
        $source=Join-Path $extracted "Win11-Debloat-$revision"
        $required=@('win11debloater.ps1','src\Debloat.Core.psm1','src\Debloat.Gui.ps1','ui\MainWindow.xaml','LICENSE')
        foreach ($relative in $required) {
            $file=Join-Path $source $relative
            if (-not (Test-Path -LiteralPath $file -PathType Leaf) -or (Get-Item -LiteralPath $file).Length -eq 0) {
                throw "Download incompleto: arquivo ausente ou vazio ($relative). O programa deixou de iniciar."
            }
        }
        # Every launch gets its own complete directory. Never overwrite files used by
        # an existing window or execute a partially downloaded/previous cached copy.
        $installedPath=Join-Path $InstallRoot ($revision+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
        Move-Item -LiteralPath $source -Destination $installedPath -ErrorAction Stop
        $metadata=[pscustomobject]@{Repository=$repository; Commit=$revision; DownloadedAt=(Get-Date).ToString('o')}
        [IO.File]::WriteAllText((Join-Path $installedPath 'source.json'),($metadata | ConvertTo-Json),(New-Object Text.UTF8Encoding($false)))
    } finally {
        [Net.ServicePointManager]::SecurityProtocol=$previousProtocol
        if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue }
    }
    if ($DownloadOnly) {
        return [pscustomobject]@{Path=$installedPath; Commit=$revision; Launched=$false}
    }
    $powershell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not [Environment]::Is64BitProcess) { $powershell=Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe' }
    $entry=Join-Path $installedPath 'win11debloater.ps1'
    $arguments='-NoProfile -STA -ExecutionPolicy Bypass -File "{0}"' -f $entry
    Write-Host 'Arquivos baixados. Abrindo a interface; confirme o pedido de administrador.' -ForegroundColor Green
    try { $null=Start-Process -FilePath $powershell -ArgumentList $arguments -Verb RunAs -PassThru -ErrorAction Stop }
    catch { throw "Erro ao abrir a interface. Arquivos em '$installedPath'. $($_.Exception.Message)" }
} $Ref $InstallRoot $DownloadOnly
