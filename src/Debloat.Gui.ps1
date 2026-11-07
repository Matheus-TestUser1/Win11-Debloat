#Requires -Version 5.1
param([switch]$SmokeTest)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
Import-Module (Join-Path $PSScriptRoot 'Debloat.Core.psm1') -Force

# Observable selection model keeps selection across category/search changes.
if (-not ('Win11Debloat.Option' -as [type])) {
    Add-Type -TypeDefinition @'
using System.ComponentModel;
namespace Win11Debloat {
    public class Option : INotifyPropertyChanged {
        public string Id { get; set; }
        public string Category { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }
        public bool Recommended { get; set; }
        public string Kind { get; set; }
        private bool selected;
        public bool Selected { get { return selected; } set { selected=value; Changed("Selected"); } }
        private string availability;
        public string Availability { get { return availability; } set { availability=value; Changed("Availability"); } }
        public event PropertyChangedEventHandler PropertyChanged;
        private void Changed(string name) { if(PropertyChanged!=null) PropertyChanged(this,new PropertyChangedEventArgs(name)); }
    }
}
'@
}
$xamlPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'ui\MainWindow.xaml'
$reader = [Xml.XmlReader]::Create($xamlPath)
try { $script:Window = [Windows.Markup.XamlReader]::Load($reader) } finally { $reader.Close() }
$script:Controls = @{}
foreach ($name in @('CategoryList','ActionsList','SearchBox','RecommendedButton','SelectionCount','AppsCount','SystemLabel','SummaryLabel','RestorePointCheck','RestoreButton','OpenLogsButton','SaveLogButton','LogBox','StatusLabel','WorkProgress','ScanButton','PreviewButton','ApplyButton')) {
    $script:Controls[$name] = $script:Window.FindName($name)
    if (-not $script:Controls[$name]) { throw "Controle ausente no XAML: $name" }
}
$script:Options = New-Object 'System.Collections.ObjectModel.ObservableCollection[Win11Debloat.Option]'
foreach ($action in Get-DebloatCatalog) {
    $option = New-Object Win11Debloat.Option
    foreach ($property in @('Id','Category','Title','Description','Recommended','Kind')) { $option.$property = $action.$property }
    $option.Availability = if ($action.Kind -eq 'Appx') { 'Analise para verificar se está instalado' } else { '' }
    $option.add_PropertyChanged({ Update-Selection })
    $script:Options.Add($option)
}
$script:View = [Windows.Data.CollectionViewSource]::GetDefaultView($script:Options)
$script:Controls.ActionsList.ItemsSource = $script:View
$script:Busy = $false
$script:Job = $null
$script:PersistentLog = $null

function Add-UiLog {
    param([string]$Message, [string]$Level='Info')
    $line = "$(Get-Date -Format 'HH:mm:ss') [$Level] $Message"
    $script:Controls.LogBox.AppendText("$line`r`n")
    $script:Controls.LogBox.ScrollToEnd()
    if ($script:PersistentLog) {
        try { Add-Content -LiteralPath $script:PersistentLog -Value $line -Encoding UTF8 -ErrorAction Stop }
        catch { $script:Controls.StatusLabel.Text='Não foi possível gravar o registro em disco. Use Salvar registro.'; $script:PersistentLog=$null }
    }
}

function Update-Selection {
    $selected = @($script:Options | Where-Object Selected)
    $script:Controls.SelectionCount.Text = if ($selected.Count -eq 1) { '1 opção' } else { "$($selected.Count) opções" }
    $script:Controls.SummaryLabel.Text = if ($selected.Count) { ($selected.Title | ForEach-Object { "• $_" }) -join "`n`n" } else { 'Selecione as opções ao lado.' }
    $script:Controls.ApplyButton.IsEnabled = -not $script:Busy -and $selected.Count -gt 0
    $script:Controls.PreviewButton.IsEnabled = -not $script:Busy -and $selected.Count -gt 0
}

function Update-Filter {
    $script:View.Filter = [Predicate[object]]{
        param($item)
        $category = [string]$script:Controls.CategoryList.SelectedItem.Content
        $query = $script:Controls.SearchBox.Text.Trim()
        $matchesCategory = $category -eq 'Todas as opções' -or $item.Category -eq $category
        $text = "$($item.Title) $($item.Description) $($item.Category)"
        $matchesCategory -and ($query.Length -eq 0 -or $text.IndexOf($query, [StringComparison]::CurrentCultureIgnoreCase) -ge 0)
    }
    $script:View.Refresh()
}

function Set-UiBusy {
    param([bool]$Value)
    $script:Busy=$Value
    foreach ($name in @('ScanButton','RestoreButton','RecommendedButton','ActionsList','RestorePointCheck')) { $script:Controls[$name].IsEnabled=-not $Value }
    $script:Controls.WorkProgress.IsIndeterminate=$Value
    Update-Selection
}

function Start-UiOperation {
    param([string]$Mode, [string[]]$Ids=@(), [string]$BackupPath='')
    if ($script:Busy) { return }
    try {
        $queue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
        $runspace = [RunspaceFactory]::CreateRunspace()
        $runspace.ApartmentState='STA'
        $runspace.ThreadOptions='ReuseThread'
        $runspace.Open()
        $ps = [PowerShell]::Create()
        $ps.Runspace=$runspace
        # Worker never touches a WPF control. DispatcherTimer drains the event queue.
        $worker = {
            param($ModulePath,$Mode,$Ids,$BackupPath,$CreatePoint,$Queue)
            $ErrorActionPreference='Stop'
            try {
                Import-Module $ModulePath -Force
                $callback = { param($event) $Queue.Enqueue([pscustomobject]@{Type='Log'; Data=$event}) }
                $result = switch ($Mode) {
                    'Scan' { Get-DebloatSystemInfo }
                    'Preview' { Invoke-DebloatApply -ActionIds $Ids -WhatIf -OnEvent $callback }
                    'Apply' { Invoke-DebloatApply -ActionIds $Ids -CreateRestorePoint:$CreatePoint -Confirm:$false -OnEvent $callback }
                    'Restore' { Restore-DebloatBackup -Path $BackupPath -Confirm:$false -OnEvent $callback }
                }
                $Queue.Enqueue([pscustomobject]@{Type='Result'; Data=$result; Mode=$Mode})
            } catch { $Queue.Enqueue([pscustomobject]@{Type='Error'; Data=$_.Exception.Message}) }
        }
        $null=$ps.AddScript($worker.ToString()).AddArgument((Join-Path $PSScriptRoot 'Debloat.Core.psm1')).AddArgument($Mode).AddArgument($Ids).AddArgument($BackupPath).AddArgument([bool]$script:Controls.RestorePointCheck.IsChecked).AddArgument($queue)
        $script:Job = @{PowerShell=$ps; Runspace=$runspace; Queue=$queue; Handle=$null}
        Set-UiBusy $true
        $script:Controls.StatusLabel.Text='Operação em andamento...'
        $script:Controls.WorkProgress.Value=0
        $script:Job.Handle=$ps.BeginInvoke()
        $script:Timer.Start()
    } catch {
        if ($script:Job) { $script:Job.PowerShell.Dispose(); $script:Job.Runspace.Dispose(); $script:Job=$null }
        else {
            if ($ps) { $ps.Dispose() }
            if ($runspace) { $runspace.Dispose() }
        }
        Set-UiBusy $false
        Add-UiLog $_.Exception.Message 'Error'
        $script:Controls.StatusLabel.Text='Não foi possível iniciar a operação.'
    }
}

function Receive-UiEvents {
    if (-not $script:Job) { return }
    $event=$null
    while ($script:Job.Queue.TryDequeue([ref]$event)) {
        switch ($event.Type) {
            Log {
                Add-UiLog $event.Data.Message $event.Data.Level
                if ($event.Data.Percent -ge 0) { $script:Controls.WorkProgress.IsIndeterminate=$false; $script:Controls.WorkProgress.Value=$event.Data.Percent }
            }
            Error { Add-UiLog $event.Data 'Error'; $script:Controls.StatusLabel.Text='Operação interrompida. Consulte o registro.' }
            Result {
                switch ($event.Mode) {
                    Scan {
                        $script:Controls.SystemLabel.Text="$($event.Data.Caption) • build $($event.Data.Build) • $($event.Data.MemoryGB) GB RAM"
                        $catalog = @(Get-DebloatCatalog)
                        $installedCount=0
                        foreach ($option in $script:Options) {
                            if ($option.Kind -eq 'Appx') {
                                $action=$catalog | Where-Object Id -EQ $option.Id
                                $installed=@($action.Targets | Where-Object { $_ -in $event.Data.InstalledApps }).Count -gt 0
                                $option.Availability=if($installed){$installedCount++; 'Instalado nesta conta'}else{'Não instalado nesta conta'}
                            }
                        }
                        $script:Controls.AppsCount.Text=if($installedCount -eq 1){'1 encontrado'}else{"$installedCount encontrados"}
                        $script:Controls.StatusLabel.Text='Análise concluída. Nenhum ajuste aplicado.'
                        Add-UiLog 'Computador e aplicativos analisados. Nenhum ajuste aplicado.'
                    }
                    Preview {
                        $script:Controls.StatusLabel.Text='Simulação concluída. Nenhum ajuste aplicado.'
                        Add-UiLog 'A simulação lista as ações selecionadas; não testa permissões nem garante que elas terão efeito nesta edição.'
                    }
                    Apply {
                        $r=$event.Data
                        $script:Controls.StatusLabel.Text="Concluídos: $($r.Success) • Falhas: $($r.Failed) • Ignorados: $($r.Skipped)."
                        Add-UiLog $script:Controls.StatusLabel.Text
                        Add-UiLog "Backup: $($r.BackupPath)"
                        $script:Controls.WorkProgress.Value=100
                    }
                    Restore {
                        $script:Controls.StatusLabel.Text="Ajustes restaurados: $($event.Data.Restored) • Falhas: $($event.Data.Failed)."
                        Add-UiLog $script:Controls.StatusLabel.Text
                    }
                }
            }
        }
        $event=$null
    }
}

$script:Timer=New-Object Windows.Threading.DispatcherTimer
$script:Timer.Interval=[TimeSpan]::FromMilliseconds(150)
$script:Timer.add_Tick({
    Receive-UiEvents
    if ($script:Job -and $script:Job.Handle.IsCompleted) {
        try {
            $null=$script:Job.PowerShell.EndInvoke($script:Job.Handle)
            Receive-UiEvents
            foreach ($errorRecord in $script:Job.PowerShell.Streams.Error) { Add-UiLog $errorRecord.ToString() 'Error' }
        } catch { Add-UiLog $_.Exception.Message 'Error'; $script:Controls.StatusLabel.Text='Operação interrompida. Consulte o registro.' }
        finally {
            $script:Timer.Stop()
            $script:Job.PowerShell.Dispose(); $script:Job.Runspace.Dispose(); $script:Job=$null
            Set-UiBusy $false
        }
    }
})
$script:Controls.CategoryList.add_SelectionChanged({Update-Filter})
$script:Controls.SearchBox.add_TextChanged({Update-Filter})
$script:Controls.RecommendedButton.add_Click({foreach($option in $script:Options){$option.Selected=$option.Recommended}})
$script:Controls.ScanButton.add_Click({Start-UiOperation 'Scan'})
$script:Controls.PreviewButton.add_Click({Start-UiOperation 'Preview' @($script:Options | Where-Object Selected | ForEach-Object Id)})
$script:Controls.ApplyButton.add_Click({
    $selected=@($script:Options | Where-Object Selected)
    $text="Aplicar estas opções?`n`n" + (($selected.Title | ForEach-Object { "• $_" }) -join "`n") + "`n`nAplicativos, arquivos excluídos e reparos do SFC não são desfeitos pelo backup de ajustes."
    if (-not $script:Controls.RestorePointCheck.IsChecked) { $text+="`n`nVocê desmarcou a criação do ponto de restauração." }
    if ([Windows.MessageBox]::Show($script:Window,$text,'Revisar seleção','YesNo','Question') -eq 'Yes') { Start-UiOperation 'Apply' @($selected.Id) }
})
$script:Controls.RestoreButton.add_Click({
    try {
        $pending = @(Get-DebloatBackups | Where-Object {
            $j=Get-Content -LiteralPath $_.FullName -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json
            @($j.Entries | Where-Object { -not $_.Restored }).Count -gt 0
        })
        if (-not $pending.Count) { Add-UiLog 'Nenhum backup de ajustes pendente para restaurar.'; return }
        $backup=$pending[0]
        if ([Windows.MessageBox]::Show($script:Window,"Restaurar os valores salvos em $($backup.Name)?`n`nSomente registro, serviços e energia serão restaurados.",'Restaurar último backup','YesNo','Question') -eq 'Yes') { Start-UiOperation -Mode Restore -BackupPath $backup.FullName }
    } catch { Add-UiLog $_.Exception.Message 'Error' }
})
$script:Controls.OpenLogsButton.add_Click({
    try { $path=Get-DebloatDataPath; $null=[IO.Directory]::CreateDirectory($path); Start-Process explorer.exe -ArgumentList ('"{0}"' -f $path) }
    catch { Add-UiLog $_.Exception.Message 'Error' }
})
$script:Controls.SaveLogButton.add_Click({
    $dialog=New-Object Microsoft.Win32.SaveFileDialog
    $dialog.Filter='Arquivo de texto (*.log)|*.log'
    $dialog.FileName='Win11Debloat.log'
    if ($dialog.ShowDialog($script:Window)) {
        try { [IO.File]::WriteAllText($dialog.FileName,$script:Controls.LogBox.Text,(New-Object Text.UTF8Encoding($true))) }
        catch { Add-UiLog $_.Exception.Message 'Error' }
    }
})
$script:Window.add_Closing({
    param($sender,$eventArgs)
    if ($script:Busy) {
        $eventArgs.Cancel=$true
        $null=[Windows.MessageBox]::Show($script:Window,'Aguarde a operação terminar antes de fechar.','Operação em andamento','OK','Information')
    }
})
Update-Selection
Add-UiLog 'Pronto. Escolha as opções ou use Analisar para identificar aplicativos.'
if ($SmokeTest) {
    # Exercise actual WPF bindings, filters and background runspace without changing Windows.
    if ($script:Options.Count -ne @(Get-DebloatCatalog).Count) { throw 'Catálogo incompleto na GUI.' }
    $script:Options[0].Selected=$true
    if ($script:Controls.SelectionCount.Text -ne '1 opção') { throw 'Binding de seleção não atualizou.' }
    $script:Controls.SearchBox.Text='___no_matches___'
    if (@($script:View).Count -ne 0) { throw 'Filtro não funcionou.' }
    $script:Controls.SearchBox.Text=''
    Start-UiOperation 'Preview' @($script:Options[0].Id)
    $deadline=(Get-Date).AddSeconds(30)
    while ($script:Busy -and (Get-Date) -lt $deadline) {
        $frame=New-Object Windows.Threading.DispatcherFrame
        $null=$script:Window.Dispatcher.BeginInvoke([Windows.Threading.DispatcherPriority]::Background,[Action]{$frame.Continue=$false})
        [Windows.Threading.Dispatcher]::PushFrame($frame)
        Start-Sleep -Milliseconds 20
    }
    if ($script:Busy -or $script:Controls.StatusLabel.Text -notlike 'Simulação concluída*') { throw 'Worker da simulação não concluiu.' }
    # Render the actual native window for visual review on the Windows CI runner.
    $script:Window.Show()
    $script:Window.UpdateLayout()
    $visual=$script:Window.Content
    $bitmap=New-Object Windows.Media.Imaging.RenderTargetBitmap ([int]$visual.ActualWidth),([int]$visual.ActualHeight),96,96,([Windows.Media.PixelFormats]::Pbgra32)
    $bitmap.Render($visual)
    $encoder=New-Object Windows.Media.Imaging.PngBitmapEncoder
    $encoder.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($bitmap))
    $stream=[IO.File]::Create((Join-Path (Split-Path -Parent $PSScriptRoot) 'gui-smoke.png'))
    try { $encoder.Save($stream) } finally { $stream.Dispose() }
    $script:Window.Close()
    Write-Output 'WPF smoke test passed.'
    return
}
try {
    $logPath=Join-Path (Get-DebloatDataPath) 'Logs'
    $null=[IO.Directory]::CreateDirectory($logPath)
    $script:PersistentLog=Join-Path $logPath ((Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8) + '.log')
    $script:Controls.LogBox.Text | Set-Content -LiteralPath $script:PersistentLog -Encoding UTF8
} catch { Add-UiLog 'Registro em disco indisponível. Você ainda pode usar Salvar registro.' 'Warning' }
$null=$script:Window.ShowDialog()
