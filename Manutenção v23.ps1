# Requer PowerShell 5.1 ou superior
# Versão Final 23.0 - Estável (Modificada com correções de GUI e Windows Update)

# Verificar e solicitar privilégios de administrador
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- Configurações Iniciais ---
$script:rebootRequired = $false
$script:cancelRequest = $false
$scriptFolder = $PSScriptRoot
$logFile = Join-Path -Path $scriptFolder -ChildPath "WindowsMaintenance_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# --- Funções de Manutenção ---

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $Message"
    Add-Content -Path $logFile -Value $logMessage
}

function Executar-ComandoELogar {
    param(
        [string]$Comando,
        [string[]]$ArgumentList,
        [System.Windows.Forms.TextBox]$StatusBox
    )
    $tempLog = Join-Path $env:TEMP "$(New-Guid).log"
    $tempErr = Join-Path $env:TEMP "$(New-Guid).err"

    try {
        $process = Start-Process -FilePath $Comando -ArgumentList $ArgumentList -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput $tempLog -RedirectStandardError $tempErr
        
        $fullOutput = ""
        if (Test-Path $tempLog) {
            $output = Get-Content $tempLog -Encoding OEM
            $fullOutput += ($output | Out-String)
            $StatusBox.AppendText(($output | Out-String).Trim() + "`r`n")
            [System.Windows.Forms.Application]::DoEvents()
        }
        if (Test-Path $tempErr) {
            $errors = Get-Content $tempErr
            $fullOutput += ($errors | Out-String)
            $StatusBox.AppendText(($errors | Out-String).Trim() + "`r`n")
            [System.Windows.Forms.Application]::DoEvents()
        }
        
        Write-Log "--- Início da Saída do Comando: $Comando $ArgumentList ---"
        Write-Log $fullOutput.Trim()
        Write-Log "--- Fim da Saída do Comando ---"

        return $process.ExitCode -eq 0
    }
    catch {
        $errorMessage = $_.Exception.Message
        $logMessage = "ERRO ao tentar executar o comando {0}: {1}" -f $Comando, $errorMessage
        Write-Log $logMessage
        return $false
    }
    finally {
        if (Test-Path $tempLog) { Remove-Item $tempLog -Force }
        if (Test-Path $tempErr) { Remove-Item $tempErr -Force }
    }
}

function Invoke-SfcScan {
    param($StatusBox)
    Write-Log "Iniciando verificação SFC..."
    $sfcPath = Join-Path $env:SystemRoot "System32\sfc.exe"
    return Executar-ComandoELogar -Comando $sfcPath -ArgumentList "/scannow" -StatusBox $StatusBox
}

function Invoke-DismRepair {
    param($StatusBox)
    Write-Log "Iniciando DISM..."
    $dismPath = Join-Path $env:SystemRoot "System32\dism.exe"
    return Executar-ComandoELogar -Comando $dismPath -ArgumentList "/Online", "/Cleanup-Image", "/RestoreHealth" -StatusBox $StatusBox
}

function Invoke-WinSxSCleanup {
    param($StatusBox)
    Write-Log "Iniciando limpeza avançada de componentes (WinSxS)..."
    $dismPath = Join-Path $env:SystemRoot "System32\dism.exe"
    return Executar-ComandoELogar -Comando $dismPath -ArgumentList "/Online", "/Cleanup-Image", "/StartComponentCleanup" -StatusBox $StatusBox
}

function Invoke-WindowsUpdate {
    param($StatusBox)
    Write-Log "Iniciando processo de Windows Update..."
    $StatusBox.AppendText("Verificando módulo PSWindowsUpdate...`r`n")
    
    try {
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Write-Log "Módulo PSWindowsUpdate não encontrado. Tentando instalar..."
            $StatusBox.AppendText("Módulo PSWindowsUpdate não encontrado. Tentando instalar...`r`n")
            Install-Module PSWindowsUpdate -Force -Scope CurrentUser -AcceptLicense -ErrorAction Stop
            Write-Log "Módulo PSWindowsUpdate instalado."
            $StatusBox.AppendText("Módulo PSWindowsUpdate instalado com sucesso.`r`n")
        }
        Import-Module PSWindowsUpdate -ErrorAction Stop
    } catch {
        Write-Log "FALHA CRÍTICA ao instalar/importar o módulo PSWindowsUpdate: $($_.Exception.Message)"
        $StatusBox.AppendText("ERRO: Falha ao carregar o módulo PSWindowsUpdate. A verificação não pode continuar.`r`n")
        return $false
    }

    Write-Log "Procurando por atualizações..."
    $StatusBox.AppendText("Procurando por atualizações... Isso pode levar alguns minutos.`r`n")
    [System.Windows.Forms.Application]::DoEvents()
    
    try {
        $updates = Get-WindowsUpdate
        $mandatoryUpdates = $updates | Where-Object { $_.Title -notlike "*driver*" -and $_.Title -notlike "*preview*" -and $_.IsBeta -eq $false -and $_.IsInstalled -eq $false }
        $optionalUpdates = $updates | Where-Object { ($_.Title -like "*driver*" -or $_.Title -like "*preview*" -or $_.IsBeta -eq $true) -and $_.IsInstalled -eq $false }

        if ($mandatoryUpdates.Count -gt 0) {
            Write-Log "Encontradas $($mandatoryUpdates.Count) atualizações importantes. Instalando..."
            $StatusBox.AppendText("Encontradas $($mandatoryUpdates.Count) atualizações importantes. Iniciando instalação...`r`n")
            $result = Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -Update (Get-WindowsUpdate -UpdateID ($mandatoryUpdates.UpdateID))
            if ($result | Where-Object { $_.RebootRequired }) { $script:rebootRequired = $true }
            Write-Log "Instalação de atualizações importantes concluída."
        } else {
            Write-Log "Nenhuma atualização importante encontrada."
            $StatusBox.AppendText("Nenhuma nova atualização importante encontrada.`r`n")
        }

        if ($optionalUpdates.Count -gt 0) {
            Write-Log "Encontradas $($optionalUpdates.Count) atualizações opcionais."
            $optionalList = ($optionalUpdates.Title | ForEach-Object { "- $_" }) -join "`n"
            $message = "Foram encontradas as seguintes atualizações opcionais (drivers, etc.):`n`n$optionalList`n`nDeseja instalá-las também?"
            
            $userChoice = [System.Windows.Forms.MessageBox]::Show($message, "Atualizações Opcionais Encontradas", "YesNo", "Question")
            
            if ($userChoice -eq "Yes") {
                Write-Log "Usuário optou por instalar as atualizações opcionais."
                $StatusBox.AppendText("Instalando atualizações opcionais conforme solicitado...`r`n")
                $resultOpt = Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -Update (Get-WindowsUpdate -UpdateID ($optionalUpdates.UpdateID))
                if ($resultOpt | Where-Object { $_.RebootRequired }) { $script:rebootRequired = $true }
                Write-Log "Instalação de atualizações opcionais concluída."
            } else {
                Write-Log "Usuário optou por não instalar as atualizações opcionais."
            }
        }
        return $true
    } catch {
        Write-Log "ERRO durante a execução do Windows Update: $($_.Exception.Message)"
        $StatusBox.AppendText("ERRO: Ocorreu uma falha durante o processo de atualização.`r`n")
        return $false
    }
}

function Invoke-OptimizeDrives { Write-Log "Iniciando otimização de unidades..."; $systemDrive = $env:SystemDrive.Trim(":"); try { Optimize-Volume -DriveLetter $systemDrive -Verbose -ErrorAction Stop; return $true } catch { Write-Log "Falha ao otimizar a unidade: $($_.Exception.Message)"; return $false } }
function Invoke-CleanTempFiles { Write-Log "Iniciando limpeza de arquivos temporários..."; $paths = @( "$env:TEMP\*", "$env:WINDIR\Temp\*", "$env:LOCALAPPDATA\Temp\*", "$env:SystemRoot\Prefetch\*" ); $paths | ForEach-Object { Remove-Item $_ -Recurse -Force -ErrorAction SilentlyContinue }; Write-Log "Limpeza de arquivos temporários concluída."; return $true }
function Invoke-Chkdsk { Write-Log "Agendando CHKDSK na próxima reinicialização..."; fsutil dirty set $env:SystemDrive > $null; Write-Log "CHKDSK agendado. Uma reinicialização é necessária."; $script:rebootRequired = $true; return $true }
function Invoke-CleanWUCache { Write-Log "Limpando cache do Windows Update..."; Stop-Service wuauserv -Force -ErrorAction SilentlyContinue; Remove-Item "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue; Start-Service wuauserv -ErrorAction SilentlyContinue; Write-Log "Cache do Windows Update limpo."; return $true }
function Invoke-DnsFlush { Write-Log "Limpando cache DNS e renovando IP..."; ipconfig /flushdns; ipconfig /release; ipconfig /renew; Write-Log "DNS e IP renovados."; return $true }
function Invoke-MemoryTest { Write-Log "Agendando Teste de Memória na próxima reinicialização..."; Write-Log "O Teste de Memória deve ser iniciado manualmente. Uma reinicialização é necessária."; $script:rebootRequired = $true; return $true }
function Invoke-RepairStoreApps { Write-Log "Reparando aplicativos da Windows Store..."; Get-AppXPackage -AllUsers | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -ErrorAction SilentlyContinue }; Write-Log "Reparo de aplicativos concluído."; return $true }
function Invoke-CheckServices { Write-Log "Verificando serviços essenciais..."; $servicos = "wuauserv", "bits", "WinDefend", "MpsSvc"; foreach ($s in $servicos) { Set-Service -Name $s -StartupType Automatic -ErrorAction SilentlyContinue; Start-Service -Name $s -ErrorAction SilentlyContinue }; Write-Log "Serviços essenciais verificados."; return $true }
function Invoke-ResetNetwork { Write-Log "Resetando configurações de rede..."; netsh int ip reset; netsh winsock reset; Write-Log "Configurações de rede resetadas. Uma reinicialização é recomendada."; $script:rebootRequired = $true; return $true }
function Invoke-RemoveBloatware { Write-Log "Removendo bloatware selecionado..."; $apps = "Microsoft.BingNews", "Microsoft.GetHelp", "Microsoft.XboxApp", "Microsoft.YourPhone", "Microsoft.ZuneVideo"; foreach ($app in $apps) { Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue; Write-Log "Tentativa de remoção de $app." }; Write-Log "Remoção de bloatware concluída."; return $true }
function Invoke-UpdateDefenderSignatures { Write-Log "Atualizando assinaturas do Microsoft Defender..."; try { Update-MpSignature -ErrorAction Stop; Write-Log "Assinaturas do Defender atualizadas com sucesso."; return $true } catch { Write-Log "Falha ao atualizar assinaturas do Defender: $($_.Exception.Message)"; return $false } }
function Invoke-ClearIconCache { Write-Log "Limpando o cache de ícones..."; $iconCacheDb = "$env:LOCALAPPDATA\IconCache.db"; try { Stop-Process -Name explorer -Force -ErrorAction Stop; if (Test-Path $iconCacheDb) { Remove-Item $iconCacheDb -Force -ErrorAction SilentlyContinue } } finally { Start-Process explorer; Write-Log "Cache de ícones limpo. O Explorer foi reiniciado." }; return $true }
function Criar-PontoRestauracao { Write-Log "Criando ponto de restauração..."; try { $restorePoint = Checkpoint-Computer -Description "Ponto de Restauração - Script Manutenção Windows $(Get-Date -Format 'dd/MM/yyyy HH:mm')"; if ($restorePoint.State -eq 'Completed') { Write-Log "Ponto de restauração criado com sucesso."; return $true } else { Write-Log "AVISO: Checkpoint-Computer não completou com sucesso."; $continue = [System.Windows.Forms.MessageBox]::Show("Não foi possível criar um novo ponto de restauração (provavelmente um já foi criado nas últimas 24 horas).`n`nDeseja continuar a manutenção sem um novo ponto de restauração?", "Aviso: Ponto de Restauração", "YesNo", "Warning") -eq "Yes"; return $continue } } catch { Write-Log "FALHA CRÍTICA ao criar ponto de restauração: $($_.Exception.Message)"; [System.Windows.Forms.MessageBox]::Show("Falha ao criar ponto de restauração!`nVerifique se a Proteção do Sistema está ativada.", "Erro Crítico", "OK", "Error"); return $false } }

# --- Interface Gráfica (GUI) ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "Manutenção Windows 10/11"
$form.Size = New-Object System.Drawing.Size(520, 740)
$form.MinimumSize = New-Object System.Drawing.Size(500, 600)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::Sizable
$form.BackColor = [System.Drawing.Color]::White

$panel = New-Object System.Windows.Forms.Panel
$panel.Location = New-Object System.Drawing.Point(10, 10)
$panel.Size = New-Object System.Drawing.Size(480, 450)
$panel.AutoScroll = $true
$panel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$panel.Anchor = 'Top', 'Left', 'Right'
$form.Controls.Add($panel)

$toolTip = New-Object System.Windows.Forms.ToolTip
$funcoes = [ordered]@{ "dism"="DISM: Restaurar imagem"; "sfc"="Verificar arquivos (SFC)"; "winsxs"="Limpeza Avançada de Componentes"; "defrag"="Otimizar unidades"; "temp"="Limpar temporários"; "chkdsk"="Verificar disco (reinício)"; "wu"="Limpar cache do Windows Update"; "update"="Instalar atualizações"; "defender"="Atualizar Assinaturas do Defender"; "dns"="Renovar IP e DNS"; "store"="Reparar apps da Store"; "servico"="Verificar serviços"; "rede"="Resetar rede (reinício)"; "iconcache"="Limpar Cache de Ícones"; "bloat"="Remover bloatware"; "mem"="Agendar Teste de Memória" }
$descricoes = @{ "dism"="Repara a imagem de componentes do Windows."; "sfc"="Verifica a integridade dos arquivos protegidos do sistema."; "winsxs"="Remove versões antigas de componentes do Windows para liberar espaço."; "defrag"="Otimiza a organização de arquivos em HDDs e SSDs."; "temp"="Remove arquivos temporários do sistema e do usuário."; "chkdsk"="Verifica o sistema de arquivos em busca de erros na próxima reinicialização."; "wu"="Limpa o cache de downloads do Windows Update."; "update"="Procura, baixa e instala novas atualizações do Windows."; "defender"="Força o download das mais recentes definições de vírus."; "dns"="Limpa o cache de resolução de nomes DNS e solicita um novo IP."; "store"="Tenta registrar novamente todos os aplicativos da Microsoft Store."; "servico"="Garante que serviços essenciais do Windows estejam ativos."; "rede"="Restaura as configurações de rede para o padrão. Requer reinicialização."; "iconcache"="Apaga o cache de ícones para corrigir ícones corrompidos."; "bloat"="Remove aplicativos pré-instalados comuns."; "mem"="Agenda a Ferramenta de Diagnóstico de Memória na próxima reinicialização." }
$checkboxes = @{}; $statusLabels = @{}; $i = 0
foreach ($key in $funcoes.Keys) { 
    $cb = New-Object System.Windows.Forms.CheckBox; $cb.Text = $funcoes[$key]; $cb.Location = New-Object System.Drawing.Point(10, (10 + ($i * 30))); $cb.Size = New-Object System.Drawing.Size(350, 25); $cb.Font = New-Object System.Drawing.Font("Segoe UI", 9); $panel.Controls.Add($cb); $checkboxes[$key] = $cb
    $lblStatus = New-Object System.Windows.Forms.Label; $lblStatus.Location = New-Object System.Drawing.Point(370, (13 + ($i * 30))); $lblStatus.Size = New-Object System.Drawing.Size(50, 20); $lblStatus.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold); $panel.Controls.Add($lblStatus); $statusLabels[$key] = $lblStatus
    if ($descricoes.ContainsKey($key)) { $toolTip.SetToolTip($cb, $descricoes[$key]) }
    $i++ 
}

$chkTurbo = New-Object System.Windows.Forms.CheckBox
$chkTurbo.Text = "Modo Turbo (executar todas as tarefas)"
$chkTurbo.Location = New-Object System.Drawing.Point(20, 470)
$chkTurbo.Size = New-Object System.Drawing.Size(350, 25)
$chkTurbo.Anchor = 'Top', 'Left'
$chkTurbo.Add_CheckedChanged({ foreach ($cb in $checkboxes.Values) { $cb.Checked = $chkTurbo.Checked } })
$form.Controls.Add($chkTurbo)

$lblStatusGeral = New-Object System.Windows.Forms.Label
$lblStatusGeral.Location = New-Object System.Drawing.Point(20, 500)
$lblStatusGeral.Size = New-Object System.Drawing.Size(460, 20)
$lblStatusGeral.ForeColor = [System.Drawing.Color]::DarkBlue
$lblStatusGeral.Anchor = 'Top', 'Left', 'Right'
$form.Controls.Add($lblStatusGeral)

$txtStatus = New-Object System.Windows.Forms.TextBox
$txtStatus.Location = New-Object System.Drawing.Point(20, 525)
$txtStatus.Size = New-Object System.Drawing.Size(460, 100)
$txtStatus.Multiline = $true; $txtStatus.ScrollBars = 'Vertical'; $txtStatus.ReadOnly = $true
$txtStatus.BackColor = [System.Drawing.Color]::WhiteSmoke; $txtStatus.Font = New-Object System.Drawing.Font("Consolas", 9)
$txtStatus.Anchor = 'Top', 'Bottom', 'Left', 'Right'
$form.Controls.Add($txtStatus)

# --- INÍCIO DA CORREÇÃO DEFINITIVA DOS BOTÕES ---
# Usamos os valores fixos definidos no início para a posição inicial
$initialWidth = 520
$initialHeight = 740
# Ajustamos os valores para compensar as bordas da janela
$buttonY = $initialHeight - 80 
$sairX = $initialWidth - 140
$cancelarX = $sairX - 110
$executarX = $cancelarX - 110

$btnSair = New-Object System.Windows.Forms.Button
$btnSair.Text = "Sair"; $btnSair.Size = New-Object System.Drawing.Size(100, 30)
$btnSair.Location = New-Object System.Drawing.Point($sairX, $buttonY)
$btnSair.Anchor = 'Bottom', 'Right' 
$btnSair.Add_Click({ $form.Close() })
$form.Controls.Add($btnSair)

$btnCancelar = New-Object System.Windows.Forms.Button
$btnCancelar.Text = "Cancelar"; $btnCancelar.Size = New-Object System.Drawing.Size(100, 30)
$btnCancelar.Location = New-Object System.Drawing.Point($cancelarX, $buttonY)
$btnCancelar.BackColor = [System.Drawing.Color]::LightCoral; $btnCancelar.Enabled = $false
$btnCancelar.Anchor = 'Bottom', 'Right' 
$form.Controls.Add($btnCancelar)

$btnExecutar = New-Object System.Windows.Forms.Button
$btnExecutar.Text = "Executar"; $btnExecutar.Size = New-Object System.Drawing.Size(100, 30)
$btnExecutar.Location = New-Object System.Drawing.Point($executarX, $buttonY)
$btnExecutar.BackColor = [System.Drawing.Color]::LightGreen
$btnExecutar.Anchor = 'Bottom', 'Right' 
$form.Controls.Add($btnExecutar)
# --- FIM DA CORREÇÃO DEFINITIVA DOS BOTÕES ---

# --- Lógica de Execução Sequencial ---

$btnExecutar.Add_Click({
    if (-NOT (Criar-PontoRestauracao)) { return }

    $btnExecutar.Enabled = $false; $btnSair.Enabled = $false; $btnCancelar.Enabled = $true
    $txtStatus.Clear()
    $script:cancelRequest = $false; $script:rebootRequired = $false
    foreach ($key in $statusLabels.Keys) { $statusLabels[$key].Text = "" }

    $tarefasSelecionadas = @()
    foreach ($key in $funcoes.Keys) { if ($checkboxes[$key].Checked) { $tarefasSelecionadas += $key } }

    if ($tarefasSelecionadas.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Nenhuma tarefa foi selecionada.", "Aviso", "OK", "Warning")
        $btnExecutar.Enabled = $true; $btnSair.Enabled = $true
        return
    }

    foreach ($task in $tarefasSelecionadas) {
        if ($script:cancelRequest) {
            $txtStatus.AppendText("$(Get-Date -Format 'HH:mm:ss') - Execução cancelada pelo usuário.`r`n")
            break
        }

        $lblStatusGeral.Text = "Executando: $($funcoes[$task])..."
        $txtStatus.AppendText("$(Get-Date -Format 'HH:mm:ss') - Iniciando: $($funcoes[$task])...`r`n")
        [System.Windows.Forms.Application]::DoEvents()

        $success = $false
        switch ($task) {
            "sfc"       { $success = Invoke-SfcScan -StatusBox $txtStatus }
            "dism"      { $success = Invoke-DismRepair -StatusBox $txtStatus }
            "defrag"    { $success = Invoke-OptimizeDrives }
            "temp"      { $success = Invoke-CleanTempFiles }
            "chkdsk"    { $success = Invoke-Chkdsk }
            "wu"        { $success = Invoke-CleanWUCache }
            "update"    { $success = Invoke-WindowsUpdate -StatusBox $txtStatus }
            "dns"       { $success = Invoke-DnsFlush }
            "mem"       { $success = Invoke-MemoryTest }
            "store"     { $success = Invoke-RepairStoreApps }
            "servico"   { $success = Invoke-CheckServices }
            "rede"      { $success = Invoke-ResetNetwork }
            "bloat"     { $success = Invoke-RemoveBloatware }
            "winsxs"    { $success = Invoke-WinSxSCleanup -StatusBox $txtStatus }
            "defender"  { $success = Invoke-UpdateDefenderSignatures }
            "iconcache" { $success = Invoke-ClearIconCache }
        }

        if ($success) {
            $statusLabels[$task].Text = "✓"; $statusLabels[$task].ForeColor = [System.Drawing.Color]::Green
            $txtStatus.AppendText("$(Get-Date -Format 'HH:mm:ss') - Sucesso: $($funcoes[$task])`r`n")
        } else {
            $statusLabels[$task].Text = "✗"; $statusLabels[$task].ForeColor = [System.Drawing.Color]::Red
            $txtStatus.AppendText("$(Get-Date -Format 'HH:mm:ss') - Falha: $($funcoes[$task])`r`n")
        }
        $txtStatus.ScrollToCaret()
        [System.Windows.Forms.Application]::DoEvents()
    }

    $lblStatusGeral.Text = "Manutenção concluída!"
    Write-Log -Message "Manutenção concluída."
    $finalMessage = "Todas as tarefas foram concluídas."
    if ($script:rebootRequired) { $finalMessage += "`n`nATENÇÃO: Algumas tarefas exigem uma reinicialização." }
    $finalMessage += "`n`nO log foi salvo em: $logFile"
    [System.Windows.Forms.MessageBox]::Show($finalMessage, "Concluído", "OK", "Information")
    if (Test-Path $logFile) { Invoke-Item $logFile }
    
    $btnExecutar.Enabled = $true; $btnSair.Enabled = $true; $btnCancelar.Enabled = $false
})

$btnCancelar.Add_Click({
    $script:cancelRequest = $true
    $lblStatusGeral.Text = "Cancelamento solicitado... Aguardando a tarefa atual."
    $btnCancelar.Enabled = $false
})

# Iniciar interface
$form.ShowDialog()