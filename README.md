# Win11 Debloat — interface WPF

Ferramenta local de ajustes do Windows 10/11 de 64 bits, escrita em PowerShell 5.1, com interface gráfica nativa em português. A versão 3.0 separa o catálogo de ações, a execução e a interface.

> Versão em revisão. Os testes automatizados usam operações de sistema simuladas. Valide os ajustes reais em uma máquina virtual Windows com snapshot antes de usar em produção. Não há promessa de aumento de FPS ou de eliminação completa da telemetria.

## Abrir a interface

1. Baixe o ZIP **da branch que você quer testar** pelo botão **Code → Download ZIP**, ou clone o repositório.
2. Extraia **todos os arquivos** para uma pasta local.
3. Abra `Start-Debloat.cmd` e aceite a solicitação de administrador.
4. Use **Analisar** para identificar Windows e aplicativos. Selecione as opções, use **Simular** e revise antes de **Aplicar seleção**.

Também é possível iniciar pelo Windows PowerShell:

```powershell
powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File .\win11debloater.ps1
```

A política Bypass vale somente para esse processo. Não é necessário instalar Python, Node, Electron ou PowerShell 7. A interface usa WPF do .NET Framework incluído no Windows. Baixe e revise os arquivos locais; os atalhos antigos que executavam URLs encurtadas foram removidos.

Se o UAC solicitar credenciais de **outro usuário**, os ajustes HKCU e a remoção de aplicativos afetarão essa outra conta. Execute a partir da conta administrativa que deseja configurar. Em computadores gerenciados, políticas da organização podem prevalecer.

## O que a interface oferece

- Categorias de privacidade, aplicativos, serviços, desempenho e manutenção, com busca.
- Seleção individual persistente ao trocar de categoria; nenhum ajuste selecionado ao abrir.
- **Perfil básico**: marca somente diagnóstico opcional e anúncios/sugestões.
- **Simular**: mostra as ações planejadas sem alterar registro, serviços, aplicativos ou criar backup/ponto de restauração. Não verifica a aplicabilidade de cada política.
- Execução em runspace separado, progresso por opção e registros de sucesso, falha e itens ignorados. Um mutex impede aplicações/restaurações simultâneas, inclusive em outras janelas.
- Ponto de restauração marcado por padrão na GUI. Se não for possível confirmar sua criação, a execução é interrompida. Verifique a Proteção do Sistema; o Windows limita a frequência de criação. Desmarcar essa opção exige revisar a confirmação.
- Backup persistente dos valores originais de registro, dos serviços e do plano de energia, gravado **antes** das alterações.
- Restauração do último backup pendente. Restaure sessões da mais recente para a mais antiga.

## Correções em relação à versão 2.1

| Função anterior | Comportamento revisado |
| --- | --- |
| Backup de chaves em pastas temporárias | Diário por execução, tipos e valores originais, escrita atômica e falha de backup interrompendo alterações |
| Restaurar serviços como Automático | Restaura Manual/Automático/Desativado, inicialização atrasada e estado anterior |
| Privacidade gravando textos como DWORD | Cada valor declara seu tipo; valores ausentes são removidos ao restaurar |
| Remover apps por correspondência ampla para todos | Catálogo com nomes exatos, seleção por aplicativo e remoção só da conta atual; provisionamento preservado |
| Desabilitar Edge e seus atualizadores | Ajustes apenas de segundo plano e inicialização acelerada; mantém Edge, WebView2 e atualizações |
| Desabilitar muitos serviços de uma vez | Opções explícitas para mapas offline e Xbox Live, com descrição do impacto |
| “Desempenho” alterando prioridade e hibernação | Animações e plano de energia separados e reversíveis; sem alterar prioridade de CPU ou hibernação |
| Limpeza do cache do Windows Update | Limpa apenas arquivos antigos do TEMP do usuário; não interrompe o Windows Update |
| Mensagens de sucesso de comandos externos | Verifica códigos de saída e reporta falhas; preserva saída do SFC |
| Menu de terminal obrigatório | GUI por padrão; catálogo, execução e restauração também disponíveis por linha de comando |

Defender, Firewall, Windows Update, Microsoft Store, App Installer, Terminal, câmera, captura de tela, serviços de busca e impressão ficam fora do catálogo de remoções. Não há encerramento forçado de processos do Edge nem downloads executados pelo programa.

## Linha de comando

Execute aplicação/restauração em **Windows PowerShell 5.1 de 64 bits como administrador**. A simulação e a listagem não exigem elevação. A CLI respeita `-WhatIf` e `-Confirm`.

```powershell
# Consultar os IDs disponíveis (também funciona sem Windows)
.\win11debloater.ps1 -List

# Simular duas opções sem alterar o sistema
.\win11debloater.ps1 -Console -Action telemetry,ads -WhatIf

# Aplicar com ponto de restauração verificado e backup dos ajustes
.\win11debloater.ps1 -Console -Action telemetry,ads -CreateRestorePoint

# Desfazer um backup de ajustes da conta e computador atuais
.\win11debloater.ps1 -Console -RestoreBackup "$env:LOCALAPPDATA\Win11Debloat\Backups\NOME.json"
```

Sem `-Action`, `-Console` mostra o catálogo. A CLI só cria ponto de restauração quando `-CreateRestorePoint` é informado; os backups de ajustes são obrigatórios em toda aplicação. O SFC e algumas APIs do Windows podem exigir execução no Windows PowerShell, mesmo que a lógica de simulação seja compatível com PowerShell 7.

## Limites da restauração

Backups e registros ficam em `%LOCALAPPDATA%\Win11Debloat`. O botão **Abrir backups e registros** abre essa pasta. Guarde os arquivos JSON se quiser desfazer ajustes. O backup contém nome do computador e SID do usuário para evitar restauração na conta errada.

- **Registro:** recupera valor e tipo anteriores; exclui valores que não existiam. Chaves criadas podem permanecer vazias.
- **Serviços:** restaura o modo e o estado observados antes da ação. Alguns serviços podem recusar parada ou inicialização; a falha aparece no registro.
- **Energia:** restaura o GUID do plano anterior, se ele ainda existir.
- **Aplicativos, arquivos e SFC:** não são desfeitos por esse backup. Reinstale aplicativos pela Store. Um ponto de restauração também não substitui um backup dos arquivos pessoais.

A ferramenta não garante compatibilidade com cada versão, edição, política corporativa ou personalização de Windows. Aplicar um valor de política com sucesso não confirma que a edição do Windows irá respeitá-lo. Para desfazer ajustes feitos pela antiga versão 2.1, use o backup/ponto daquela execução; a 3.0 não inventa valores anteriores que não foram salvos.

## Desenvolvimento e validação

```powershell
# Parser, catálogo e regressões de aplicação/restauração sem alterar o Windows
.\tests\Run-Tests.ps1

# Somente no Windows: carregar XAML, testar bindings, filtros e worker de simulação
powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File .\src\Debloat.Gui.ps1 -SmokeTest
```

O teste `Windows-Registry.Tests.ps1` verifica a API real de registro somente em uma chave HKCU descartável, removida ao final, sem alterar políticas ou serviços.

O teste WPF gera `gui-smoke.png` a partir da janela nativa, sem executar ajustes reais. O workflow **Windows PowerShell and WPF** roda os testes em Windows PowerShell 5.1 e PowerShell em Linux e guarda a captura da interface como artefato. Ele não valida alterações reais em Windows.

Estrutura: `src/Debloat.Core.psm1` contém ações e backups; `ui/MainWindow.xaml`, o layout; `src/Debloat.Gui.ps1`, os eventos e o worker; `win11debloater.ps1`, o ponto de entrada.

Antes de uma versão estável, teste em VM: aplicação e restauração de cada opção, conta administrativa e UAC cancelado, falta de espaço no backup, Proteção do Sistema desativada, serviço ausente, aplicativo em uso e escalas de tela de 100%, 150% e 200%.

## Créditos e licença

Projeto de [Matheus-TestUser1](https://github.com/Matheus-TestUser1). A versão original usou partes de [teeotsa/windows-11-debloat](https://github.com/teeotsa/windows-11-debloat), modificadas pelo autor. Código distribuído sob a GPL-3.0 conforme o arquivo [LICENSE](LICENSE).
