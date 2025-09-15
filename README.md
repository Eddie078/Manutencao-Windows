# 🔧 Utilitário de Manutenção para Windows

Um script PowerShell completo com interface gráfica (GUI) para realizar uma vasta gama de tarefas de manutenção, limpeza e reparo em sistemas operacionais Windows 10 e 11.

## 🎯 Objetivo

Este projeto centraliza as ferramentas de manutenção mais importantes do Windows em uma interface única e fácil de usar. O objetivo é automatizar e simplificar o processo de otimização do sistema, tanto para usuários comuns quanto para técnicos.



---

## ✨ Funcionalidades

O script oferece uma seleção de tarefas que podem ser executadas individualmente ou todas de uma vez através do **"Modo Turbo"**.

* **Reparo de Imagem (DISM):** Repara a imagem de componentes do Windows, essencial para corrigir problemas de corrupção.
* **Verificação de Arquivos (SFC):** Executa o `sfc /scannow` para verificar a integridade de todos os arquivos protegidos do sistema.
* **Limpeza Avançada (WinSxS):** Remove versões antigas de componentes do Windows para liberar espaço em disco.
* **Instalar Atualizações:** Procura, baixa e instala atualizações importantes do Windows (requer o módulo `PSWindowsUpdate`, que o script tenta instalar automaticamente).
* **Atualizar Assinaturas do Defender:** Força o download das mais recentes definições de vírus para o Microsoft Defender.
* **Otimizar Unidades:** Desfragmenta e otimiza HDDs e SSDs.
* **Limpar Arquivos Temporários:** Remove arquivos temporários do sistema e do usuário de múltiplas localizações.
* **Verificar Disco (Chkdsk):** Agenda uma verificação do sistema de arquivos na próxima reinicialização para corrigir erros.
* **Limpar Cache do Windows Update:** Apaga arquivos de atualização baixados e corrompidos.
* **Renovar IP e DNS:** Limpa o cache de DNS e renova o endereço IP.
* **Reparar Apps da Store:** Tenta registrar novamente todos os aplicativos da Microsoft Store para corrigir falhas.
* **Verificar Serviços Essenciais:** Garante que serviços críticos do Windows (Update, BITS, Defender) estejam ativos e configurados para iniciar automaticamente.
* **Resetar Rede:** Restaura as configurações de rede do Windows para o padrão (requer reinicialização).
* **Limpar Cache de Ícones:** Apaga o cache de ícones do sistema para corrigir ícones corrompidos ou que não são exibidos corretamente.
* **Remover Bloatware:** Remove uma lista selecionada de aplicativos pré-instalados comuns (Bing News, Xbox App, Your Phone, etc.).
* **Agendar Teste de Memória:** Agenda a Ferramenta de Diagnóstico de Memória do Windows para ser executada na próxima reinicialização.

### Segurança
* **Ponto de Restauração:** Cria automaticamente um ponto de restauração do sistema antes de iniciar qualquer tarefa.
* **Log Detalhado:** Todas as operações são registradas em um arquivo de log (`WindowsMaintenance_DATA_HORA.log`) na mesma pasta do script.
* **Elevação Automática:** O script verifica se está sendo executado como administrador e, caso não esteja, solicita a elevação de privilégios automaticamente.

---

## 🚀 Como Usar

**1. Download:**
* **Opção A (Git):** Clone o repositório para o seu computador:
    ```bash
    git clone [https://github.com/SEU-USUARIO/SEU-REPOSITORIO.git](https://github.com/SEU-USUARIO/SEU-REPOSITORIO.git)
    ```
* **Opção B (Download Direto):** Na página do repositório no GitHub, clique em **Code** -> **Download ZIP** e extraia os arquivos.

**2. Execução:**
* Navegue até a pasta onde o script foi salvo.
* Clique com o botão direito do mouse sobre o arquivo `.ps1`.
* Selecione **"Executar com PowerShell"**.
* O script solicitará permissão de administrador. Confirme para continuar.

**3. Seleção de Tarefas:**
* Na janela que abrir, marque as caixas de seleção correspondentes às tarefas que deseja executar.
* Para executar todas, marque a opção **"Modo Turbo"**.
* Clique em **"Executar"**.

---

## 📋 Pré-requisitos

* **Sistema Operacional:** Windows 10 ou Windows 11.
* **PowerShell:** Versão 5.1 ou superior (já vem instalado por padrão no Windows 10/11).
* **Permissões:** Acesso de Administrador no computador.
* **Conexão com a Internet:** Necessária para as tarefas de atualização (Windows Update, Defender) e para a instalação automática do módulo `PSWindowsUpdate`.

---

## 🤝 Contribuições

Contribuições são bem-vindas! Se você tiver uma ideia para uma nova funcionalidade, uma correção de bug ou uma melhoria no código, sinta-se à vontade para abrir uma **Pull Request**.