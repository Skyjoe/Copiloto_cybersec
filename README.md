#  🛡️ Copiloto_cybersec
🔒 Solução EDR open-source com inteligência artificial local (Llama 3), quarentena automática de ficheiros maliciosos, monitoramento de processos por Machine Learning e auditoria de rede

O **Copiloto CyberSec** é uma solução EDR (*Endpoint Detection and Response*) local e open-source desenvolvida em Python. O projeto integra Machine Learning, análise comportamental e Inteligência Artificial local via **Llama 3** para proteger sistemas Linux e Windows contra malware, modificações não autorizadas no sistema, conexões de rede suspeitas e tentativas de phishing.

## 🚀 Principais Funcionalidades

1. **🤖 Análise Comportamental com IA Local (Llama 3):**

   * Monitoriza o uso de CPU e RAM dos processos em tempo real utilizando `IsolationForest` (Machine Learning).

   * Caso um processo apresente comportamento anómalo, o Llama 3 (executado localmente via `llama.cpp`) analisa o risco e decide se aciona um Alerta Vermelho.

2. **📄 Quarentena Ativa e Verificação de Downloads (VirusTotal):**

   * Monitoriza a pasta de *Downloads* continuamente através do `watchdog`.

   * Calcula o hash SHA-256 dos novos ficheiros e consulta a API do VirusTotal.

   * **Quarentena Automática:** Se um malware for detetado, o ficheiro é movido de imediato para uma pasta isolada e segura (`quarentena/`), tendo as suas permissões de execução totalmente revogadas.

3. **🚪 Monitor de Rede e Portas (Locais e Externas):**

   * Inspeciona portas de escuta (`LISTEN`) para detetar potenciais aplicações não autorizadas ou *backdoors*.

   * Monitoriza conexões ativas estabelecidas com endereços IP remotos externos (`ESTABLISHED`) para identificar potenciais comunicações com servidores de comando e controlo (C2).

4. **📁 Proteção de Pastas Críticas do Sistema:**

   * Vigia diretórios vitais do sistema operativo (como `/etc` no Linux ou `System32` no Windows) contra alterações não autorizadas.

5. **📋 Monitor Inteligente de Clipboard & OCR (Análise de Tela):**

   * Lê links copiados para a área de transferência e recorre à IA para identificar tentativas de *phishing* ou golpes.

   * Extrai texto do ecrã em tempo real através de OCR (`pyesseract`) para auditar possíveis comandos ou conteúdos maliciosos visíveis.

6. **📊 Registo Forense Estruturado:**

   * Regista todos os eventos críticos de segurança (como deteções, ativações de quarentena e acessos de rede) num diário de auditoria em formato JSON (`forense.json`).

7. **🎛️ Interface Gráfica e System Tray:**

   * Interface limpa desenvolvida em `customtkinter` com modo escuro e sistema de abas.

   * Ícone vetorial estilizado em alta definição na bandeja do sistema (*System Tray*).

## 🛠️ Pré-requisitos e Dependências

* **Python 3.10+** instalado no sistema.

* **Tesseract-OCR** instalado (necessário para a função de OCR/análise de tela):

  ```
  sudo apt install tesseract-ocr tesseract-ocr-por
  
  ```

* Um modelo **Llama 3 (.gguf)** configurado para rodar localmente com `llama-cpp-python` ou `llama.cpp`.

* Uma chave de API gratuita do **VirusTotal** (para a verificação de hash de ficheiros descarregados).

## 📦 Instalação

1. Clona o repositório para a tua máquina:

   ```
   git clone https://github.com/o-teu-utilizador/copilot_cybersec.git
   cd copilot_cybersec
   
   ```

2. Cria e ativa um ambiente virtual Python:

   ```
   python3 -m venv venv
   source venv/bin/activate
   
   ```

3. Instala todas as dependências listadas no projeto:

   ```
   pip install -r requirements.txt
   
   ```

4. Configura as tuas variáveis de ambiente:
   Cria um ficheiro chamado `.env` na raiz do projeto e adiciona a tua chave do VirusTotal:

   ```
   VIRUSTOTAL_API_KEY=a_tua_chave_aqui
   
   ```

## 🚀 Como Executar

### Execução Manual

Podes iniciar o servidor do Llama e o agente de monitoramento através do script de inicialização integrado:

```
./iniciar_copiloto.sh

```

### Inicialização Automática com o Sistema (Linux Mint / GNOME / Cinnamon)

Para fazer o Copiloto iniciar sozinho ao ligar o computador:

1. Abre as configurações de **Aplicativos de Inicialização** no teu sistema.

2. Clica em **Adicionar aplicativo personalizado**.

3. Define o comando apondo para o script de inicialização:

   ```
   /caminho/para/o/seu/copilot_cybersec/iniciar_copiloto.sh
   
   ```

4. Guarda as alterações. O script encarregará de subir o servidor local e o EDR de forma sincronizada.

## 🤝 Contribuições

Contribuições, sugestões de melhorias e novas funcionalidades são sempre bem-vindas! Siste-te à vontade para abrir uma *Issue* ou enviar um *Pull Request*.

## 📜 Licença

Este projeto é distribuído sob a licença MIT. Consulta o ficheiro `LICENSE` para mais detalhes.
