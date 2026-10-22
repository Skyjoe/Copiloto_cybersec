import customtkinter as ctk
import threading
import time
import requests
import psutil
import os
import hashlib
import json
import mss
import pytesseract
import pyperclip
from PIL import Image, ImageDraw
import pystray
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from dotenv import load_dotenv
import shutil

# Importações de Machine Learning para Anomalias
import numpy as np
from sklearn.ensemble import IsolationForest
import sys

# --- CONFIGURAÇÕES E DIRETÓRIO DO PROJETO ---
load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

PASTA_DOWNLOADS = os.path.expanduser("~/Downloads")

# Define o diretório atual do script como base para quarentena e logs
DIRETORIO_PROJETO = os.path.dirname(os.path.abspath(__file__))
PASTA_QUARENTENA = os.path.join(DIRETORIO_PROJETO, "quarentena")
ARQUIVO_WHITELIST = os.path.join(DIRETORIO_PROJETO, "whitelist.json")
ARQUIVO_LOG_FORENSE = os.path.join(DIRETORIO_PROJETO, "forense.json")

# Cria a pasta de quarentena dentro do projeto se não existir
os.makedirs(PASTA_QUARENTENA, exist_ok=True)

# --- DEFINIÇÃO DAS PASTAS CRÍTICAS DE SISTEMA (Multiplataforma) ---
if os.name == 'nt': # Windows
    PASTAS_SISTEMA_CRITICAS = [r"C:\Windows\System32"]
else: # Linux / Unix
    PASTAS_SISTEMA_CRITICAS = ["/etc"]

# --- TRAVA ANTI-INSTÂNCIA DUPLA ---
ARQUIVO_LOCK = os.path.expanduser("~/.copiloto_cybersec.lock")

def verificar_instancia_unica():
    if os.path.exists(ARQUIVO_LOCK):
        try:
            with open(ARQUIVO_LOCK, "r") as f:
                pid_antigo = int(f.read().strip())
            if psutil.pid_exists(pid_antigo):
                print("⚠️ O Copiloto CyberSec já está rodando em segundo plano!")
                sys.exit(0)
        except:
            pass
    
    with open(ARQUIVO_LOCK, "w") as f:
        f.write(str(os.getpid()))

# --- LOG FORENSE CORRIGIDO (JSON VÁLIDO) ---
def registrar_log_forense(tipo_evento, detalhes):
    try:
        evento = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "tipo": tipo_evento,
            "detalhes": detalhes
        }
        logs = []
        if os.path.exists(ARQUIVO_LOG_FORENSE):
            with open(ARQUIVO_LOG_FORENSE, "r", encoding="utf-8") as f:
                try:
                    logs = json.load(f)
                    if not isinstance(logs, list):
                        logs = []
                except:
                    logs = []
        logs.append(evento)
        with open(ARQUIVO_LOG_FORENSE, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=4, ensure_ascii=False)
    except Exception as e:
        print(f"Erro ao salvar log forense: {e}")

# --- GERENCIAMENTO DA WHITELIST ---
def carregar_whitelist():
    if os.path.exists(ARQUIVO_WHITELIST):
        with open(ARQUIVO_WHITELIST, "r") as f:
            return json.load(f)
    padrao = [
        "sleep", "bash", "grep", "ps", "kworker", "spotify", "gnome-calculator", 
        "sh", "python3", "python", "agente_monitor", "systemd", "dbus-daemon", 
        "brave", "cinnamon", "cpuUsage.sh", "df", "QtWebEngineProcess", 
        "audacity", "bwrap", "xdg-dbus-proxy", "ostnamed", "executar.sh", 
        "oosplash", "soffice.bin", "gnome-shell", "Xorg", "apt", "dpkg", "snapd", "code", "agy"
    ]
    salvar_whitelist(padrao)
    return padrao

def salvar_whitelist(lista):
    with open(ARQUIVO_WHITELIST, "w") as f:
        json.dump(lista, f)

WHITELIST = carregar_whitelist()

# --- CLASSE PRINCIPAL DA INTERFACE ---
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

FONTE_TEXTO = ("Arial", 18)
FONTE_BOTAO = ("Arial", 18, "bold")

class CopilotoApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Copiloto CyberSec")
        self.geometry("900x650")
        self.withdraw()
        
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        
        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(padx=20, pady=20, fill="both", expand=True)
        self.tabview._segmented_button.configure(font=FONTE_TEXTO)
        
        self.aba_chat = self.tabview.add("Análise & Chat")
        self.aba_downloads = self.tabview.add("Downloads & Vírus")
        self.aba_logs = self.tabview.add("Logs de Processos")
        self.aba_whitelist = self.tabview.add("Whitelist")

        self.setup_aba_chat()
        self.setup_aba_downloads()
        self.setup_aba_logs()
        self.setup_aba_whitelist()

    def mostrar_janela(self):
        self.after(0, self.deiconify)

    def tornar_copiavel(self, textbox):
        def copiar_selecao(event):
            try:
                selecao = textbox.get("sel.first", "sel.last")
                pyperclip.copy(selecao)
            except Exception:
                pass
            return "break"
        
        textbox.bind("<Control-c>", copiar_selecao)
        textbox.bind("<Control-C>", copiar_selecao)
        textbox.bind("<Key>", lambda e: "break")

    def setup_aba_chat(self):
        self.chat_history = ctk.CTkTextbox(self.aba_chat, font=FONTE_TEXTO, wrap="word")
        self.chat_history.pack(padx=10, pady=(10,0), fill="both", expand=True)
        self.tornar_copiavel(self.chat_history)

        frame_botoes = ctk.CTkFrame(self.aba_chat, fg_color="transparent")
        frame_botoes.pack(padx=10, pady=10, fill="x")

        self.entrada_chat = ctk.CTkEntry(frame_botoes, placeholder_text="Pergunte algo à IA ou cole um link...", font=FONTE_TEXTO)
        self.entrada_chat.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.entrada_chat.bind("<Return>", lambda e: self.enviar_msg_chat())

        btn_enviar = ctk.CTkButton(frame_botoes, text="Enviar", command=self.enviar_msg_chat, width=80, font=FONTE_BOTAO)
        btn_enviar.pack(side="left", padx=(0, 10))

        btn_clipboard = ctk.CTkButton(frame_botoes, text="🔗 Testar Link Copiado", command=self.testar_link_copiado, fg_color="#1f538d", hover_color="#14375e", font=FONTE_BOTAO)
        btn_clipboard.pack(side="right", padx=(0, 10))

        btn_print = ctk.CTkButton(frame_botoes, text="📷 Analisar Tela", command=self.analisar_tela, fg_color="#8B0000", hover_color="#5C0000", font=FONTE_BOTAO)
        btn_print.pack(side="right")

    def add_chat_msg(self, autor, msg):
        self.chat_history.configure(state="normal")
        self.chat_history.insert("end", f"[{autor}]: {msg}\n\n")
        self.chat_history.see("end")
        self.chat_history.configure(state="disabled")

    def enviar_msg_chat(self):
        msg = self.entrada_chat.get()
        if not msg.strip(): return
        self.entrada_chat.delete(0, "end")
        self.add_chat_msg("Você", msg)
        threading.Thread(target=self.consultar_ia, args=(msg,)).start()

    def _analisar_url_thread(self, texto_url):
        prompt = f"<|user|>\nAnalise esta URL rapidamente em PORTUGUÊS DO BRASIL. Ela é um GOLPE/PHISHING ou é SEGURA? Resuma em apenas uma frase curta: {texto_url}<|end|>\n<|assistant|>"
        try:
            r = requests.post("http://127.0.0.1:8000/v1/completions", json={"prompt": prompt, "max_tokens": 80, "temperature": 0.1})
            resposta_ia = r.json()['choices'][0]['text'].strip()
            self.after(0, lambda: self.add_chat_msg("IA", resposta_ia))
            
            ameacas_reais = ["phishing", "golpe real", "fraude", "falso site", "site clonado", "malware", "estelionato"]
            if any(termo in resposta_ia.lower() for termo in ameacas_reais) and "não é" not in resposta_ia.lower() and "segura" not in resposta_ia.lower():
                registrar_log_forense("PHISHING_DETECTADO", {"url": texto_url, "analise": resposta_ia})
                self.after(0, lambda: self.mostrar_alerta_bloqueio("🚨 LINK SUSPEITO DETECTADO!", f"A IA analisou o link e confirmou uma ameaça:\n\n{resposta_ia}"))
            else:
                self.after(0, lambda: self.mostrar_toast("✅ Link Seguro", resposta_ia, "#00ff00"))
        except Exception as e:
            self.after(0, lambda: self.add_chat_msg("Erro", f"Falha ao contatar a IA: {e}"))
    
    def testar_link_copiado(self):
        try:
            link = pyperclip.paste().strip()
            if link:
                self.add_chat_msg("Você (Link Manual)", link)
                threading.Thread(target=self._analisar_url_thread, args=(link,)).start()
            else:
                self.add_chat_msg("Sistema", "A área de transferência está vazia.")
        except Exception as e:
            self.add_chat_msg("Erro", f"Não foi possível ler a área de transferência: {e}")

    def analisar_tela(self):
        self.add_chat_msg("Sistema", "Tirando print e lendo texto da tela... (Aguarde)")
        threading.Thread(target=self._processar_print).start()

    def _processar_print(self):
        try:
            with mss.mss() as sct:
                img = sct.grab(sct.monitors[1])
                img_pil = Image.frombytes("RGB", img.size, img.bgra, "raw", "BGRX")
                
            texto_tela = pytesseract.image_to_string(img_pil, lang='por')
            if not texto_tela.strip():
                self.after(0, lambda: self.add_chat_msg("IA", "Não encontrei nenhum texto legível na tela."))
                return
            
            prompt = f"Analise o texto extraído da minha tela e diga se há sinais de phishing, golpe ou comandos suspeitos. Texto: {texto_tela[:1500]}"
            self.consultar_ia(prompt)
        except Exception as e:
            self.after(0, lambda: self.add_chat_msg("Erro", f"Falha no OCR: {e}"))

    def consultar_ia(self, prompt_usuario):
        prompt = f"<|user|>\n{prompt_usuario}<|end|>\n<|assistant|>"
        try:
            r = requests.post("http://127.0.0.1:8000/v1/completions", json={"prompt": prompt, "max_tokens": 800, "temperature": 0.2})
            texto_ia = r.json()['choices'][0]['text'].strip()
            self.after(0, lambda: self.add_chat_msg("IA", texto_ia))
        except Exception:
            self.after(0, lambda: self.add_chat_msg("Erro", "Falha de conexão com servidor Llama local."))

    def setup_aba_downloads(self):
        lbl_info = ctk.CTkLabel(self.aba_downloads, text="Histórico de verificação de arquivos baixados (VirusTotal & Quarentena):", font=FONTE_TEXTO)
        lbl_info.pack(padx=10, pady=(10, 0), anchor="w")
        
        self.caixa_downloads = ctk.CTkTextbox(self.aba_downloads, font=FONTE_TEXTO, wrap="word", fg_color="#1e1e1e", text_color="#aaaaaa")
        self.caixa_downloads.pack(padx=10, pady=10, fill="both", expand=True)
        self.tornar_copiavel(self.caixa_downloads)

    def add_log_download(self, nome_arquivo, status):
        self.caixa_downloads.configure(state="normal")
        hora = time.strftime("%H:%M:%S")
        self.caixa_downloads.insert("end", f"[{hora}] 📄 {nome_arquivo}\nStatus: {status}\n{'-'*60}\n")
        self.caixa_downloads.see("end")
        self.caixa_downloads.configure(state="disabled")

    def setup_aba_logs(self):
        lbl_info = ctk.CTkLabel(self.aba_logs, text="Histórico de Anomalias, Rede e Alertas de Segurança:", font=FONTE_TEXTO)
        lbl_info.pack(padx=10, pady=(10, 0), anchor="w")
        
        self.caixa_logs = ctk.CTkTextbox(self.aba_logs, font=FONTE_TEXTO, wrap="word", fg_color="#1e1e1e", text_color="#aaaaaa")
        self.caixa_logs.pack(padx=10, pady=10, fill="both", expand=True)
        self.tornar_copiavel(self.caixa_logs)

    def add_log_processo(self, nome_processo, texto_ia):
        self.caixa_logs.configure(state="normal")
        hora = time.strftime("%H:%M:%S")
        self.caixa_logs.insert("end", f"[{hora}] Alerta: {nome_processo}\nIA: {texto_ia}\n{'-'*60}\n")
        self.caixa_logs.see("end")
        self.caixa_logs.configure(state="disabled")

    def setup_aba_whitelist(self):
        frame_top = ctk.CTkFrame(self.aba_whitelist, fg_color="transparent")
        frame_top.pack(padx=10, pady=10, fill="x")

        self.entrada_wl = ctk.CTkEntry(frame_top, placeholder_text="Nome do processo", font=FONTE_TEXTO)
        self.entrada_wl.pack(side="left", fill="x", expand=True, padx=(0, 10))

        btn_add = ctk.CTkButton(frame_top, text="Adicionar", command=self.add_whitelist, width=100, font=FONTE_BOTAO)
        btn_add.pack(side="left")

        self.lista_wl = ctk.CTkTextbox(self.aba_whitelist, font=FONTE_TEXTO)
        self.lista_wl.pack(padx=10, pady=10, fill="both", expand=True)
        self.tornar_copiavel(self.lista_wl)
        self.atualizar_lista_wl()

    def atualizar_lista_wl(self):
        self.lista_wl.configure(state="normal")
        self.lista_wl.delete("0.0", "end")
        self.lista_wl.insert("end", "\n".join(sorted(WHITELIST)))
        self.lista_wl.configure(state="disabled")

    def add_whitelist(self):
        processo = self.entrada_wl.get().strip()
        if processo and processo not in WHITELIST:
            WHITELIST.append(processo)
            salvar_whitelist(WHITELIST)
            self.entrada_wl.delete(0, "end")
            self.atualizar_lista_wl()

    def mostrar_toast(self, titulo, mensagem, cor_borda="#00ff00"):
        toast = ctk.CTkToplevel(self)
        toast.overrideredirect(True)
        toast.attributes("-topmost", True)
        
        frame = ctk.CTkFrame(toast, border_width=2, border_color=cor_borda, fg_color="#1a1a1a")
        frame.pack(fill="both", expand=True)
        
        lbl_titulo = ctk.CTkLabel(frame, text=titulo, font=("Arial", 20, "bold"), text_color="white")
        lbl_titulo.pack(padx=15, pady=(15, 5), anchor="w")
        
        lbl_msg = ctk.CTkLabel(frame, text=mensagem, font=("Arial", 18), justify="left", wraplength=400)
        lbl_msg.pack(padx=15, pady=(0, 15), anchor="w")

        toast.update_idletasks()
        w, h = toast.winfo_width(), toast.winfo_height()
        ws, hs = toast.winfo_screenwidth(), toast.winfo_screenheight()
        
        x = ws - w - 20
        y = hs - h - 50
        toast.geometry(f"+{x}+{y}")
        
        self.after(8000, toast.destroy)

    def mostrar_alerta_bloqueio(self, titulo, mensagem):
        alerta = ctk.CTkToplevel(self)
        alerta.overrideredirect(True)
        alerta.attributes("-topmost", True)
        
        w, h = 800, 500
        ws = alerta.winfo_screenwidth()
        hs = alerta.winfo_screenheight()
        x = (ws // 2) - (w // 2)
        y = (hs // 2) - (h // 2)
        alerta.geometry(f"{w}x{h}+{x}+{y}")
        
        frame = ctk.CTkFrame(alerta, border_width=6, border_color="#ff0000", fg_color="#2b0000")
        frame.pack(fill="both", expand=True)
        
        lbl_titulo = ctk.CTkLabel(frame, text=titulo, font=("Arial", 32, "bold"), text_color="#ff4444")
        lbl_titulo.pack(padx=20, pady=(25, 10))
        
        txt_msg = ctk.CTkTextbox(frame, font=("Arial", 20), text_color="white", fg_color="#1a0000", wrap="word")
        txt_msg.pack(padx=20, pady=10, fill="both", expand=True)
        txt_msg.insert("0.0", mensagem)
        txt_msg.configure(state="disabled")
        
        btn_fechar = ctk.CTkButton(
            frame, 
            text="ESTOU CIENTE (FECHAR)", 
            fg_color="#ff0000", 
            hover_color="#aa0000", 
            font=("Arial", 18, "bold"), 
            command=alerta.destroy
        )
        btn_fechar.pack(pady=20)

# Instância Global
app_ui = None

# --- ROTINAS DE BACKEND (ML, Sistema, Quarentena e Rede) ---
ml_model = None

def treinar_baseline_inicial():
    global ml_model
    dados_normais = np.array([
        [0.5, 1.2, 4],   
        [2.0, 3.5, 12],  
        [0.1, 0.5, 2],   
        [15.0, 8.0, 20],  
        [0.0, 0.2, 1]    
    ])
    ml_model = IsolationForest(contamination=0.20, random_state=42)
    ml_model.fit(dados_normais)

def analisar_comportamento_processo(nome_processo, cpu_uso, mem_uso):
    global ml_model
    if not ml_model:
        treinar_baseline_inicial()
    
    if "python" in nome_processo.lower() or "agente" in nome_processo.lower():
        return

    features = np.array([[cpu_uso, mem_uso, 5]])
    previsao = ml_model.predict(features) 
    
    if previsao[0] == -1 and (cpu_uso > 8.0 or mem_uso > 15.0):
        prompt = f"<|user|>\nO processo '{nome_processo}' apresentou comportamento anômalo (CPU: {cpu_uso}%, RAM: {mem_uso}%). Isso é um MALWARE, GOLPE ou comportamento malicioso real? Resuma em uma frase curta em PORTUGUÊS: {nome_processo}<|end|>\n<|assistant|>"
        try:
            r = requests.post("http://127.0.0.1:8000/v1/completions", json={"prompt": prompt, "max_tokens": 80, "temperature": 0.1})
            texto = r.json()['choices'][0]['text'].strip()
            
            if app_ui:
                app_ui.after(0, lambda: app_ui.add_log_processo(nome_processo, texto))
                
                termos_perigo_processo = ["malware", "malicioso", "virus", "suspeito", "ataque", "minerador", "intruso", "perigoso"]
                if any(termo in texto.lower() for termo in termos_perigo_processo) and "não é" not in texto.lower() and "legítimo" not in texto.lower():
                    registrar_log_forense("PROCESSO_ANOMALO_MALICIOSO", {"processo": nome_processo, "cpu": cpu_uso, "ia": texto})
                    app_ui.after(0, lambda: app_ui.mostrar_alerta_bloqueio(
                        "🚨 PROCESSO ANÔMALO SUSPEITO!", 
                        f"O Copiloto detectou um comportamento perigoso:\n\nProcesso: {nome_processo}\nUso de CPU: {cpu_uso}%\n\nAnálise da IA:\n{texto}"
                    ))
        except:
            pass

def quarentena_arquivo(caminho_origem, nome_arquivo):
    try:
        destino = os.path.join(PASTA_QUARENTENA, nome_arquivo)
        shutil.move(caminho_origem, destino)
        # Remove permissões de execução do arquivo isolado
        os.chmod(destino, 0o000)
        registrar_log_forense("QUARENTENA_ATIVADA", {"arquivo": nome_arquivo, "caminho_original": caminho_origem})
        return True
    except Exception as e:
        print(f"Erro ao colocar em quarentena: {e}")
        return False

def checar_virustotal(hash_arquivo, nome_arquivo, caminho_completo):
    if not VIRUSTOTAL_API_KEY:
        if app_ui:
            app_ui.after(0, lambda: app_ui.add_log_download(nome_arquivo, "⚠️ ERRO: Chave VirusTotal não encontrada no .env."))
        return
        
    url = f"https://www.virustotal.com/api/v3/files/{hash_arquivo}"
    try:
        r = requests.get(url, headers={"x-apikey": VIRUSTOTAL_API_KEY})
        if r.status_code == 200:
            stats = r.json()['data']['attributes']['last_analysis_stats']
            maliciosos = stats['malicious']
            if app_ui:
                if maliciosos > 0:
                    msg_log = f"🚨 DETECTADO POR {maliciosos} ANTIVÍRUS! Movido para Quarentena."
                    app_ui.after(0, lambda: app_ui.add_log_download(nome_arquivo, msg_log))
                    
                    # Ativa a Quarentena Ativa isolando o arquivo
                    quarentena_arquivo(caminho_completo, nome_arquivo)
                    
                    app_ui.after(0, lambda: app_ui.mostrar_alerta_bloqueio("🚨 AMEAÇA ISOLADA EM QUARENTENA!", f"O arquivo:\n'{nome_arquivo}'\n\nFoi classificado como MALWARE por {maliciosos} motores e isolado com segurança na Quarentena!"))
                else:
                    msg_log = "✅ Arquivo limpo (0 detecções)."
                    app_ui.after(0, lambda: app_ui.add_log_download(nome_arquivo, msg_log))
                    app_ui.after(0, lambda: app_ui.mostrar_toast("✅ Download Seguro", f"'{nome_arquivo}' está limpo.", "#00ff00"))
        elif r.status_code == 404:
            if app_ui:
                msg_log = "ℹ️ Arquivo Desconhecido (100% Privado)."
                app_ui.after(0, lambda: app_ui.add_log_download(nome_arquivo, msg_log))
                app_ui.after(0, lambda: app_ui.mostrar_toast("🔒 Arquivo Privado", f"'{nome_arquivo}' é desconhecido na nuvem (Seguro).", "#00ff00"))
    except Exception as e:
        if app_ui:
            app_ui.after(0, lambda: app_ui.add_log_download(nome_arquivo, f"❌ Erro de conexão com a API: {e}"))

# --- MONITOR DE CLIPBOARD AUTOMÁTICO ---
def loop_clipboard():
    ultimo_texto = ""
    while True:
        try:
            texto_atual = pyperclip.paste().strip()
            if texto_atual != ultimo_texto and (texto_atual.startswith("http://") or texto_atual.startswith("https://")):
                ultimo_texto = texto_atual
                
                if app_ui:
                    app_ui.after(0, lambda t=texto_atual: app_ui.add_chat_msg("Você (Copiou Link)", t))
                    app_ui.after(0, lambda t=texto_atual: threading.Thread(target=app_ui._analisar_url_thread, args=(t,), daemon=True).start())
        except Exception:
            pass
        time.sleep(1)

# --- MONITOR DE ARQUIVOS (Downloads e Pastas de Sistema) ---
class MonitorArquivos(FileSystemEventHandler):
    def __init__(self, tipo="download"):
        self.tipo = tipo
        self.ultimo_alerta = 0

    def on_created(self, event): self._proc(event.src_path)
    def on_modified(self, event): 
        if self.tipo == "sistema":
            self._proc(event.src_path)
    def on_moved(self, event): self._proc(event.dest_path)
    
    def _proc(self, caminho):
        if not os.path.isdir(caminho):
            nome = os.path.basename(caminho)
            
            if self.tipo == "sistema":
                if nome.endswith('~') or '.swp' in nome or '.lock' in nome or 'cups' in caminho:
                    return
                
                tempo_atual = time.time()
                if (tempo_atual - self.ultimo_alerta) < 2.0:
                    return
                self.ultimo_alerta = tempo_atual
                
                msg_alerta = f"⚠️ ATENÇÃO: Modificação detectada na pasta crítica do sistema!\nArquivo: {caminho}"
                if app_ui:
                    registrar_log_forense("MODIFICACAO_SISTEMA_CRITICO", {"caminho": caminho})
                    app_ui.after(0, lambda: app_ui.add_log_processo("Modificação no Sistema", msg_alerta))
                    app_ui.after(0, lambda: app_ui.mostrar_alerta_bloqueio(
                        "🚨 ALTERAÇÃO NA PASTA DO SISTEMA!", 
                        f"Um processo não autorizado tentou modificar arquivos vitais no diretório protegido:\n\n{caminho}"
                    ))
                return

            if nome.endswith('.crdownload') or nome.endswith('.part') or '.org.chromium' in nome or nome in arquivos_processados: return
            arquivos_processados.add(nome)
            time.sleep(1.5)
            
            try:
                sha256 = hashlib.sha256()
                with open(caminho, "rb") as f:
                    for b in iter(lambda: f.read(4096), b""): sha256.update(b)
                checar_virustotal(sha256.hexdigest(), nome, caminho)
            except: pass

arquivos_processados = set()

# --- MONITOR DE REDE E PORTAS (Com Inspeção de IPs Externos C2) ---
def loop_monitor_rede():
    portas_vistas = set()
    time.sleep(10)
    
    while True:
        try:
            conexoes = psutil.net_connections(kind='inet')
            for conn in conexoes:
                # 1. Verifica Portas em Escuta (LISTEN)
                if conn.status == 'LISTEN' and conn.laddr:
                    porta = conn.laddr.port
                    pid = conn.pid
                    if pid:
                        try:
                            proc = psutil.Process(pid)
                            nome_proc = proc.name()
                            ignorar = ["code", "python", "agente", "agy", "systemd", "dbus", "gnome", "firefox", "brave"]
                            if nome_proc and not any(ign in nome_proc.lower() for ign in ignorar) and porta not in [8000, 631, 53, 5353]:
                                chave_porta = f"{pid}-{porta}"
                                if chave_porta not in portas_vistas:
                                    portas_vistas.add(chave_porta)
                                    
                                    prompt = f"<|user|>\nO processo '{nome_proc}' abriu uma porta de rede em escuta (Porta {porta}). Isso é um malware/backdoor real ou um serviço de rede legítimo? Resuma em uma frase curta em PORTUGUÊS: {nome_proc}<|end|>\n<|assistant|>"
                                    r = requests.post("http://127.0.0.1:8000/v1/completions", json={"prompt": prompt, "max_tokens": 80, "temperature": 0.1})
                                    texto = r.json()['choices'][0]['text'].strip()
                                    
                                    if app_ui:
                                        app_ui.after(0, lambda np=nome_proc, p=porta, t=texto: app_ui.add_log_processo(f"Porta Aberta ({p})", f"Processo: {np}\n{t}"))
                                        
                                        termos_perigo_rede = ["malware", "backdoor", "malicioso", "trojan", "intruso", "perigoso"]
                                        if any(termo in texto.lower() for termo in termos_perigo_rede) and "não é" not in texto.lower() and "legítimo" not in texto.lower():
                                            registrar_log_forense("PORTA_SUSPEITA", {"processo": nome_proc, "porta": porta, "ia": texto})
                                            app_ui.after(0, lambda np=nome_proc, p=porta, t=texto: app_ui.mostrar_alerta_bloqueio(
                                                "🚨 PORTA SUSPEITA ABERTA NA REDE!",
                                                f"Um aplicativo abriu uma porta de escuta não autorizada:\n\nProcesso: {np}\nPorta: {p}\n\nAnálise da IA:\n{t}"
                                            ))
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                            
                # 2. Verifica Conexões Externas Ativas (ESTABLISHED com IPs remotos)
                elif conn.status == 'ESTABLISHED' and conn.raddr:
                    ip_remoto = conn.raddr.ip
                    # Ignora endereços locais/privados
                    if not ip_remoto.startswith("127.") and not ip_remoto.startswith("192.168.") and not ip_remoto.startswith("10."):
                        pid = conn.pid
                        if pid:
                            try:
                                proc = psutil.Process(pid)
                                nome_proc = proc.name()
                                ignorar = ["code", "python", "agente", "agy", "firefox", "brave", "chromium", "systemd"]
                                if nome_proc and not any(ign in nome_proc.lower() for ign in ignorar):
                                    chave_ip = f"{pid}-{ip_remoto}"
                                    if chave_ip not in portas_vistas:
                                        portas_vistas.add(chave_ip)
                                        registrar_log_forense("CONEXAO_EXTERNA_SUSPEITA", {"processo": nome_proc, "ip_remoto": ip_remoto})
                            except:
                                pass
        except Exception:
            pass
        time.sleep(30)

def loop_processos():
    treinar_baseline_inicial()
    
    observer_downloads = Observer()
    observer_downloads.schedule(MonitorArquivos(tipo="download"), PASTA_DOWNLOADS, recursive=False)
    observer_downloads.start()

    observers_sistema = []
    for pasta in PASTAS_SISTEMA_CRITICAS:
        if os.path.exists(pasta):
            obs = Observer()
            obs.schedule(MonitorArquivos(tipo="sistema"), pasta, recursive=True)
            obs.start()
            observers_sistema.append(obs)

    processos_ativos = {}

    while True:
        try:
            pids_atuais = set()
            for p in psutil.process_iter(['pid', 'name', 'memory_percent']):
                try:
                    pid = p.info['pid']
                    nome = p.info['name']
                    pids_atuais.add(pid)
                    
                    if nome and not any(nome.startswith(w) for w in WHITELIST):
                        mem = p.info['memory_percent'] or 0.0
                        
                        if pid not in processos_ativos:
                            processos_ativos[pid] = p
                            p.cpu_percent(interval=None)
                            continue
                        
                        cpu = processos_ativos[pid].cpu_percent(interval=None) or 0.0
                        analisar_comportamento_processo(nome, cpu, mem)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            pids_mortos = set(processos_ativos.keys()) - pids_atuais
            for pid in pids_mortos:
                del processos_ativos[pid]
                
        except Exception:
            pass
        time.sleep(15)

# --- ÍCONE EM VETOR DE ALTA DEFINIÇÃO (SYSTEM TRAY) ---
def criar_icone():
    img_size = 256
    img = Image.new('RGBA', (img_size, img_size), color=(0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    
    pontos_escudo = [
        (128, 20),   (230, 60),   (230, 140),  
        (128, 236),  (26, 140),   (26, 60)     
    ]
    d.polygon(pontos_escudo, fill=(15, 23, 42), outline=(0, 255, 120))
    
    pontos_interno = [
        (128, 32), (216, 70), (216, 134),
        (128, 220), (40, 134), (40, 70)
    ]
    d.polygon(pontos_interno, fill=(20, 30, 50), outline=(0, 200, 90))

    d.rectangle([96, 120, 160, 176], fill=(0, 255, 120))
    d.arc([104, 76, 152, 128], start=180, end=360, fill=(0, 255, 120), width=14)
    d.rectangle([122, 138, 134, 154], fill=(15, 23, 42))
    d.ellipse([122, 150, 134, 162], fill=(15, 23, 42))

    return img.resize((64, 64), Image.Resampling.LANCZOS)

def tray_thread_func():
    menu = pystray.Menu(
        pystray.MenuItem('Abrir Painel', lambda: app_ui.mostrar_janela(), default=True),
        pystray.MenuItem('Encerrar', lambda icon: (icon.stop(), os._exit(0)))
    )
    icone = pystray.Icon("cybersec", criar_icone(), "Copiloto CyberSec", menu)
    icone.run()

if __name__ == "__main__":
    verificar_instancia_unica()
    
    app_ui = CopilotoApp()
    
    threading.Thread(target=tray_thread_func, daemon=True).start()
    threading.Thread(target=loop_processos, daemon=True).start()
    threading.Thread(target=loop_clipboard, daemon=True).start()
    threading.Thread(target=loop_monitor_rede, daemon=True).start()
    
    try:
        app_ui.mainloop()
    finally:
        if os.path.exists(ARQUIVO_LOCK):
            os.remove(ARQUIVO_LOCK)