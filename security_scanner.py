import psutil
import socket
import customtkinter as ctk
import threading
import time
import os
from tkinter import filedialog, LEFT, messagebox
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from datetime import datetime
import json

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

class SecurityScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Security Scanner - by euuCode")
        self.root.geometry("900x600")
        self.root.resizable(False, False)

        self.main_frame = ctk.CTkFrame(root, corner_radius=20, fg_color="#1e1e1e")
        self.main_frame.pack(pady=30, padx=30, fill="both", expand=True)

        self.title_label = ctk.CTkLabel(self.main_frame, text="Security Scanner",
                                        font=("Helvetica", 28, "bold"), text_color="#4CAF50")
        self.title_label.pack(pady=20)

        self.tab_view = ctk.CTkTabview(self.main_frame, width=840, height=480, corner_radius=15,
                                       fg_color="#2b2b2b", border_width=2, border_color="#4CAF50")
        self.tab_view.pack(pady=20, padx=20)

        
        self.computer_tab = self.tab_view.add("Scanner de Computador")
        self.files_tab = self.tab_view.add("Scanner de Arquivos")
        self.history_tab = self.tab_view.add("Histórico de Logs")

       
        self.computer_frame = ctk.CTkFrame(self.computer_tab, corner_radius=15, fg_color="#1e1e1e")
        self.computer_frame.pack(pady=20, padx=20, fill="both", expand=True)

        self.scan_computer_button = ctk.CTkButton(self.computer_frame, text="Escanear Computador",
                                                  command=self.start_scan_computer, font=("Helvetica", 16, "bold"),
                                                  corner_radius=15, height=45, fg_color="#4CAF50",
                                                  hover_color="#45a049", border_width=0)
        self.scan_computer_button.pack(pady=10)

        self.cancel_computer_button = ctk.CTkButton(self.computer_frame, text="Cancelar",
                                                    command=self.cancel_computer_scan, font=("Helvetica", 16, "bold"),
                                                    corner_radius=15, height=45, fg_color="#f44336",
                                                    hover_color="#d32f2f", border_width=0, state="disabled")
        self.cancel_computer_button.pack(pady=5)

        self.computer_result_text = ctk.CTkTextbox(self.computer_frame, width=700, height=200,
                                                   font=("Consolas", 14), corner_radius=15, state="disabled",
                                                   fg_color="#2b2b2b", text_color="#e0e0e0", border_width=2,
                                                   border_color="#4CAF50")
        self.computer_result_text.pack(pady=10, padx=20)

        self.computer_progress = ctk.CTkProgressBar(self.computer_frame, width=700, mode="indeterminate", corner_radius=15,
                                                    progress_color="#4CAF50", fg_color="#3a3a3a")
        self.computer_progress.pack(pady=10)

      
        self.files_frame = ctk.CTkFrame(self.files_tab, corner_radius=15, fg_color="#1e1e1e")
        self.files_frame.pack(pady=20, padx=20, fill="both", expand=True)

        self.path_frame = ctk.CTkFrame(self.files_frame, corner_radius=15, fg_color="#2b2b2b")
        self.path_frame.pack(pady=20, padx=20, fill="x")

        self.path_entry = ctk.CTkEntry(self.path_frame, width=600, height=40, font=("Helvetica", 14),
                                       placeholder_text="Insira o caminho de uma pasta ou arquivo",
                                       corner_radius=15, fg_color="#3a3a3a", text_color="#e0e0e0",
                                       border_width=2, border_color="#4CAF50")
        self.path_entry.pack(side=LEFT, padx=10, pady=10)

        self.browse_button = ctk.CTkButton(self.path_frame, text="Selecionar Pasta",
                                           command=self.browse_directory, font=("Helvetica", 14, "bold"),
                                           corner_radius=15, height=40, fg_color="#4CAF50", hover_color="#45a049",
                                           border_width=0)
        self.browse_button.pack(side=LEFT, padx=10, pady=10)

        self.scan_files_button = ctk.CTkButton(self.files_frame, text="Escanear Arquivos",
                                               command=self.start_scan_files, font=("Helvetica", 16, "bold"),
                                               corner_radius=15, height=45, fg_color="#2196F3",
                                               hover_color="#1976D2", border_width=0)
        self.scan_files_button.pack(pady=10)

        self.cancel_files_button = ctk.CTkButton(self.files_frame, text="Cancelar",
                                                 command=self.cancel_files_scan, font=("Helvetica", 16, "bold"),
                                                 corner_radius=15, height=45, fg_color="#f44336",
                                                 hover_color="#d32f2f", border_width=0, state="disabled")
        self.cancel_files_button.pack(pady=5)

        self.files_result_text = ctk.CTkTextbox(self.files_frame, width=700, height=200,
                                                font=("Consolas", 14), corner_radius=15, state="disabled",
                                                fg_color="#2b2b2b", text_color="#e0e0e0", border_width=2,
                                                border_color="#4CAF50")
        self.files_result_text.pack(pady=10, padx=20)

        self.files_progress = ctk.CTkProgressBar(self.files_frame, width=700, mode="indeterminate", corner_radius=15,
                                                 progress_color="#2196F3", fg_color="#3a3a3a")
        self.files_progress.pack(pady=10)

        
        self.history_frame = ctk.CTkFrame(self.history_tab, corner_radius=15, fg_color="#1e1e1e")
        self.history_frame.pack(pady=20, padx=20, fill="both", expand=True)

        self.history_text = ctk.CTkTextbox(self.history_frame, width=700, height=250,
                                          font=("Consolas", 14), corner_radius=15, state="disabled",
                                          fg_color="#2b2b2b", text_color="#e0e0e0", border_width=2,
                                          border_color="#4CAF50")
        self.history_text.pack(pady=10, padx=20)

        self.download_button = ctk.CTkButton(self.history_frame, text="Baixar PDF",
                                            command=self.download_history_pdf, font=("Helvetica", 16, "bold"),
                                            corner_radius=15, height=45, fg_color="#2196F3", hover_color="#1976D2")
        self.download_button.pack(pady=5)

        self.clear_button = ctk.CTkButton(self.history_frame, text="Excluir Logs",
                                         command=self.clear_history, font=("Helvetica", 16, "bold"),
                                         corner_radius=15, height=45, fg_color="#f44336", hover_color="#d32f2f")
        self.clear_button.pack(pady=5)

        self.scanning_computer = False
        self.scanning_files = False
        self.cancel_computer = False
        self.cancel_files = False
        self.logs = []  

       
        self.load_logs()

    def log_result(self, text_widget, message, delay=0.1):
        text_widget.configure(state="normal")
        text_widget.insert("end", message + "\n")
        text_widget.configure(state="disabled")
        text_widget.update()
        time.sleep(delay)

    def save_logs(self, log_text, scan_type):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {
            "timestamp": timestamp,
            "type": scan_type,
            "content": log_text.strip()
        }
        self.logs.append(log_entry)
        self.save_logs_to_file()
        self.update_history()

    def save_logs_to_file(self):
        try:
            logs_dir = os.path.dirname(os.path.abspath(__file__))
            logs_path = os.path.join(logs_dir, "scan_logs.json")
            with open(logs_path, "w", encoding="utf-8") as f:
                json.dump(self.logs, f, ensure_ascii=False, indent=4)
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao salvar logs: {str(e)}. Verifique permissões na pasta atual.")

    def load_logs(self):
        try:
            logs_dir = os.path.dirname(os.path.abspath(__file__))
            logs_path = os.path.join(logs_dir, "scan_logs.json")
            if os.path.exists(logs_path):
                with open(logs_path, "r", encoding="utf-8") as f:
                    self.logs = json.load(f)
            else:
                self.logs = []
            self.update_history()
        except json.JSONDecodeError:
            self.logs = []
            messagebox.showwarning("Aviso", "O arquivo de logs está corrompido. Criando novo histórico.")
            self.save_logs_to_file()
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao carregar logs: {str(e)}. Criando novo histórico.")
            self.logs = []
        self.update_history()

    def update_history(self):
        self.history_text.delete("0.0", "end")
        for log in self.logs:
            self.history_text.insert("end", f"[{log['timestamp']}] - {log['type']}\n")
            self.history_text.insert("end", log['content'] + "\n\n")

    def download_history_pdf(self):
        if not self.logs:
            messagebox.showwarning("Aviso", "Nenhum log disponível para download!")
            return

        desktop_path = os.path.join(os.path.expanduser("~"), "Desktop", "scan_history_report.pdf")
        try:
            doc = SimpleDocTemplate(desktop_path, pagesize=letter)
            elements = []
            styles = getSampleStyleSheet()

            elements.append(Paragraph("<font size=20><b>Histórico de Scans</b></font>", styles["Title"]))
            elements.append(Spacer(1, 20))

          
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            elements.append(Paragraph(f"<font size=12>Data/Hora do Relatório: {timestamp}</font>", styles["Normal"]))
            elements.append(Spacer(1, 10))

          
            for log in self.logs:
                elements.append(Paragraph(f"<font size=16><b>Scan de {log['type']} - {log['timestamp']}</b></font>", styles["Heading1"]))
                elements.append(Spacer(1, 10))
                for line in log['content'].split("\n"):
                    if line:
                        if line.startswith("[!]") or line.startswith("[✓]") or line.startswith("[*]"):
                            elements.append(Paragraph(f"<font size=12 color=#4CAF50>{line}</font>", styles["Normal"]))
                        else:
                            elements.append(Paragraph(f"<font size=12>{line}</font>", styles["Normal"]))
                        elements.append(Spacer(1, 5))

          
            elements.append(Spacer(1, 20))
            elements.append(Paragraph("<font size=12><i>Gerado por Security Scanner - by euuCode</i></font>", styles["Italic"]))
            
            doc.build(elements)
            messagebox.showinfo("Sucesso", f"Relatório salvo em PDF: {desktop_path}")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao gerar PDF: {str(e)}. Verifique permissões ou instalação do reportlab.")

    def clear_history(self):
        if messagebox.askyesno("Confirmar", "Tem certeza que deseja excluir todos os logs?"):
            self.logs = []
            self.save_logs_to_file()
            self.update_history()
            messagebox.showinfo("Sucesso", "Logs excluídos com sucesso!")

    def check_camera_mic(self):
        suspicious = []
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                name = proc.info['name'].lower()
                if any(keyword in name for keyword in ["cam", "mic", "video", "audio"]):
                    suspicious.append(f"Possível acesso a câmera/microfone: {name} (PID: {proc.info['pid']})")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, Exception) as e:
            self.log_result(self.computer_result_text, f"[!] Erro ao checar câmera/microfone: {str(e)}")
            return suspicious
        return suspicious

    def resolve_ip(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return ip

    def check_network(self):
        suspicious = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    ip = conn.raddr.ip
                    if ip.startswith(("192.168", "127.", "10.")):
                        continue
                    
                    hostname = self.resolve_ip(ip)
                    suspicious.append(f"Conexão ativa com {hostname} ({ip}:{conn.raddr.port}) (PID: {conn.pid})")
        except Exception as e:
            self.log_result(self.computer_result_text, f"[!] Erro ao checar redes: {str(e)}")
            return suspicious
        return suspicious

    def check_malware(self):
        suspicious = []
        malware_signatures = ["virus", "trojan", "spy", "malware", "keylogger"]
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                name = proc.info['name'].lower()
                if any(sig in name for sig in malware_signatures):
                    suspicious.append(f"Possível malware detectado: {name} (PID: {proc.info['pid']})")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, Exception) as e:
            self.log_result(self.computer_result_text, f"[!] Erro ao checar malwares: {str(e)}")
            return suspicious
        return suspicious

    def check_files(self, path=None):
        suspicious = []
        suspicious_extensions = {".exe", ".bat", ".js", ".dll", ".vbs", ".scr"}
        
        if not path:
            path = os.path.expanduser("~")

        self.log_result(self.files_result_text, f"[*] Escaneando arquivos em {path}...")
        
        if os.path.isfile(path):
            try:
                file_name = os.path.basename(path)
                if any(file_name.lower().endswith(ext) for ext in suspicious_extensions):
                    suspicious.append(f"Arquivo potencialmente suspeito (extensão): {path}")
            except (PermissionError, IOError, MemoryError, Exception) as e:
                self.log_result(self.files_result_text, f"[!] Erro ao escanear {path}: {str(e)}")
                return suspicious
        elif os.path.isdir(path):
            for root, _, files in os.walk(path, topdown=True, onerror=None):
                for file in files[:50]:
                    file_path = os.path.join(root, file)
                    if self.cancel_files:
                        return suspicious  
                    try:
                        file_name = os.path.basename(file_path)
                        if any(file_name.lower().endswith(ext) for ext in suspicious_extensions):
                            suspicious.append(f"Arquivo potencialmente suspeito (extensão): {file_path}")
                    except (PermissionError, IOError, MemoryError, Exception) as e:
                        self.log_result(self.files_result_text, f"[!] Erro ao escanear {file_path}: {str(e)}")
                        continue
        else:
            self.log_result(self.files_result_text, f"[!] Caminho inválido: {path}")

        self.log_result(self.files_result_text, f"[DEBUG] Checagem de arquivos concluída com {len(suspicious)} resultados.")
        return suspicious

    def browse_directory(self):
        directory = filedialog.askdirectory(title="Selecione uma pasta para escanear")
        if directory:
            self.path_entry.delete(0, "end")
            self.path_entry.insert(0, directory)

    def cancel_computer_scan(self):
        self.cancel_computer = True
        self.cancel_computer_button.configure(state="disabled")
        self.log_result(self.computer_result_text, "[*] Escaneamento do computador cancelado.")

    def cancel_files_scan(self):
        self.cancel_files = True
        self.cancel_files_button.configure(state="disabled")
        self.log_result(self.files_result_text, "[*] Escaneamento de arquivos cancelado.")

    def scan_computer(self):
        self.computer_result_text.delete("0.0", "end")
        self.log_result(self.computer_result_text, "[*] Iniciando escaneamento do computador...\n")

        self.scanning_computer = True
        self.cancel_computer = False
        self.scan_computer_button.configure(state="disabled")
        self.cancel_computer_button.configure(state="normal")
        self.computer_progress.start()

        try:
            
            self.log_result(self.computer_result_text, "Checando câmeras e microfones...")
            cam_mic_results = []
            for proc in psutil.process_iter(['pid', 'name']):
                if self.cancel_computer:
                    self.log_result(self.computer_result_text, "[!] Scan cancelado pelo usuário.")
                    break
                name = proc.info['name'].lower()
                if any(keyword in name for keyword in ["cam", "mic", "video", "audio"]):
                    cam_mic_results.append(f"Possível acesso a câmera/microfone: {name} (PID: {proc.info['pid']})")
            if self.cancel_computer:
                return
            if cam_mic_results:
                self.log_result(self.computer_result_text, "[!] Alertas de câmera/microfone:")
                for result in cam_mic_results:
                    self.log_result(self.computer_result_text, f"- {result}")
            else:
                self.log_result(self.computer_result_text, "[✓] Nenhum acesso suspeito a câmera/microfone.")

         
            self.log_result(self.computer_result_text, "\nChecando conexões de rede ativas...")
            net_results = []
            for conn in psutil.net_connections(kind='inet'):
                if self.cancel_computer:
                    self.log_result(self.computer_result_text, "[!] Scan cancelado pelo usuário.")
                    break
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    ip = conn.raddr.ip
                    if not ip.startswith(("192.168", "127.", "10.")):
                        hostname = self.resolve_ip(ip)
                        net_results.append(f"Conexão ativa com {hostname} ({ip}:{conn.raddr.port}) (PID: {conn.pid})")
            if self.cancel_computer:
                return
            if net_results:
                self.log_result(self.computer_result_text, "[!] Conexões de rede suspeitas:")
                for result in net_results:
                    self.log_result(self.computer_result_text, f"- {result}")
            else:
                self.log_result(self.computer_result_text, "[✓] Nenhuma conexão suspeita detectada.")

          
            self.log_result(self.computer_result_text, "\nChecando por malwares em processos...")
            mal_results = []
            malware_signatures = ["virus", "trojan", "spy", "malware", "keylogger"]
            for proc in psutil.process_iter(['pid', 'name']):
                if self.cancel_computer:
                    self.log_result(self.computer_result_text, "[!] Scan cancelado pelo usuário.")
                    break
                name = proc.info['name'].lower()
                if any(sig in name for sig in malware_signatures):
                    mal_results.append(f"Possível malware detectado: {name} (PID: {proc.info['pid']})")
            if self.cancel_computer:
                return
            if mal_results:
                self.log_result(self.computer_result_text, "[!] Possíveis malwares detectados:")
                for result in mal_results:
                    self.log_result(self.computer_result_text, f"- {result}")
            else:
                self.log_result(self.computer_result_text, "[✓] Nenhum malware óbvio detectado.")
        except Exception as e:
            self.log_result(self.computer_result_text, f"[!] Erro durante o escaneamento do computador: {str(e)}")

        if not self.cancel_computer:
            self.log_result(self.computer_result_text, "\n[✓] Escaneamento do computador concluído.")
            log_text = self.computer_result_text.get("0.0", "end").strip()
            self.save_logs(log_text, "Computador")
        else:
            self.log_result(self.computer_result_text, "[!] Escaneamento cancelado antes de concluir.")

        self.computer_progress.stop()
        self.scanning_computer = False
        self.cancel_computer = False
        self.scan_computer_button.configure(state="normal")
        self.cancel_computer_button.configure(state="disabled")

    def scan_files(self):
        self.files_result_text.delete("0.0", "end")
        self.log_result(self.files_result_text, "[*] Iniciando escaneamento de arquivos...\n")

        self.scanning_files = True
        self.cancel_files = False
        self.scan_files_button.configure(state="disabled")
        self.cancel_files_button.configure(state="normal")
        self.scan_computer_button.configure(state="disabled")
        self.files_progress.start()

        path = self.path_entry.get().strip() or None
        file_results = self.check_files(path)
        if not self.cancel_files:
            if file_results:
                self.log_result(self.files_result_text, "\n[!] Arquivos Suspeitos Detectados:")
                for result in file_results:
                    self.log_result(self.files_result_text, f"- {result}")
            else:
                self.log_result(self.files_result_text, "\n[✓] Nenhum arquivo suspeito detectado.")

            self.log_result(self.files_result_text, "\n[✓] Escaneamento de arquivos concluído.")
            log_text = self.files_result_text.get("0.0", "end").strip()
            self.save_logs(log_text, "Arquivos")
        else:
            self.log_result(self.files_result_text, "[!] Escaneamento cancelado antes de concluir.")

        self.files_progress.stop()
        self.scanning_files = False
        self.cancel_files = False
        self.scan_files_button.configure(state="normal")
        self.cancel_files_button.configure(state="disabled")
        self.scan_computer_button.configure(state="normal")

    def start_scan_computer(self):
        if not self.scanning_computer:
            thread = threading.Thread(target=self.scan_computer)
            thread.daemon = True
            thread.start()

    def start_scan_files(self):
        if not self.scanning_files:
            thread = threading.Thread(target=self.scan_files)
            thread.daemon = True
            thread.start()

def main():
    root = ctk.CTk()
    app = SecurityScanner(root)
    root.mainloop()

if __name__ == "__main__":
    main()
