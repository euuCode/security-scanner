import psutil
import socket
import customtkinter as ctk
import threading
import time
import os
import hashlib
import tkinter as tk
import csv
from tkinter import filedialog

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

      
        self.computer_frame = ctk.CTkFrame(self.computer_tab, corner_radius=15, fg_color="#1e1e1e")
        self.computer_frame.pack(pady=20, padx=20, fill="both", expand=True)

        self.scan_computer_button = ctk.CTkButton(self.computer_frame, text="Escanear Computador",
                                                  command=self.start_scan_computer, font=("Helvetica", 16, "bold"),
                                                  corner_radius=15, height=45, fg_color="#4CAF50",
                                                  hover_color="#45a049", border_width=0)
        self.scan_computer_button.pack(pady=20)

        self.computer_result_text = ctk.CTkTextbox(self.computer_frame, width=700, height=250,
                                                   font=("Consolas", 14), corner_radius=15, state="disabled",
                                                   fg_color="#2b2b2b", text_color="#e0e0e0", border_width=2,
                                                   border_color="#4CAF50")
        self.computer_result_text.pack(pady=20, padx=20)

        self.computer_progress = ctk.CTkProgressBar(self.computer_frame, width=700, mode="indeterminate", corner_radius=15,
                                                    progress_color="#4CAF50", fg_color="#3a3a3a")
        self.computer_progress.pack(pady=15)

        self.files_frame = ctk.CTkFrame(self.files_tab, corner_radius=15, fg_color="#1e1e1e")
        self.files_frame.pack(pady=20, padx=20, fill="both", expand=True)

        self.path_frame = ctk.CTkFrame(self.files_frame, corner_radius=15, fg_color="#2b2b2b")
        self.path_frame.pack(pady=20, padx=20, fill="x")

        self.path_entry = ctk.CTkEntry(self.path_frame, width=600, height=40, font=("Helvetica", 14),
                                       placeholder_text="Insira o caminho de uma pasta ou arquivo",
                                       corner_radius=15, fg_color="#3a3a3a", text_color="#e0e0e0",
                                       border_width=2, border_color="#4CAF50")
        self.path_entry.pack(side=tk.LEFT, padx=10, pady=10)

        self.browse_button = ctk.CTkButton(self.path_frame, text="Selecionar Pasta",
                                           command=self.browse_directory, font=("Helvetica", 14, "bold"),
                                           corner_radius=15, height=40, fg_color="#4CAF50", hover_color="#45a049",
                                           border_width=0)
        self.browse_button.pack(side=tk.LEFT, padx=10, pady=10)

        self.scan_files_button = ctk.CTkButton(self.files_frame, text="Escanear Arquivos",
                                               command=self.start_scan_files, font=("Helvetica", 16, "bold"),
                                               corner_radius=15, height=45, fg_color="#2196F3",
                                               hover_color="#1976D2", border_width=0)
        self.scan_files_button.pack(pady=20)

        self.files_result_text = ctk.CTkTextbox(self.files_frame, width=700, height=250,
                                                font=("Consolas", 14), corner_radius=15, state="disabled",
                                                fg_color="#2b2b2b", text_color="#e0e0e0", border_width=2,
                                                border_color="#4CAF50")
        self.files_result_text.pack(pady=20, padx=20)

        self.files_progress = ctk.CTkProgressBar(self.files_frame, width=700, mode="indeterminate", corner_radius=15,
                                                 progress_color="#2196F3", fg_color="#3a3a3a")
        self.files_progress.pack(pady=15)

        self.scanning_computer = False
        self.scanning_files = False

    def log_result(self, text_widget, message, delay=0.1):
        text_widget.configure(state="normal")
        text_widget.insert("end", message + "\n")
        text_widget.configure(state="disabled")
        text_widget.update()
        time.sleep(delay)

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
        
        malware_hashes = {}
        try:
            with open('malware_hashes.csv', 'r', newline='') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    malware_hashes[row['hash']] = row['description']
        except FileNotFoundError:
            malware_hashes = {
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Trojan Example",
                "d41d8cd98f00b204e9800998ecf8427e": "Virus Sample"
            }
            self.log_result(self.files_result_text, "[!] Arquivo malware_hashes.csv não encontrado. Usando hashes padrão.")

        if not path:
            path = os.path.expanduser("~")

        self.log_result(self.files_result_text, f"[*] Escaneando arquivos em {path}...")
        
        if os.path.isfile(path):
            try:
                file_name = os.path.basename(path)
                if any(file_name.lower().endswith(ext) for ext in suspicious_extensions):
                    suspicious.append(f"Arquivo potencialmente suspeito (extensão): {path}")
                
                with open(path, "rb") as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                if file_hash in malware_hashes:
                    suspicious.append(f"Arquivo suspeito: {path} (Possível {malware_hashes[file_hash]})")
            except (PermissionError, IOError, MemoryError, Exception) as e:
                self.log_result(self.files_result_text, f"[!] Erro ao escanear {path}: {str(e)}")
                return suspicious
        elif os.path.isdir(path):
            for root, _, files in os.walk(path, topdown=True, onerror=None):
                for file in files[:50]:
                    file_path = os.path.join(root, file)
                    try:
                        file_name = os.path.basename(file_path)
                        if any(file_name.lower().endswith(ext) for ext in suspicious_extensions):
                            suspicious.append(f"Arquivo potencialmente suspeito (extensão): {file_path}")
                        
                        with open(file_path, "rb") as f:
                            file_hash = hashlib.sha256(f.read()).hexdigest()
                        if file_hash in malware_hashes:
                            suspicious.append(f"Arquivo suspeito: {file_path} (Possível {malware_hashes[file_hash]})")
                    except (PermissionError, IOError, MemoryError, Exception) as e:
                        self.log_result(self.files_result_text, f"[!] Erro ao escanear {file_path}: {str(e)}")
                        continue
        else:
            self.log_result(self.files_result_text, f"[!] Caminho inválido: {path}")

        return suspicious

    def browse_directory(self):
        directory = filedialog.askdirectory(title="Selecione uma pasta para escanear")
        if directory:
            self.path_entry.delete(0, "end")
            self.path_entry.insert(0, directory)

    def scan_computer(self):
        self.computer_result_text.delete("0.0", "end")
        self.log_result(self.computer_result_text, "[*] Iniciando escaneamento do computador...\n")

        self.scanning_computer = True
        self.scan_computer_button.configure(state="disabled")
        self.computer_progress.start()

        try:
            cam_mic_results = self.check_camera_mic()
            if cam_mic_results:
                self.log_result(self.computer_result_text, "[!] Alertas de câmera/microfone:")
                for result in cam_mic_results:
                    self.log_result(self.computer_result_text, f"- {result}")
            else:
                self.log_result(self.computer_result_text, "[✓] Nenhum acesso suspeito a câmera/microfone.")

            net_results = self.check_network()
            if net_results:
                self.log_result(self.computer_result_text, "\n[!] Conexões de rede suspeitas:")
                for result in net_results:
                    self.log_result(self.computer_result_text, f"- {result}")
            else:
                self.log_result(self.computer_result_text, "\n[✓] Nenhuma conexão suspeita detectada.")

            mal_results = self.check_malware()
            if mal_results:
                self.log_result(self.computer_result_text, "\n[!] Possíveis malwares detectados:")
                for result in mal_results:
                    self.log_result(self.computer_result_text, f"- {result}")
            else:
                self.log_result(self.computer_result_text, "\n[✓] Nenhum malware óbvio detectado.")
        except Exception as e:
            self.log_result(self.computer_result_text, f"[!] Erro durante o escaneamento do computador: {str(e)}")

        self.log_result(self.computer_result_text, "\n[✓] Escaneamento do computador concluído.")

        desktop_path = os.path.expanduser("~") + "/Desktop/computer_report.txt"
        with open(desktop_path, "w") as f:
            f.write(self.computer_result_text.get("0.0", "end"))

        self.computer_progress.stop()
        self.scanning_computer = False
        self.scan_computer_button.configure(state="normal")

    def scan_files(self):
        self.files_result_text.delete("0.0", "end")
        self.log_result(self.files_result_text, "[*] Iniciando escaneamento de arquivos...\n")

        self.scanning_files = True
        self.scan_files_button.configure(state="disabled")
        self.scan_computer_button.configure(state="disabled")
        self.files_progress.start()

        path = self.path_entry.get().strip() or None
        file_results = self.check_files(path)
        if file_results:
            self.log_result(self.files_result_text, "\n[!] Arquivos Suspeitos Detectados:")
            for result in file_results:
                self.log_result(self.files_result_text, f"- {result}")
        else:
            self.log_result(self.files_result_text, "\n[✓] Nenhum arquivo suspeito detectado.")

        self.log_result(self.files_result_text, "\n[✓] Escaneamento de arquivos concluído.")

        desktop_path = os.path.expanduser("~") + "/Desktop/files_report.txt"
        with open(desktop_path, "w") as f:
            f.write(self.files_result_text.get("0.0", "end"))

        self.files_progress.stop()
        self.scanning_files = False
        self.scan_files_button.configure(state="normal")
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
