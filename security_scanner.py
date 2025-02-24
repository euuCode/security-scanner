import psutil
import socket
import customtkinter as ctk
import threading
import time
import os
import hashlib
import tkinter as tk  
import csv  

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

class SecurityScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Security Scanner - by euuCode")
        self.root.geometry("800x500")
        self.root.resizable(False, False)

        self.main_frame = ctk.CTkFrame(root, corner_radius=10)
        self.main_frame.pack(pady=20, padx=20, fill="both", expand=True)

        self.title_label = ctk.CTkLabel(self.main_frame, text="Security Scanner",
                                        font=("Helvetica", 24, "bold"))
        self.title_label.pack(pady=10)

      
        self.path_frame = ctk.CTkFrame(self.main_frame, corner_radius=8)
        self.path_frame.pack(pady=10)

        self.path_entry = ctk.CTkEntry(self.path_frame, width=500, height=35, font=("Helvetica", 12),
                                       placeholder_text="Insira o caminho de uma pasta ou arquivo",
                                       corner_radius=8, fg_color="#3a3a3a", text_color="#e0e0e0")
        self.path_entry.pack(side=tk.LEFT, padx=5)

        self.browse_button = ctk.CTkButton(self.path_frame, text="Selecionar Pasta",
                                           command=self.browse_directory, font=("Helvetica", 12, "bold"),
                                           corner_radius=8, height=35, fg_color="#4CAF50", hover_color="#45a049")
        self.browse_button.pack(side=tk.LEFT, padx=5)

       
        self.scan_intruders_button = ctk.CTkButton(self.main_frame, text="Scanner de Intrusos",
                                                   command=self.start_scan_intruders, font=("Helvetica", 14, "bold"),
                                                   corner_radius=8, height=40, fg_color="#4CAF50",
                                                   hover_color="#45a049")
        self.scan_intruders_button.pack(pady=5)

        self.scan_files_button = ctk.CTkButton(self.main_frame, text="Scanner de Arquivos",
                                               command=self.start_scan_files, font=("Helvetica", 14, "bold"),
                                               corner_radius=8, height=40, fg_color="#2196F3",
                                               hover_color="#1976D2")
        self.scan_files_button.pack(pady=5)

        self.result_text = ctk.CTkTextbox(self.main_frame, width=700, height=250,
                                          font=("Consolas", 12), corner_radius=8, state="disabled")
        self.result_text.pack(pady=15)

        self.progress = ctk.CTkProgressBar(self.main_frame, width=600, mode="indeterminate")
        self.progress.pack(pady=10)
        self.scanning = False

    def log_result(self, message, delay=0.1):
        self.result_text.configure(state="normal")
        self.result_text.insert("end", message + "\n")
        self.result_text.configure(state="disabled")
        self.result_text.update()
        time.sleep(delay)

    def check_camera_mic(self):
        suspicious = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                name = proc.info['name'].lower()
                if any(keyword in name for keyword in ["cam", "mic", "video", "audio"]):
                    suspicious.append(f"Possível acesso a câmera/microfone: {name} (PID: {proc.info['pid']})")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return suspicious

    def resolve_ip(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return ip

    def check_network(self):
        suspicious = []
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and conn.raddr:
                ip = conn.raddr.ip
                if ip.startswith(("192.168", "127.", "10.")):
                    continue
                
                hostname = self.resolve_ip(ip)
                suspicious.append(f"Conexão ativa com {hostname} ({ip}:{conn.raddr.port}) (PID: {conn.pid})")
        return suspicious

    def check_malware(self):
        suspicious = []
        malware_signatures = ["virus", "trojan", "spy", "malware", "keylogger"]
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                name = proc.info['name'].lower()
                if any(sig in name for sig in malware_signatures):
                    suspicious.append(f"Possível malware detectado: {name} (PID: {proc.info['pid']})")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
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
            self.log_result("[!] Arquivo malware_hashes.csv não encontrado. Usando hashes padrão.")

        if not path:
            path = os.path.expanduser("~")

        self.log_result(f"[*] Escaneando arquivos em {path}...")
        
        if os.path.isfile(path):
            try:
                file_name = os.path.basename(path)
                if any(file_name.lower().endswith(ext) for ext in suspicious_extensions):
                    suspicious.append(f"Arquivo potencialmente suspeito (extensão): {path}")
                
                with open(path, "rb") as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                if file_hash in malware_hashes:
                    suspicious.append(f"Arquivo suspeito: {path} (Possível {malware_hashes[file_hash]})")
            except (PermissionError, IOError, MemoryError):
                self.log_result(f"[!] Erro ao escanear {path} - Permissão negada, inacessível ou muito grande.")
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
                    except (PermissionError, IOError, MemoryError):
                        self.log_result(f"[!] Erro ao escanear {file_path} - Permissão negada, inacessível ou muito grande.")
                        continue
                    except Exception as e:
                        self.log_result(f"[!] Erro inesperado ao escanear {file_path}: {str(e)}")
                        continue
        else:
            self.log_result(f"[!] Caminho inválido: {path}")

        return suspicious

    def browse_directory(self):
        directory = filedialog.askdirectory(title="Selecione uma pasta para escanear")
        if directory:
            self.path_entry.delete(0, "end")
            self.path_entry.insert(0, directory)

    def scan_intruders(self):
        self.result_text.delete("0.0", "end")
        self.log_result("[*] Iniciando escaneamento de intrusos...\n")

        self.scanning = True
        self.scan_intruders_button.configure(state="disabled")
        self.scan_files_button.configure(state="disabled")
        self.progress.start()

        cam_mic_results = self.check_camera_mic()
        if cam_mic_results:
            self.log_result("[!] Alertas de câmera/microfone:")
            for result in cam_mic_results:
                self.log_result(f"- {result}")
        else:
            self.log_result("[✓] Nenhum acesso suspeito a câmera/microfone.")

        net_results = self.check_network()
        if net_results:
            self.log_result("\n[!] Conexões de rede suspeitas:")
            for result in net_results:
                self.log_result(f"- {result}")
        else:
            self.log_result("\n[✓] Nenhuma conexão suspeita detectada.")

        mal_results = self.check_malware()
        if mal_results:
            self.log_result("\n[!] Possíveis malwares detectados:")
            for result in mal_results:
                self.log_result(f"- {result}")
        else:
            self.log_result("\n[✓] Nenhum malware óbvio detectado.")

        self.log_result("\n[✓] Escaneamento de intrusos concluído.")

        desktop_path = os.path.expanduser("~") + "/Desktop/intruders_report.txt"
        with open(desktop_path, "w") as f:
            f.write(self.result_text.get("0.0", "end"))

        self.progress.stop()
        self.scanning = False
        self.scan_intruders_button.configure(state="normal")
        self.scan_files_button.configure(state="normal")

    def scan_files(self):
        self.result_text.delete("0.0", "end")
        self.log_result("[*] Iniciando escaneamento de arquivos...\n")

        self.scanning = True
        self.scan_intruders_button.configure(state="disabled")
        self.scan_files_button.configure(state="disabled")
        self.progress.start()

        path = self.path_entry.get().strip() or None
        file_results = self.check_files(path)
        if file_results:
            self.log_result("\n[!] Arquivos Suspeitos Detectados:")
            for result in file_results:
                self.log_result(f"- {result}")
        else:
            self.log_result("\n[✓] Nenhum arquivo suspeito detectado.")

        self.log_result("\n[✓] Escaneamento de arquivos concluído.")

        desktop_path = os.path.expanduser("~") + "/Desktop/files_report.txt"
        with open(desktop_path, "w") as f:
            f.write(self.result_text.get("0.0", "end"))

        self.progress.stop()
        self.scanning = False
        self.scan_intruders_button.configure(state="normal")
        self.scan_files_button.configure(state="normal")

    def start_scan_intruders(self):
        if not self.scanning:
            thread = threading.Thread(target=self.scan_intruders)
            thread.start()

    def start_scan_files(self):
        if not self.scanning:
            thread = threading.Thread(target=self.scan_files)
            thread.start()

def main():
    root = ctk.CTk()
    app = SecurityScanner(root)
    root.mainloop()

if __name__ == "__main__":
    main()
