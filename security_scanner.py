import psutil
import socket
import customtkinter as ctk
import threading
import time
import os

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

        self.scan_button = ctk.CTkButton(self.main_frame, text="Iniciar Escaneamento",
                                         command=self.start_scan, font=("Helvetica", 14, "bold"),
                                         corner_radius=8, height=40)
        self.scan_button.pack(pady=15)

        self.result_text = ctk.CTkTextbox(self.main_frame, width=700, height=250,
                                          font=("Consolas", 12), corner_radius=8)
        self.result_text.pack(pady=15)

        self.progress = ctk.CTkProgressBar(self.main_frame, width=600, mode="indeterminate")
        self.progress.pack(pady=10)
        self.scanning = False

    def log_result(self, message, delay=0.5):
        """Exibe mensagem na interface com um pequeno delay."""
        self.result_text.insert("end", message + "\n")
        self.result_text.update()
        time.sleep(delay)

    def check_camera_mic(self):
        suspicious = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                name = proc.info['name'].lower()
                if any(keyword in name for keyword in ["cam", "mic", "video", "audio"]):
                    suspicious.append(f"Possível acesso a câmera/microfone: {name} (PID: {proc.info['pid']})")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return suspicious

    def resolve_ip(self, ip):
        """Tenta obter o nome do host a partir do IP"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return ip

    def check_network(self):
        suspicious = []
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and conn.raddr:
                ip = conn.raddr.ip
                if ip.startswith(("192.168", "127.", "10.")):  # Ignorar redes locais
                    continue
                
                hostname = self.resolve_ip(ip)  # Resolver nome do host
                
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
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return suspicious

    def scan_system(self):
        self.result_text.delete("0.0", "end")
        self.log_result("[*] Iniciando escaneamento do sistema...\n")

        self.scanning = True
        self.scan_button.configure(state="disabled")
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

        self.log_result("\n[✓] Escaneamento concluído.")

       
        with open("security_report.txt", "w") as f:
            f.write(self.result_text.get("0.0", "end"))

        self.progress.stop()
        self.scanning = False
        self.scan_button.configure(state="normal")

    def start_scan(self):
        if not self.scanning:
            thread = threading.Thread(target=self.scan_system)
            thread.start()


def main():
    root = ctk.CTk()
    app = SecurityScanner(root)
    root.mainloop()


if __name__ == "__main__":
    main()
