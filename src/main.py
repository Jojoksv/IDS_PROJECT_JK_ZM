import threading
import time
import os
from src.core.watchdog_monitor import FileMonitor
from src.core.port_scanner import PortScanner
from src.core.process_monitor import ProcessMonitor
from src.core.report_generator import ReportGenerator
from src.utils.logger import log_event
from config.settings import CRITICAL_FILE_PATHS

# Fonctions wrapper pour les threads
def run_file_monitor_service_thread(path_to_monitor, sensitive_global_paths):
    all_paths_to_watch = [path_to_monitor] + sensitive_global_paths
    file_monitor = FileMonitor(all_paths_to_watch)
    file_monitor.start()

def run_port_scanner_service_thread():
    port_scanner = PortScanner()
    port_scanner.start()

def run_process_monitor_service_thread():
    process_monitor = ProcessMonitor()
    process_monitor.start()

def run_report_generator_service_thread():
    report_generator = ReportGenerator()
    report_generator.start()

def main():
    log_event("MAIN", "STARTUP", "N/A", "Démarrage du système IDS.")
    print("Bienvenue dans le système de détection d'intrusion (IDS) simplifié.\n")

    # Vérification des droits pour Nmap (recommandé pour -sS, -O)
    if os.name != 'nt' and hasattr(os, 'geteuid'):
        if os.geteuid() != 0:
            print("[!] Attention : certains scans Nmap (ex: -sS, -O) nécessitent les droits administrateur (root/sudo).\n")

    threads = []

    # --- Configuration et lancement du Moniteur de Fichiers ---
    path_to_monitor = input("Chemin absolu du dossier/fichier à surveiller (ex: /home/user/Documents/IDS_Test): ").strip()
    path_to_monitor = os.path.abspath(path_to_monitor)

    # Vérifier que le chemin existe
    if not os.path.exists(path_to_monitor):
        print(f"[!] Le chemin spécifié n'existe pas : {path_to_monitor}")
        return

    effective_critical_paths = [p for p in CRITICAL_FILE_PATHS if os.path.exists(p)]

    file_monitor_thread = threading.Thread(
        target=run_file_monitor_service_thread,
        args=(path_to_monitor, effective_critical_paths),
        name="FileMonitorThread"
    )
    threads.append(file_monitor_thread)

    # --- Lancement du Scanner de Ports ---
    port_scanner_thread = threading.Thread(
        target=run_port_scanner_service_thread,
        name="PortScannerThread"
    )
    threads.append(port_scanner_thread)

    # --- Lancement du Moniteur de Processus ---
    process_monitor_thread = threading.Thread(
        target=run_process_monitor_service_thread,
        name="ProcessMonitorThread"
    )
    threads.append(process_monitor_thread)

    # --- Lancement du Générateur de Rapports ---
    report_generator_thread = threading.Thread(
        target=run_report_generator_service_thread,
        name="ReportGeneratorThread"
    )
    threads.append(report_generator_thread)

    # --- Démarrage de tous les services IDS ---
    for t in threads:
        t.daemon = True
        t.start()

    print("\n[*] Tous les services IDS sont démarrés.")
    print("[*] Appuyez sur CTRL+C pour arrêter le système.")
    log_event("MAIN", "STATUS", "N/A", "Tous les services IDS ont été lancés.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log_event("MAIN", "SHUTDOWN", "N/A", "Système IDS arrêté par l'utilisateur.")
        print("\n[*] Système IDS arrêté proprement.")
    except Exception as e:
        log_event("MAIN", "CRASH", "N/A", f"Erreur critique dans le système principal : {e}", level="CRITICAL")

if __name__ == "__main__":
    main()

