# Process monitoring logic
import psutil
import time
import os
from src.utils.logger import log_event
from src.utils.alerter import generate_alert
from config.settings import PROCESS_MONITOR_INTERVAL_SECONDS, \
                            WHITELISTED_PROCESS_NAMES, \
                            SUSPICIOUS_CPU_THRESHOLD_PERCENT, \
                            SUSPICIOUS_MEMORY_THRESHOLD_PERCENT

class ProcessMonitor:
    """
    Service de surveillance des processus pour détecter les programmes inconnus ou suspects.
    """
    def __init__(self):
        self.scan_interval = PROCESS_MONITOR_INTERVAL_SECONDS
        self.whitelisted_process_names = set(WHITELISTED_PROCESS_NAMES)
        self.suspicious_cpu_threshold = SUSPICIOUS_CPU_THRESHOLD_PERCENT
        self.suspicious_memory_threshold = SUSPICIOUS_MEMORY_THRESHOLD_PERCENT
        self.logger = log_event
        self.alerter = generate_alert
        self.service_name = "PROCESS_MONITOR"
        self.last_known_processes = {} # Dictionnaire {pid: process_name} pour suivre les processus
        self.running = False

        self.logger(self.service_name, "INIT", "N/A",
                    f"Initialisation du moniteur de processus. Intervalle: {self.scan_interval}s.")

    def _get_process_info(self, p):
        """Tente de récupérer les informations nécessaires d'un processus psutil."""
        info = {
            'pid': p.pid,
            'name': p.name(),
            'status': p.status(),
            'username': 'N/A', # Par défaut
            'exe': 'N/A',      # Par défaut
            'cmdline': 'N/A',  # Par défaut
            'cpu_percent': 0.0,
            'memory_percent': 0.0
        }
        try:
            info['username'] = p.username()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass # L'accès refusé est courant pour les processus système
        try:
            info['exe'] = p.exe()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        try:
            info['cmdline'] = ' '.join(p.cmdline()) if p.cmdline() else 'N/A'
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        # Ces méthodes peuvent lever NoSuchProcess si le processus meurt entre l'itération et l'appel
        try:
            info['cpu_percent'] = p.cpu_percent(interval=None) # Non-blocking call
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        try:
            info['memory_percent'] = p.memory_percent()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        return info

    def run_scan_cycle(self):
        """
        Exécute un cycle de scan complet des processus en cours d'exécution.
        """
        current_processes = {} # {pid: process_name}
        self.logger(self.service_name, "SCANNING", "N/A", "Scan des processus en cours...")
        print("[*] Scan des processus en cours...")

        for p in psutil.process_iter(['pid', 'name', 'status', 'username', 'exe', 'cmdline']):
            try:
                process_info = self._get_process_info(p)
                pid = process_info['pid']
                name = process_info['name']
                exe_path = process_info['exe']
                username = process_info['username']
                cpu_percent = process_info['cpu_percent']
                memory_percent = process_info['memory_percent']

                current_processes[pid] = name

                # Détection de processus inconnu (non-whitelisté)
                if name not in self.whitelisted_process_names:
                    description = (f"Processus inconnu détecté: PID={pid}, Nom='{name}', "
                                   f"Utilisateur='{username}', Exe='{exe_path}', "
                                   f"CPU={cpu_percent:.2f}%, RAM={memory_percent:.2f}%")
                    self.logger(self.service_name, "UNKNOWN_PROCESS", str(pid), description, level="WARNING")
                    self.alerter(self.service_name, "UNKNOWN_PROCESS_DETECTED", str(pid), description,
                                 severity="MEDIUM", metadata=process_info)

                # Détection de consommation de ressources suspecte
                if (cpu_percent > self.suspicious_cpu_threshold or
                    memory_percent > self.suspicious_memory_threshold):
                    description = (f"Processus utilisant des ressources de manière suspecte: PID={pid}, Nom='{name}', "
                                   f"Utilisateur='{username}', CPU={cpu_percent:.2f}%, RAM={memory_percent:.2f}%")
                    self.logger(self.service_name, "SUSPICIOUS_RESOURCE_USAGE", str(pid), description, level="WARNING")
                    self.alerter(self.service_name, "SUSPICIOUS_RESOURCE_USAGE", str(pid), description,
                                 severity="MEDIUM", metadata=process_info)


            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                # Cela peut arriver si un processus se termine juste après l'itération,
                # ou si nous n'avons pas les permissions pour certaines infos.
                # Ce n'est pas toujours une erreur critique.
                self.logger(self.service_name, "PROCESS_ACCESS_ERROR", str(p.pid), f"Impossible d'accéder aux infos du processus {p.pid}: {e}", level="DEBUG")
            except Exception as e:
                self.logger(self.service_name, "PROCESS_SCAN_ERROR", "N/A", f"Erreur inattendue lors de la récupération d'un processus: {e}", level="ERROR")

        # Détecter les nouveaux processus apparus
        newly_started_pids = set(current_processes.keys()) - set(self.last_known_processes.keys())
        for pid in newly_started_pids:
            name = current_processes[pid]
            # Si le processus est inconnu, l'alerte a déjà été générée au-dessus
            if name in self.whitelisted_process_names:
                self.logger(self.service_name, "NEW_PROCESS_STARTED", str(pid), f"Nouveau processus légitime démarré: PID={pid}, Nom='{name}'", level="INFO")

        # Détecter les processus qui ont disparu
        terminated_pids = set(self.last_known_processes.keys()) - set(current_processes.keys())
        for pid in terminated_pids:
            name = self.last_known_processes[pid]
            self.logger(self.service_name, "PROCESS_TERMINATED", str(pid), f"Processus terminé: PID={pid}, Nom='{name}'", level="INFO")
            # Une alerte pourrait être générée si un processus critique disparaît

        self.last_known_processes = current_processes # Mettre à jour l'état

    def start(self):
        """Démarre le processus de surveillance périodique."""
        self.running = True
        self.logger(self.service_name, "STARTUP", "N/A", "Démarrage du moniteur de processus.")
        print("[*] Démarrage du service de surveillance des processus...")
        try:
            # Exécuter un premier scan CPU pour avoir des données valides pour cpu_percent()
            # psutil.cpu_percent() nécessite d'être appelé deux fois pour des valeurs non nulles
            psutil.cpu_percent(interval=None, percpu=True)
            time.sleep(0.1) # Petite pause avant le premier scan réel

            while self.running:
                self.run_scan_cycle()
                self.logger(self.service_name, "IDLE", "N/A", f"Prochain scan de processus dans {self.scan_interval} secondes.")
                time.sleep(self.scan_interval)
        except KeyboardInterrupt:
            self.stop()
        except Exception as e:
            self.logger(self.service_name, "CRASH", "N/A", f"Le moniteur de processus a rencontré une erreur critique: {e}", level="CRITICAL")
            self.alerter(self.service_name, "SERVICE_CRASH", "N/A", f"Le moniteur de processus a planté: {e}", severity="CRITICAL")
            self.stop()

    def stop(self):
        """Arrête le moniteur."""
        self.running = False
        self.logger(self.service_name, "SHUTDOWN", "N/A", "Moniteur de processus arrêté.")
        print("[*] Moniteur de processus arrêté.")