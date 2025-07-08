# Port scanning logic
import time
import nmap # Importation de la bibliothèque python-nmap
from src.utils.logger import log_event
from src.utils.alerter import generate_alert
from config.settings import NMAP_SCAN_TARGETS, NMAP_SCAN_INTERVAL_SECONDS, \
                            NMAP_PORTS_TO_SCAN, ALLOWED_OPEN_PORTS, NMAP_SCAN_OPTIONS

class PortScanner:
    """
    Service de scan de ports utilisant Nmap pour identifier les services actifs
    et détecter l'ouverture inopinée de ports.
    """
    def __init__(self):
        # Initialisation de Nmap.PortScanner. Le chemin de l'exécutable Nmap est normalement trouvé
        # si Nmap est dans le PATH système.
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError as e:
            # Cette erreur se produit si Nmap n'est pas trouvé ou si une autre erreur d'initialisation survient.
            log_event("PORT_SCANNER", "INIT_ERROR", "N/A", f"Erreur lors de l'initialisation de Nmap: {e}. Assurez-vous que Nmap est installé et dans le PATH.", level="CRITICAL")
            raise Exception(f"Nmap n'est pas trouvé ou ne peut pas être initialisé. Erreur: {e}")

        self.scan_targets = NMAP_SCAN_TARGETS
        self.scan_interval = NMAP_SCAN_INTERVAL_SECONDS
        self.ports_to_scan = NMAP_PORTS_TO_SCAN
        self.allowed_ports = set(ALLOWED_OPEN_PORTS)
        self.scan_options = NMAP_SCAN_OPTIONS
        self.logger = log_event
        self.alerter = generate_alert
        self.service_name = "PORT_SCANNER"
        self.last_known_open_ports = {} # Dictionnaire pour suivre les ports par hôte
        self.running = False

        self.logger(self.service_name, "INIT", "N/A",
                    f"Initialisation du scanner de ports Nmap. Cibles: {self.scan_targets}, Ports: {self.ports_to_scan}, Options: '{self.scan_options}', Intervalle: {self.scan_interval}s.")

    def run_scan_cycle(self):
        """
        Exécute un cycle de scan Nmap complet pour les cibles configurées
        et compare les résultats avec les ports autorisés.
        """
        self.logger(self.service_name, "SCANNING", "N/A", f"Lancement du scan Nmap sur {self.scan_targets} pour les ports {self.ports_to_scan} avec options '{self.scan_options}'...")
        print(f"[*] Lancement du scan Nmap sur {self.scan_targets}...")

        try:
            # Exécute le scan Nmap
            # arguments='-sV' ajoute la détection de version de service
            # '-oX -' est implicite avec python-nmap pour obtenir les résultats en XML
            self.nm.scan(hosts=self.scan_targets, ports=self.ports_to_scan, arguments=self.scan_options)

            for host in self.nm.all_hosts():
                current_open_ports = set()
                host_state = self.nm[host].state() # 'up' or 'down'

                if host_state == 'up':
                    # Traitement des ports TCP
                    if 'tcp' in self.nm[host]:
                        for port in self.nm[host]['tcp']:
                            port_state = self.nm[host]['tcp'][port]['state']
                            if port_state == 'open':
                                current_open_ports.add(port)
                                service_name = self.nm[host]['tcp'][port].get('name', 'N/A')
                                service_product = self.nm[host]['tcp'][port].get('product', 'N/A')
                                service_version = self.nm[host]['tcp'][port].get('version', 'N/A')
                                self.logger(self.service_name, "PORT_OPEN_TCP", f"{host}:{port}",
                                            f"Port TCP {port} ouvert. Service: {service_name}, Produit: {service_product}, Version: {service_version}")
                    # Traitement des ports UDP (si inclus dans les options de scan)
                    if 'udp' in self.nm[host]:
                        for port in self.nm[host]['udp']:
                            port_state = self.nm[host]['udp'][port]['state']
                            if port_state == 'open':
                                current_open_ports.add(port) # Note: UDP is harder to determine "open" vs "open|filtered"
                                service_name = self.nm[host]['udp'][port].get('name', 'N/A')
                                self.logger(self.service_name, "PORT_OPEN_UDP", f"{host}:{port}",
                                            f"Port UDP {port} ouvert. Service: {service_name}")

                self.logger(self.service_name, "SCAN_RESULT", host, f"Ports ouverts détectés sur {host}: {sorted(list(current_open_ports))}")

                # Comparaison avec l'état précédent pour cet hôte
                last_known_ports_for_host = self.last_known_open_ports.get(host, set())

                # Détecter les nouveaux ports ouverts (non connus auparavant ou non autorisés)
                newly_opened_ports = current_open_ports - last_known_ports_for_host - self.allowed_ports
                if newly_opened_ports:
                    description = f"Nouveaux ports inattendus ouverts sur {host}: {sorted(list(newly_opened_ports))}"
                    self.logger(self.service_name, "NEW_UNEXPECTED_PORT", host, description, level="CRITICAL")
                    self.alerter(self.service_name, "UNEXPECTED_PORT_OPEN", host, description,
                                 severity="HIGH", metadata={"host": host, "ports": list(newly_opened_ports)})

                # Détecter les ports fermés qui étaient connus auparavant
                closed_ports = last_known_ports_for_host - current_open_ports
                if closed_ports:
                    description = f"Ports précédemment ouverts et maintenant fermés sur {host}: {sorted(list(closed_ports))}"
                    self.logger(self.service_name, "PORT_CLOSED", host, description, level="INFO")
                    # Une alerte de niveau inférieur pourrait être générée ici si la fermeture est suspecte.

                # Détecter les ports ouverts qui sont autorisés.
                expected_but_open = current_open_ports.intersection(self.allowed_ports)
                if expected_but_open:
                    self.logger(self.service_name, "EXPECTED_PORTS_OPEN", host, f"Ports attendus ouverts sur {host}: {sorted(list(expected_but_open))}", level="INFO")

                # Mise à jour de l'état connu pour cet hôte
                self.last_known_open_ports[host] = current_open_ports

        except nmap.PortScannerError as e:
            self.logger(self.service_name, "SCAN_ERROR", self.scan_targets, f"Erreur de scan Nmap: {e}. Vérifiez les permissions (exécutez en admin ?), les arguments Nmap et si la cible est atteignable.", level="CRITICAL")
            self.alerter(self.service_name, "NMAP_SCAN_FAILED", self.scan_targets, f"Le scan Nmap a échoué: {e}", severity="CRITICAL")
        except Exception as e:
            self.logger(self.service_name, "UNKNOWN_ERROR", "N/A", f"Erreur inattendue lors du scan de ports: {e}", level="CRITICAL")
            self.alerter(self.service_name, "PORT_SCAN_CRASH", "N/A", f"Le scanner de ports a rencontré une erreur: {e}", severity="CRITICAL")

    def start(self):
        """Démarre le processus de scan périodique."""
        self.running = True
        self.logger(self.service_name, "STARTUP", "N/A", "Démarrage du scanner de ports Nmap.")
        print("[*] Démarrage du service de surveillance des ports Nmap...")
        try:
            while self.running:
                self.run_scan_cycle()
                self.logger(self.service_name, "IDLE", "N/A", f"Prochain scan dans {self.scan_interval} secondes.")
                time.sleep(self.scan_interval)
        except KeyboardInterrupt:
            self.stop()
        except Exception as e:
            self.logger(self.service_name, "CRASH", "N/A", f"Le scanner de ports a rencontré une erreur critique: {e}", level="CRITICAL")
            self.alerter(self.service_name, "SERVICE_CRASH", "N/A", f"Le scanner de ports a planté: {e}", severity="CRITICAL")
            self.stop()

    def stop(self):
        """Arrête le scanner."""
        self.running = False
        self.logger(self.service_name, "SHUTDOWN", "N/A", "Scanner de ports Nmap arrêté.")
        print("[*] Scanner de ports Nmap arrêté.")