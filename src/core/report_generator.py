import os
import time
import re
import requests
from datetime import datetime, timedelta
from collections import defaultdict

from src.utils.logger import log_event
from src.utils.alerter import generate_alert
from config.settings import REPORTS_DIR, LOG_FILE_PATH, \
                            REPORT_GENERATION_INTERVAL_SECONDS, \
                            REPORT_PERIOD_HOURS, MIN_REPORT_LEVEL

class ReportGenerator:
    """
    Service de génération de rapports périodiques à partir des logs de l'IDS.
    """
    def __init__(self):
        self.reports_dir = REPORTS_DIR
        self.log_file_path = LOG_FILE_PATH
        self.generation_interval = REPORT_GENERATION_INTERVAL_SECONDS
        self.report_period = timedelta(hours=REPORT_PERIOD_HOURS)
        self.min_report_level = self._get_level_value(MIN_REPORT_LEVEL)
        self.logger = log_event
        self.alerter = generate_alert
        self.service_name = "REPORT_GENERATOR"
        self.running = False

        # S'assurer que le dossier des rapports existe
        os.makedirs(self.reports_dir, exist_ok=True)

        self.logger(self.service_name, "INIT", "N/A",
                    f"Initialisation du générateur de rapports. Intervalle: {self.generation_interval}s, Période: {REPORT_PERIOD_HOURS}h.")

    def _get_level_value(self, level_name):
        levels = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40, "CRITICAL": 50}
        return levels.get(level_name.upper(), 20)

    def _parse_log_line(self, line):
        try:
            match = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d{3} - IDS_[\w]+ - (\w+) - EVENT_TYPE=(.*?); PATH=(.*?); DESCRIPTION='(.*?)'", line)
            if match:
                timestamp_str, level, event_type, path, description = match.groups()
                timestamp = datetime.strptime(timestamp_str.split(',')[0], "%Y-%m-%d %H:%M:%S")
                return {
                    "timestamp": timestamp,
                    "level": level.upper(),
                    "level_value": self._get_level_value(level),
                    "event_type": event_type,
                    "path": path,
                    "description": description
                }
        except Exception as e:
            self.logger(self.service_name, "LOG_PARSE_ERROR", "N/A", f"Erreur parsing ligne de log : {line.strip()} - {e}", level="ERROR")
        return None

    def generate_report(self):
        self.logger(self.service_name, "REPORT_GEN_START", "N/A", "Début génération du rapport.")
        print("[*] Génération du rapport IDS en cours...")

        end_time = datetime.now()
        start_time = end_time - self.report_period

        relevant_events = []
        seen_events = set()
        event_counts = defaultdict(int)
        severity_counts = defaultdict(int)

        try:
            with open(self.log_file_path, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    event = self._parse_log_line(line)
                    if event and event['timestamp'] >= start_time:
                        if event['level_value'] >= self.min_report_level:
                            key = (event['event_type'], event['path'], event['level'])
                            if key not in seen_events:
                                relevant_events.append(event)
                                seen_events.add(key)

                            event_counts[event['event_type']] += 1
                            severity_counts[event['level']] += 1
        except FileNotFoundError:
            self.logger(self.service_name, "FILE_NOT_FOUND", self.log_file_path, "Fichier log non trouvé.", level="ERROR")
            return
        except Exception as e:
            self.logger(self.service_name, "FILE_READ_ERROR", self.log_file_path, f"Erreur lecture log : {e}", level="CRITICAL")
            return

        # Génération du contenu du rapport
        relevant_events.sort(key=lambda x: x['timestamp'])
        report_content = [
            "--- Rapport IDS Résumé ---",
            f"Généré le: {end_time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Période couverte: Du {start_time.strftime('%Y-%m-%d %H:%M:%S')} au {end_time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Niveau de gravité minimum inclus: {MIN_REPORT_LEVEL}\n",
            "--- Résumé des événements par type ---"
        ]

        if not event_counts:
            report_content.append("Aucun événement pertinent trouvé pour cette période.")
        else:
            for event_type, count in sorted(event_counts.items()):
                report_content.append(f"- {event_type}: {count} occurrence(s)")
            report_content.append("\n--- Résumé des événements par gravité ---")
            for level, count in sorted(severity_counts.items(), key=lambda item: self._get_level_value(item[0]), reverse=True):
                report_content.append(f"- {level}: {count} occurrence(s)")

        report_content.append("\n--- Détails des événements pertinents ---")
        if not relevant_events:
            report_content.append("Aucun événement détaillé à afficher.")
        else:
            for event in relevant_events:
                report_content.append(
                    f"[{event['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}] "
                    f"{event['level']} - Type: {event['event_type']}, "
                    f"Chemin: {event['path']}, Description: {event['description']}"
                )

        report_content.append("\n--- Fin du Rapport ---")

        # Sauvegarde du rapport
        report_filename = end_time.strftime("ids_report_%Y%m%d_%H%M%S.txt")
        report_filepath = os.path.join(self.reports_dir, report_filename)

        try:
            with open(report_filepath, 'w', encoding='utf-8') as f:
                f.write("\n".join(report_content))

            self.logger(self.service_name, "REPORT_GEN_SUCCESS", report_filepath, f"Rapport généré avec succès: {report_filepath}")
            print(f"[+] Rapport généré : {report_filepath}")

            # 🔔 Envoi si événements CRITIQUES
            critical_events_payload = [
                {
                    "timestamp": e['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                    "severity": e['level'],
                    "type": e['event_type'],
                    "path": e['path'],
                    "description": e['description']
                }
                for e in relevant_events if e['level'] == "CRITICAL"
            ]

            if critical_events_payload:
                self.send_alert_to_server(
                    end_time,
                    start_time,
                    end_time,
                    dict(severity_counts),
                    dict(event_counts),
                    critical_events_payload
                )

        except Exception as e:
            self.logger(self.service_name, "REPORT_WRITE_ERROR", report_filepath, f"Erreur écriture rapport : {e}", level="CRITICAL")
            self.alerter(self.service_name, "REPORT_GEN_FAILURE", report_filepath, f"Échec de génération du rapport : {e}", severity="CRITICAL")

    def send_alert_to_server(self, generated_at, start_time, end_time, severity_counts, event_counts, critical_events):
        url = "http://localhost:8000/ids/alert"
        payload = {
            "generatedAt": generated_at.strftime('%Y-%m-%d %H:%M:%S'),
            "periodStart": start_time.strftime('%Y-%m-%d %H:%M:%S'),
            "periodEnd": end_time.strftime('%Y-%m-%d %H:%M:%S'),
            "severitySummary": severity_counts,
            "typeSummary": event_counts,
            "criticalEvents": critical_events
        }

        try:
            response = requests.post(url, json=payload)
            response.raise_for_status()
            print("[+] Alerte critique envoyée au serveur avec succès.")
        except requests.RequestException as e:
            print(f"[!] Échec envoi alerte serveur : {e}")

    def start(self):
        self.running = True
        self.logger(self.service_name, "STARTUP", "N/A", "Démarrage du générateur de rapports.")
        print("[*] Générateur de rapports lancé.")
        try:
            while self.running:
                self.generate_report()
                self.logger(self.service_name, "IDLE", "N/A", f"Attente de {self.generation_interval} secondes avant le prochain rapport.")
                time.sleep(self.generation_interval)
        except KeyboardInterrupt:
            self.stop()
        except Exception as e:
            self.logger(self.service_name, "CRASH", "N/A", f"Erreur critique dans le générateur de rapports : {e}", level="CRITICAL")
            self.alerter(self.service_name, "SERVICE_CRASH", "N/A", f"Le générateur de rapports a planté : {e}", severity="CRITICAL")
            self.stop()

    def stop(self):
        self.running = False
        self.logger(self.service_name, "SHUTDOWN", "N/A", "Générateur de rapports arrêté.")
        print("[*] Générateur de rapports arrêté.")

