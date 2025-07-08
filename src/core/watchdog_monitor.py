# watchdog_monitor.py
import time
import os
import stat
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from config.settings import CRITICAL_FILE_PATHS
from src.utils.logger import log_event
from src.utils.alerter import generate_alert

class IDSFileSystemEventHandler(FileSystemEventHandler):
    """
    Gestionnaire d'événements pour la surveillance des fichiers sensibles.
    Détecte création, suppression, modification, déplacement.
    """

    def __init__(self, sensitive_paths):
        super().__init__()
        self.logger = log_event
        self.alerter = generate_alert
        self.service_name = "FILE_MONITOR"
        # Normalisation et stockage des chemins sensibles en absolu
        self.sensitive_paths = set(os.path.abspath(p) for p in sensitive_paths)

    def is_sensitive(self, path):
        """
        Vérifie si `path` est un chemin sensible ou dans un dossier sensible.
        Utilise startswith pour détecter la hiérarchie.
        """
        normalized_path = os.path.abspath(path)
        for base_path in self.sensitive_paths:
            if normalized_path.startswith(base_path):
                # S'assurer que la correspondance est exacte (évite /etc/passwd vs /etc/passwd_backup)
                if len(normalized_path) == len(base_path) or normalized_path[len(base_path)] == os.sep:
                    return True
        return False

    def on_created(self, event):
        if self.is_sensitive(event.src_path):
            self.logger(self.service_name, "CREATED", event.src_path, "Création détectée.", level="INFO")
            self.alerter(self.service_name, "FILE_CREATED", event.src_path, "Création dans chemin sensible.", severity="LOW")

    def on_deleted(self, event):
        if self.is_sensitive(event.src_path):
            self.logger(self.service_name, "DELETED", event.src_path, "Suppression détectée.", level="ERROR")
            self.alerter(self.service_name, "FILE_DELETED", event.src_path, "Suppression fichier sensible.", severity="HIGH")

    def on_modified(self, event):
        if not event.is_directory and self.is_sensitive(event.src_path):
            self.logger(self.service_name, "MODIFIED", event.src_path, "Modification détectée.", level="WARNING")
            self.alerter(self.service_name, "FILE_MODIFIED", event.src_path, "Modification fichier sensible.", severity="MEDIUM")

    def on_moved(self, event):
        # Déplacement/renommage - source ou destination sensible
        if self.is_sensitive(event.src_path) or self.is_sensitive(event.dest_path):
            self.logger(self.service_name, "MOVED", event.src_path, f"Déplacé vers {event.dest_path}", level="WARNING")
            self.alerter(self.service_name, "FILE_MOVED", event.src_path,
                         f"Fichier sensible déplacé de '{event.src_path}' vers '{event.dest_path}'.", severity="MEDIUM")

    def on_closed(self, event):
        # Optionnel : détection à la fermeture du fichier (utile si on veut moins d'alertes)
        if not event.is_directory and self.is_sensitive(event.src_path):
            self.logger(self.service_name, "CLOSED_FOR_WRITE", event.src_path, "Fichier fermé après écriture.", level="INFO")
            # Par défaut, ne pas générer d'alerte ici pour éviter doublons


class FileMonitor:
    """
    Classe pour gérer le monitoring via watchdog sur plusieurs chemins sensibles.
    """

    def __init__(self, paths_to_watch):
        self.paths_to_watch = paths_to_watch
        self.observer = Observer()
        self.event_handler = IDSFileSystemEventHandler(paths_to_watch)
        self.logger = log_event
        self.alerter = generate_alert
        self.service_name = "FILE_MONITOR"
        self.running = False

        self.logger(self.service_name, "INIT", "N/A", f"Initialisation avec chemins: {self.paths_to_watch}")

    def start(self):
        self.running = True
        monitored_paths = []

        # Vérifier l'existence des chemins avant de lancer la surveillance
        for path in self.paths_to_watch:
            if os.path.exists(path):
                self.observer.schedule(self.event_handler, path, recursive=True)
                monitored_paths.append(os.path.abspath(path))
                self.logger(self.service_name, "START", path, f"Surveillance démarrée sur: {path}", level="INFO")
                # Optionnel : vérifier les permissions au démarrage
                self.check_permissions_and_access(path)
            else:
                self.logger(self.service_name, "ERROR", path, "Chemin inexistant, non surveillé.", level="ERROR")
                self.alerter(self.service_name, "PATH_NOT_FOUND", path, f"Le chemin '{path}' n'existe pas.", severity="HIGH")

        if not monitored_paths:
            self.logger(self.service_name, "ERROR", "N/A", "Aucun chemin valide à surveiller. Arrêt.", level="CRITICAL")
            print("[!] Aucun chemin valide à surveiller. Fin du service.")
            self.running = False
            return

        self.observer.start()
        self.logger(self.service_name, "STATUS", "N/A", f"Monitoring actif sur: {monitored_paths}", level="INFO")
        print(f"[*] Monitoring fichiers actifs sur : {monitored_paths}")

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
        except Exception as e:
            self.logger(self.service_name, "CRASH", "N/A", f"Erreur critique: {e}", level="CRITICAL")
            self.alerter(self.service_name, "SERVICE_CRASH", "N/A", f"Crash du moniteur: {e}", severity="CRITICAL")
            self.stop()

    def stop(self):
        if self.running:
            self.running = False
            self.observer.stop()
            self.observer.join()
            self.logger(self.service_name, "SHUTDOWN", "N/A", "Arrêt du moniteur de fichiers.", level="INFO")
            print("[*] Moniteur de fichiers arrêté.")

    def check_permissions_and_access(self, path):
        """
        Vérifie les permissions POSIX d'un fichier/dossier critique.
        Génère un log et alerte si permissions trop larges détectées.
        """
        if not os.path.exists(path):
            self.logger(self.service_name, "PERMISSION_CHECK", path, "Chemin inexistant pour vérification.", level="WARNING")
            return

        try:
            mode = os.stat(path).st_mode
            permissions = stat.S_IMODE(mode)

            user_can_read = bool(permissions & stat.S_IRUSR)
            user_can_write = bool(permissions & stat.S_IWUSR)
            user_can_execute = bool(permissions & stat.S_IXUSR)

            group_can_read = bool(permissions & stat.S_IRGRP)
            group_can_write = bool(permissions & stat.S_IWGRP)
            group_can_execute = bool(permissions & stat.S_IXGRP)

            others_can_read = bool(permissions & stat.S_IROTH)
            others_can_write = bool(permissions & stat.S_IWOTH)
            others_can_execute = bool(permissions & stat.S_IXOTH)

            log_msg = (
                f"Permissions '{path}': Owner R={user_can_read} W={user_can_write} X={user_can_execute}, "
                f"Group R={group_can_read} W={group_can_write} X={group_can_execute}, "
                f"Others R={others_can_read} W={others_can_write} X={others_can_execute}, Octal={oct(permissions)}"
            )
            self.logger(self.service_name, "PERMISSION_CHECK", path, log_msg, level="INFO")

            # Exemple d'alerte si 'others' ont le droit d'écriture sur un fichier critique
            if others_can_write:
                self.alerter(self.service_name, "INSECURE_PERMISSIONS", path,
                             "Permissions dangereuses: autres utilisateurs peuvent écrire.", severity="CRITICAL")
        except Exception as e:
            self.logger(self.service_name, "PERMISSION_CHECK_ERROR", path, f"Erreur vérification permissions: {e}", level="ERROR")
