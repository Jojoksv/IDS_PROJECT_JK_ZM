# Alert generation and formatting
from src.utils.logger import log_event
import datetime
import json

def generate_alert(service_name, event_type, path, description, severity="MEDIUM", metadata=None):
    """
    Génère une alerte structurée en cas d'événement anormal.
    Cette fonction est le point d'entrée pour la centralisation des alertes
    et l'intégration future avec un service de notification externe.

    Args:
        service_name (str): Nom du service source de l'alerte (ex: 'FILE_MONITOR').
        event_type (str): Type d'événement déclencheur (ex: 'FILE_MODIFIED', 'UNAUTHORIZED_ACCESS').
        path (str): Chemin concerné par l'alerte.
        description (str): Description de l'alerte.
        severity (str): Gravité de l'alerte ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL').
        metadata (dict): Données supplémentaires pertinentes pour l'alerte (ex: utilisateur, pid).
    """
    alert_data = {
        "timestamp": datetime.datetime.now().isoformat(),
        "service": service_name,
        "eventType": event_type,
        "path": path,
        "description": description,
        "severity": severity,
        "metadata": metadata if metadata is not None else {}
    }

    # Pour l'instant, nous loguons l'alerte en tant que message CRITICAL, ERROR ou WARNING.
    # L'objet JSON de l'alerte est inclus dans la description pour une meilleure traçabilité.
    log_level = "CRITICAL" if severity == "CRITICAL" else ("ERROR" if severity == "HIGH" else "WARNING")
    log_event(
        service_name=service_name,
        event_type=f"ALERT_{event_type}", # Préfixe pour distinguer les alertes dans les logs
        path=path,
        description=json.dumps(alert_data), # Log l'objet JSON de l'alerte
        level=log_level
    )
    print(f"!!! ALERTE DÉTECTÉE ({severity}) !!! Service: {service_name}, Événement: {event_type}, Chemin: {path}, Description: {description}")
    # TODO: Intégrer l'appel à l'API du service de notification Node.js ici plus tard