# Custom logging utilities
import logging
from config.logging_config import setup_logging
import os

# Initialiser le logging au démarrage du module pour s'assurer qu'il est configuré
setup_logging()

def get_ids_logger(name):
    """
    Retourne un logger configuré pour l'IDS.
    Le nom du logger peut être utilisé pour identifier le service (ex: 'FILE_MONITOR').
    """
    # Utilisation d'un nom de logger unique pour chaque service pour faciliter le filtrage
    return logging.getLogger(f"IDS_{name}")

def log_event(service_name, event_type, path, description, level="INFO"):
    """
    Enregistre un événement de sécurité de manière standardisée.

    Args:
        service_name (str): Nom du service qui a détecté l'événement (ex: 'FILE_MONITOR').
        event_type (str): Type d'événement (ex: 'MODIFICATION', 'ACCESS', 'DELETION').
        path (str): Chemin du fichier ou dossier concerné.
        description (str): Description détaillée de l'événement.
        level (str): Niveau de log ('INFO', 'WARNING', 'ERROR', 'CRITICAL').
    """
    logger = get_ids_logger(service_name)
    message = f"EVENT_TYPE={event_type}; PATH={path}; DESCRIPTION='{description}'"

    # Convertir le niveau de chaîne en niveau de log Python
    log_level = getattr(logging, level.upper(), logging.INFO) # Défaut à INFO si niveau inconnu
    logger.log(log_level, message)