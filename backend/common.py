# common.py
import json
import os
from loguru import logger

class AlertManager:
    """
    Base AlertManager class to handle basic alert processing, like logging to a file.
    This class is extended by FastAPIAlertManager in main.py.
    """
    def __init__(self, log_file="alerts.log"):
        self.log_file = log_file

    def send_alert(self, alert_data: dict):
        """Logs the alert data to a specified log file."""
        try:
            # Ensure the directory exists for the log file
            log_dir = os.path.dirname(self.log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(alert_data) + "\n")
            # Corrected logging to use 'severity' and 'details.process_name'
            logger.info(f"Alert logged to {self.log_file}: {alert_data.get('severity', 'UNKNOWN')} - {alert_data.get('details', {}).get('process_name', 'unknown')}")
        except Exception as e:
            logger.error(f"Error writing alert to log file {self.log_file}: {e}")

