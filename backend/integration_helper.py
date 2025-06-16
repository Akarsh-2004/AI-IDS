# integration_helper.py - Helper to ensure compatibility between realtime_ids.py and FastAPI
import os
import sys
from loguru import logger

class IDSIntegration:
    """Helper class to integrate existing IDS with FastAPI"""
    
    @staticmethod
    def check_dependencies():
        """Check if all required files and dependencies exist"""
        required_files = [
            "realtime_ids.py",
            "syscall_parser.py", 
            "alert_manager.py",
            "ids_model.pkl"
        ]
        
        missing_files = []
        for file in required_files:
            if not os.path.exists(file):
                missing_files.append(file)
        
        if missing_files:
            logger.error(f"Missing required files: {missing_files}")
            return False, missing_files
        
        return True, []
    
    @staticmethod
    def create_dummy_modules():
        """Create dummy modules if the real ones don't exist (for testing)"""
        
        # Dummy realtime_ids.py
        if not os.path.exists("realtime_ids.py"):
            logger.info("Creating dummy realtime_ids.py for testing")
            with open("realtime_ids.py", "w") as f:
                f.write('''
import time
import threading
from loguru import logger
from datetime import datetime
import random

class RealtimeIDS:
    def __init__(self, alert_manager=None):
        self.alert_manager = alert_manager
        self.is_running = False
        self.stats = {
            "lines_processed": 0,
            "syscalls_parsed": 0,
            "detection_rate": 0.0,
            "suppressed_alerts": 0
        }
        self.model = "dummy_model"  # Simulate loaded model
        
    def start_monitoring(self):
        """Simulate IDS monitoring"""
        self.is_running = True
        logger.info("Starting dummy IDS monitoring...")
        
        while self.is_running:
            self.stats["lines_processed"] += 100
            self.stats["syscalls_parsed"] += 25
            
            if random.random() < 0.1:
                self.simulate_threat_detection()
            
            time.sleep(2)
    
    def simulate_threat_detection(self):
        threats = [
            {
                "process": "suspicious_proc",
                "syscalls": ["socket", "bind", "listen"],
                "risk_level": "HIGH",
                "confidence": 0.95
            },
            {
                "process": "malware.exe", 
                "syscalls": ["open", "/etc/passwd", "read"],
                "risk_level": "MEDIUM",
                "confidence": 0.78
            },
            {
                "process": "backdoor",
                "syscalls": ["connect", "send", "recv"],
                "risk_level": "HIGH", 
                "confidence": 0.89
            }
        ]
        
        threat = random.choice(threats)
        alert_data = {
            "timestamp": datetime.now().isoformat(),
            "process": threat["process"],
            "syscalls": threat["syscalls"],
            "risk_level": threat["risk_level"],
            "confidence": threat["confidence"],
            "details": {"type": "simulated", "description": "Dummy threat for testing"}
        }
        
        if self.alert_manager:
            self.alert_manager.send_alert(alert_data)
        
        logger.warning(f"Simulated threat detected: {threat['process']} - {threat['risk_level']}")
    
    def stop_monitoring(self):
        self.is_running = False
        logger.info("Stopping IDS monitoring...")
    
    def get_stats(self):
        if self.stats["lines_processed"] > 0:
            self.stats["detection_rate"] = self.stats["syscalls_parsed"] / self.stats["lines_processed"]
        return self.stats
        
    def update_config(self, config):
        logger.info(f"Configuration updated: {config}")
''')

        # Dummy syscall_parser.py
        if not os.path.exists("syscall_parser.py"):
            logger.info("Creating dummy syscall_parser.py")
            with open("syscall_parser.py", "w") as f:
                f.write('''
class SyscallParser:
    def __init__(self):
        pass
    
    def parse_line(self, line):
        # Dummy parsing
        return {"syscalls": ["open", "read"], "process": "dummy_process"}
''')

        # Dummy alert_manager.py  
        if not os.path.exists("alert_manager.py"):
            logger.info("Creating dummy alert_manager.py")
            with open("alert_manager.py", "w") as f:
                f.write('''
from loguru import logger

class AlertManager:
    def __init__(self):
        self.alerts = []

    def send_alert(self, alert_data):
        logger.warning(f"[DUMMY ALERT] {alert_data['process']} triggered {alert_data['risk_level']} threat")
        self.alerts.append(alert_data)

    def get_recent_alerts(self):
        return self.alerts[-10:]
''')

        # Dummy model file placeholder
        if not os.path.exists("ids_model.pkl"):
            logger.info("Creating dummy model file 'ids_model.pkl'")
            with open("ids_model.pkl", "wb") as f:
                f.write(b"DUMMY_MODEL_BYTES")

