# my_project_ids.py
import os
import time
import re
import logging
import joblib
import json
import numpy as np
from datetime import datetime
from collections import deque, defaultdict
from threading import Thread, Lock
import subprocess

# Import AlertManager from common.py
from common import AlertManager

# Configuration - Updated for improved model
MODEL_DIR = os.path.join("models", "model_os")
MODEL_PATH = os.path.join(MODEL_DIR, "rf_ids_model.joblib")
VECTORIZER_PATH = os.path.join(MODEL_DIR, "tfidf_vectorizer.joblib")
BACKUP_MODEL_PATH = os.path.join(MODEL_DIR, "rf_ids_model_backup.joblib")

# Path to the audit log file - Adjust if your Kali setup uses a different path
AUDIT_LOG_PATH = "/var/log/audit/audit.log" 

DEBUG_MODE = True
BATCH_SIZE = 50
SEQUENCE_LENGTH = 5

# Enhanced thresholds optimized for balanced model (can be updated via API)
ALERT_THRESHOLD = 0.5    # Adjusted for balanced model
PROB_ALERT_THRESHOLD = 0.45    # More sensitive for balanced model
ALERT_COOLDOWN = 30    # Seconds between alerts for same process/syscall combo
MAX_ALERTS_PER_PROCESS = 8    # Increased for better detection

# Confidence thresholds for severity levels
HIGH_CONFIDENCE_THRESHOLD = 0.85
MEDIUM_CONFIDENCE_THRESHOLD = 0.65

# System process whitelist - known legitimate processes
SYSTEM_PROCESS_WHITELIST = {
    'Xorg', 'systemd', 'kthreadd', 'ksoftirqd', 'migration', 'rcu_', 'watchdog',
    'sshd', 'dbus', 'NetworkManager', 'systemd-', 'kernel', 'init', 'gdm',
    'gnome-', 'pulseaudio', 'avahi-daemon', 'cups', 'chronyd', 'rsyslog',
    'bluetoothd', 'wpa_supplicant', 'dhclient', 'cron', 'atd'
}

# High-risk syscalls that warrant immediate attention
HIGH_RISK_SYSCALLS = {
    59,     # execve - process execution
    322,    # execveat - execute program
    265,    # clock_adjtime - system time manipulation
    168,    # poll - I/O multiplexing (suspicious patterns)
    240,    # futex - synchronization primitive
    91,     # fchmod - file permission changes
    197,    # fchown - file ownership changes
    45,     # recvfrom - network data reception
    13,     # rt_sigaction - signal handling
}

# Legitimate syscalls that rarely indicate malicious activity
BENIGN_SYSCALLS = {
    1,      # write
    2,      # open
    3,      # close
    4,      # stat
    5,      # fstat
    6,      # lstat
    8,      # lseek
    9,      # mmap
    10,     # mprotect
    11,     # munmap
    12,     # brk
    21,     # access
    43,     # accept (network connections - normal for servers)
    78,     # gettimeofday
    89,     # readdir
    102,    # getuid
    104,    # getgid
    158,    # arch_prctl
    217,    # getdents64
    231,    # exit_group
}

SYSCALL_ID_REGEX = re.compile(r"syscall=(\d+)")
PID_REGEX = re.compile(r"pid=(\d+)")
PPID_REGEX = re.compile(r"ppid=(\d+)")
UID_REGEX = re.compile(r"uid=(\d+)")
COMM_REGEX = re.compile(r"comm=\"([^\"]+)\"")
TIMESTAMP_REGEX = re.compile(r"audit\((\d+\.\d+):")

# Global state for my_project_ids module (accessed by RealtimeIDS instance methods)
# These are the actual counters/states that the monitoring thread updates
# and that main.py reads.
alert_buffer = [] 
buffer_lock = Lock()
process_sequences = defaultdict(lambda: deque(maxlen=SEQUENCE_LENGTH))
process_stats = defaultdict(lambda: {"count": 0, "malicious_count": 0, "last_seen": time.time(), "risk_score": 0.0})

# Alert rate limiting
alert_cooldowns = defaultdict(lambda: defaultdict(float))    # process_id -> syscall_id -> last_alert_time
process_alert_counts = defaultdict(lambda: defaultdict(int))    # process_id -> hour -> alert_count

# Model performance tracking
model_stats = {
    "model_version": "balanced",
    "load_time": None,
    "predictions_confidence": [],
    "avg_prediction_time": 0.0,
    "model_accuracy_estimate": 0.75    # Based on your test results
}

# Debug and overall processing statistics
debug_stats = {
    "lines_processed": 0,
    "syscalls_parsed": 0,
    "batches_processed": 0,
    "predictions_made": 0,
    "malicious_detected": 0,
    "alerts_suppressed": 0,
    "whitelisted_filtered": 0,
    "high_risk_syscalls": 0,
    "feature_samples": []
}

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [%(levelname)s] %(message)s')

class EnhancedSyscallInfo:
    def __init__(self, syscall_id, pid, ppid=None, uid=None, comm=None, timestamp=None):
        self.syscall_id = syscall_id
        self.pid = pid
        self.ppid = ppid
        self.uid = uid
        self.comm = comm
        self.timestamp = timestamp
        self.sequence_context = []
        self.risk_indicators = self._calculate_risk_indicators()
    
    def _calculate_risk_indicators(self):
        """Calculate risk indicators for this syscall"""
        indicators = []
        
        # High-risk syscall
        if self.syscall_id in HIGH_RISK_SYSCALLS:
            indicators.append("high_risk_syscall")
        
        # Suspicious UID (very high or unusual)
        if self.uid is not None and (self.uid > 65000 or self.uid == 0):
            indicators.append("suspicious_uid")
        
        # Uncommon process name patterns
        if self.comm and any(pattern in self.comm.lower() for pattern in ['tmp', 'dev', 'var', 'proc']):
            indicators.append("suspicious_process_name")
        
        return indicators

def _load_model_and_vectorizer():
    """Load the improved balanced model with fallback"""
    start_time = time.time()
    
    # Ensure model directory exists
    if not os.path.exists(MODEL_DIR):
        logging.warning(f"⚠️ Model directory not found: {MODEL_DIR}. Cannot load model.")
        return None, None

    model, vectorizer = None, None
    try:
        # Try to load the main model
        model = joblib.load(MODEL_PATH)
        vectorizer = joblib.load(VECTORIZER_PATH)
        model_stats["model_version"] = "balanced_improved"
        logging.info("✅ Improved balanced model loaded successfully")
    except Exception as e:
        logging.warning(f"⚠️  Failed to load main model: {e}")
        try:
            # Fallback to backup model
            model = joblib.load(BACKUP_MODEL_PATH)
            vectorizer = joblib.load(VECTORIZER_PATH)
            model_stats["model_version"] = "backup"
            logging.info("✅ Backup model loaded successfully")
        except Exception as e2:
            logging.error(f"❌ Failed to load any model: {e2}")
            # Do not re-raise, allow IDS to run without ML features if no model
            model, vectorizer = None, None # Ensure they are None if loading failed
    
    model_stats["load_time"] = time.time() - start_time
    logging.info(f"📊 Model loaded in {model_stats['load_time']:.3f}s")
    return model, vectorizer

def is_whitelisted_process(comm):
    """Check if process is in the system whitelist"""
    if not comm:
        return False
    return any(whitelist_name in comm for whitelist_name in SYSTEM_PROCESS_WHITELIST)

def is_benign_syscall(syscall_id):
    """Check if syscall is generally benign"""
    return syscall_id in BENIGN_SYSCALLS

def is_high_risk_syscall(syscall_id):
    """Check if syscall is high-risk"""
    return syscall_id in HIGH_RISK_SYSCALLS

def calculate_process_risk_score(pid):
    """Calculate dynamic risk score for a process"""
    stats = process_stats[pid]
    
    # Base risk from malicious ratio
    malicious_ratio = stats["malicious_count"] / max(1, stats["count"])
    base_risk = malicious_ratio * 0.7
    
    # Frequency risk (too many syscalls too quickly)
    frequency_risk = min(0.3, stats["count"] / 1000)
    
    # Recency risk (recently active processes are more suspicious)
    time_since_last = time.time() - stats["last_seen"]
    recency_risk = max(0, 0.2 - (time_since_last / 3600))
    
    total_risk = base_risk + frequency_risk + recency_risk
    stats["risk_score"] = min(1.0, total_risk)
    
    return stats["risk_score"]

def should_suppress_alert(syscall_info, triggered_by, confidence):
    """Enhanced alert suppression logic"""
    current_time = time.time()
    current_hour = int(current_time // 3600)
    
    # Check if process is whitelisted
    if is_whitelisted_process(syscall_info.comm):
        debug_stats["whitelisted_filtered"] += 1
        return True, "whitelisted_process"
    
    # Don't suppress high-confidence alerts for high-risk syscalls
    if is_high_risk_syscall(syscall_info.syscall_id) and confidence > HIGH_CONFIDENCE_THRESHOLD:
        debug_stats["high_risk_syscalls"] += 1
        return False, None
    
    # Check if syscall is benign and confidence is low
    if is_benign_syscall(syscall_info.syscall_id) and confidence < MEDIUM_CONFIDENCE_THRESHOLD:
        return True, "benign_syscall_low_confidence"
    
    # Check cooldown period for same process/syscall combination
    last_alert_time = alert_cooldowns[syscall_info.pid][syscall_info.syscall_id]
    if current_time - last_alert_time < ALERT_COOLDOWN:
        # Allow high-confidence alerts to bypass cooldown
        if confidence < HIGH_CONFIDENCE_THRESHOLD: # Only suppress if confidence is not high
            debug_stats["alerts_suppressed"] += 1
            return True, "cooldown_active"
    
    # Check if process has exceeded alert limit for this hour
    if process_alert_counts[syscall_info.pid][current_hour] >= MAX_ALERTS_PER_PROCESS:
        # Allow critical alerts to bypass rate limiting
        if confidence < HIGH_CONFIDENCE_THRESHOLD: # Only suppress if confidence is not high
            debug_stats["alerts_suppressed"] += 1
            return True, "rate_limited"
    
    return False, None

def parse_enhanced_syscall_info(line):
    syscall_match = SYSCALL_ID_REGEX.search(line)
    pid_match = PID_REGEX.search(line)
    ppid_match = PPID_REGEX.search(line)
    uid_match = UID_REGEX.search(line)
    comm_match = COMM_REGEX.search(line)
    timestamp_match = TIMESTAMP_REGEX.search(line)

    if not syscall_match or not pid_match:
        return None

    debug_stats["syscalls_parsed"] += 1

    return EnhancedSyscallInfo(
        syscall_id=int(syscall_match.group(1)),
        pid=int(pid_match.group(1)),
        ppid=int(ppid_match.group(1)) if ppid_match else None,
        uid=int(uid_match.group(1)) if uid_match else None,
        comm=comm_match.group(1) if comm_match else None,
        timestamp=float(timestamp_match.group(1)) if timestamp_match else time.time()
    )

def create_features_for_batch(syscall_batch):
    """
    Transforms a batch of EnhancedSyscallInfo objects into a list of strings
    suitable for TF-IDF vectorization, where each string represents a single syscall ID.
    """
    return [str(info.syscall_id) for info in syscall_batch]

def update_process_sequences(syscall_info):
    process_sequences[syscall_info.pid].append(syscall_info.syscall_id)
    syscall_info.sequence_context = list(process_sequences[syscall_info.pid])
    process_stats[syscall_info.pid]["count"] += 1
    process_stats[syscall_info.pid]["last_seen"] = time.time()
    
    # Update process risk score
    calculate_process_risk_score(syscall_info.pid)

def predict_batch_debug(model, vectorizer, syscall_batch):
    start_time = time.time()
    
    # Ensure model and vectorizer are available before predicting
    if model is None or vectorizer is None:
        logging.warning("Skipping prediction: Model or vectorizer not loaded.")
        # Return dummy predictions/probabilities if model is not loaded
        # Assuming 2 classes (benign, malicious), so 0 for prediction (benign) and 0.5 for each probability.
        return np.zeros(len(syscall_batch), dtype=int), np.ones((len(syscall_batch), 2)) * 0.5

    # Prepare features for prediction
    input_texts = create_features_for_batch(syscall_batch)
    features = vectorizer.transform(input_texts)
    
    predictions = model.predict(features)
    probabilities = model.predict_proba(features)

    prediction_time = time.time() - start_time
    model_stats["avg_prediction_time"] = (model_stats["avg_prediction_time"] + prediction_time) / 2
    
    # Track confidence distribution
    confidences = [max(prob) for prob in probabilities]
    model_stats["predictions_confidence"].extend(confidences)
    
    # Keep only recent confidence values
    if len(model_stats["predictions_confidence"]) > 1000:
        model_stats["predictions_confidence"] = model_stats["predictions_confidence"][-1000:]

    malicious_count = np.sum(predictions)
    debug_stats["predictions_made"] += len(predictions)
    debug_stats["malicious_detected"] += malicious_count
    debug_stats["batches_processed"] += 1
    
    return predictions, probabilities

def determine_severity(confidence, syscall_info):
    """Enhanced severity determination"""
    # Base severity from confidence
    if confidence > HIGH_CONFIDENCE_THRESHOLD:
        base_severity = "HIGH"
    elif confidence > MEDIUM_CONFIDENCE_THRESHOLD:
        base_severity = "MEDIUM"
    else:
        base_severity = "LOW"
    
    # Upgrade severity for high-risk syscalls
    if is_high_risk_syscall(syscall_info.syscall_id):
        if base_severity == "LOW":
            base_severity = "MEDIUM"
        elif base_severity == "MEDIUM":
            base_severity = "HIGH"
    
    # Consider process risk score
    process_risk = process_stats[syscall_info.pid]["risk_score"]
    if process_risk > 0.7 and base_severity == "LOW":
        base_severity = "MEDIUM"
    
    return base_severity

def create_detailed_alert(syscall_info, prediction, probability, alert_id):
    confidence = max(probability) if len(probability) > 1 else probability[0]
    severity = determine_severity(confidence, syscall_info)
    
    return {
        "id": alert_id,
        "timestamp": datetime.fromtimestamp(syscall_info.timestamp).isoformat(),
        "severity": severity,
        "prediction": "Malicious" if prediction == 1 else "Suspicious", # Assuming 1 is malicious class
        "confidence": round(confidence, 3),
        "model_info": {
            "version": model_stats["model_version"],
            "accuracy_estimate": model_stats["model_accuracy_estimate"]
        },
        "details": {
            "syscall_id": syscall_info.syscall_id,
            "pid": syscall_info.pid,
            "ppid": syscall_info.ppid,
            "uid": syscall_info.uid,
            "process_name": syscall_info.comm,
            "sequence_context": list(syscall_info.sequence_context), # Ensure it's a list for JSON serialization
            "process_syscall_count": process_stats[syscall_info.pid]["count"],
            "process_malicious_ratio": process_stats[syscall_info.pid]["malicious_count"] / max(1, process_stats[syscall_info.pid]["count"]),
            "process_risk_score": round(process_stats[syscall_info.pid]["risk_score"], 3),
            "risk_indicators": syscall_info.risk_indicators,
            "is_high_risk_syscall": is_high_risk_syscall(syscall_info.syscall_id)
        }
    }

def print_debug_stats():
    stats = debug_stats.copy()
    
    # Avoid division by zero if no predictions have been made yet
    detection_rate = (stats["malicious_detected"] / stats["predictions_made"]) * 100 if stats["predictions_made"] > 0 else 0.0
    suppression_rate = (stats["alerts_suppressed"] / stats["predictions_made"]) * 100 if stats["predictions_made"] > 0 else 0.0
    whitelist_rate = (stats["whitelisted_filtered"] / stats["predictions_made"]) * 100 if stats["predictions_made"] > 0 else 0.0
    
    # Model performance stats
    avg_confidence = np.mean(model_stats["predictions_confidence"]) if model_stats["predictions_confidence"] else 0
    
    logging.info("=" * 80)
    logging.info("🔍 ENHANCED IDS STATISTICS")
    logging.info("=" * 80)
    logging.info(f"📊 PROCESSING STATS:")
    logging.info(f"   Lines processed: {stats['lines_processed']}")
    logging.info(f"   Syscalls parsed: {stats['syscalls_parsed']}")
    logging.info(f"   Batches processed: {stats['batches_processed']}")
    logging.info(f"   Predictions made: {stats['predictions_made']}")
    logging.info(f"🎯 DETECTION STATS:")
    logging.info(f"   Malicious detected: {stats['malicious_detected']}")
    logging.info(f"   Detection rate: {detection_rate:.2f}%")
    logging.info(f"   High-risk syscalls: {stats['high_risk_syscalls']}")
    logging.info(f"🛡️  FILTERING STATS:")
    logging.info(f"   Alerts suppressed: {stats['alerts_suppressed']} ({suppression_rate:.2f}%)")
    logging.info(f"   Whitelisted filtered: {stats['whitelisted_filtered']} ({whitelist_rate:.2f}%)")
    logging.info(f"🤖 MODEL PERFORMANCE:")
    logging.info(f"   Model version: {model_stats['model_version']}")
    logging.info(f"   Avg confidence: {avg_confidence:.3f}")
    logging.info(f"   Avg prediction time: {model_stats['avg_prediction_time']:.4f}s")
    logging.info(f"   Estimated accuracy: {model_stats['model_accuracy_estimate']*100:.1f}%")
    logging.info(f"🔄 SYSTEM STATS:")
    logging.info(f"   Active processes: {len(process_stats)}")
    logging.info(f"   High-risk processes: {sum(1 for p in process_stats.values() if p['risk_score'] > 0.5)}")
    logging.info("=" * 80)

def cleanup_old_data():
    """Clean up old tracking data to prevent memory leaks"""
    current_time = time.time()
    current_hour = int(current_time // 3600)
    
    # Clean up old process stats (older than 2 hours)
    old_processes = [pid for pid, stats in process_stats.items() 
                     if current_time - stats["last_seen"] > 7200]
    for pid in old_processes:
        del process_stats[pid]
        if pid in process_sequences:
            del process_sequences[pid]
        if pid in alert_cooldowns:
            del alert_cooldowns[pid]
    
    # Clean up old hourly alert counts (older than 48 hours)
    for pid in list(process_alert_counts.keys()):
        old_hours = [hour for hour in process_alert_counts[pid] 
                     if current_hour - hour > 48]
        for hour in old_hours:
            del process_alert_counts[pid][hour]
        if not process_alert_counts[pid]:
            del process_alert_counts[pid]

# Helper function to get a snapshot of current debug stats
def _get_current_debug_stats():
    """Returns a copy of the current debug_stats and calculates relevant rates."""
    current_stats = debug_stats.copy()
    
    # Ensure detection rate is accurately calculated based on current data
    detection_rate = (current_stats["malicious_detected"] / 
                      max(1, current_stats["predictions_made"]))
    current_stats["detection_rate"] = detection_rate
    
    return current_stats

class RealtimeIDS:
    def __init__(self, alert_manager: AlertManager):
        self.alert_manager = alert_manager
        self._monitoring_active = False
        self.model, self.vectorizer = _load_model_and_vectorizer()
        self.thread = None
        self.alert_counter = 0
        self.syscall_history = deque(maxlen=10)
        self.consecutive_malicious = 0
        logging.info("RealtimeIDS instance initialized.")

    @property
    def monitoring_active(self):
        return self._monitoring_active

    def start_monitoring(self):
        if not self._monitoring_active:
            self._monitoring_active = True
            self.thread = Thread(target=self._stream_live_syscalls, daemon=True)
            self.thread.start()
            logging.info("✅ RealtimeIDS monitoring started in background thread.")
        else:
            logging.info("RealtimeIDS is already running.")

    def stop_monitoring(self):
        if self._monitoring_active:
            self._monitoring_active = False
            logging.info("🛑 RealtimeIDS monitoring stopped.")

    def get_stats(self):
        current_stats = _get_current_debug_stats()
        return {
            "syscalls_parsed": current_stats["syscalls_parsed"],
            "alerts_generated": current_stats["malicious_detected"],
            "detection_rate": current_stats["detection_rate"],
            "lines_processed": current_stats["lines_processed"],
            "suppressed_alerts": current_stats["alerts_suppressed"],
            "model_version": "realtime_gui_mode",
            "model_accuracy_estimate": 75.0,
            "is_running": self._monitoring_active
        }

    def _stream_live_syscalls(self):
        logging.info(f"🚀 Starting real-time syscall stream via tail -F {AUDIT_LOG_PATH}")
        process = None
        try:
            cmd = ["tail", "-F", AUDIT_LOG_PATH]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)

            for line in process.stdout:
                if not self._monitoring_active:
                    logging.info("RealtimeIDS monitoring thread exiting gracefully.")
                    break

                debug_stats["lines_processed"] += 1
                if "type=SYSCALL" not in line:
                    continue

                syscall_info = parse_enhanced_syscall_info(line)
                if not syscall_info:
                    if DEBUG_MODE:
                        logging.debug(f"Could not parse syscall info from line: {line.strip()}")
                    continue

                debug_stats["syscalls_parsed"] += 1

                # ======= TKINTER-LIKE LOGIC BELOW ========
                self.syscall_history.append(str(syscall_info.syscall_id))
                history_string = " ".join(self.syscall_history)
                vector = self.vectorizer.transform([history_string])
                prediction = self.model.predict(vector)
                probabilities = self.model.predict_proba(vector)
                confidence = max(probabilities[0])

                debug_stats["predictions_made"] += 1

                if prediction[0] == 1:
                    self.consecutive_malicious += 1
                    debug_stats["malicious_detected"] += 1

                    if self.consecutive_malicious >= ALERT_THRESHOLD:
                        alert_data = {
                            "id": self.alert_counter,
                            "timestamp": datetime.now().isoformat(),
                            "confidence": confidence,
                            "type": "alert",
                            "severity": "LOW",
                            "details": {
                                "syscall_id": syscall_info.syscall_id,
                                "process_name": syscall_info.comm,
                                "pid": syscall_info.pid,
                                "process_risk_score": 0.2 + confidence * 0.4
                            }
                        }
                        self.alert_manager.send_alert(alert_data)
                        self.alert_counter += 1
                        self.consecutive_malicious = 0

                        logging.warning(
                            f"⚠️  ALERT #{alert_data['id']} [LOW] triggered: "
                            f"Confidence={confidence:.2f}, PID={syscall_info.pid}, "
                            f"Syscall={syscall_info.syscall_id}, Proc={syscall_info.comm}"
                        )
                else:
                    self.consecutive_malicious = 0

        except FileNotFoundError:
            logging.error("tail or audit.log not found. Ensure auditd is running and log path is correct.")
        except Exception as e:
            logging.error(f"❌ Unexpected error in syscall stream: {e}")
        finally:
            if process and process.poll() is None:
                logging.info("Terminating tail subprocess.")
                process.terminate()
                process.wait()
            self._monitoring_active = False
            
            
# This module-level function can be called by FastAPI for overall system stats
# Note: Main.py now directly accesses my_project_ids.debug_stats and my_project_ids.model_stats
# for efficiency and direct truth. This function is kept for consistency if needed elsewhere.
def get_system_stats_module():
    """Get current system statistics from my_project_ids module globals."""
    return {
        "debug_stats": debug_stats.copy(),
        "model_stats": model_stats.copy(),
        "active_processes": len(process_stats),
        "high_risk_processes": sum(1 for p in process_stats.values() if p['risk_score'] > 0.5)
    }

# CLI entry (optional, for standalone testing of IDS logic)
if __name__ == "__main__":
    logging.info("Running RealtimeIDS in standalone CLI mode.")
    # In standalone mode, we use a basic AlertManager for console output/file logging
    basic_alert_manager = AlertManager()
    ids = RealtimeIDS(alert_manager=basic_alert_manager)
    ids.start_monitoring()
    try:
        while ids.monitoring_active: # Use the property
            time.sleep(60) # Wait a bit and print stats
            print_debug_stats()
    except KeyboardInterrupt:
        logging.info("🛑 IDS standalone mode stopped by user.")
        ids.stop_monitoring()
        print_debug_stats()

