import logging
from collections import deque
import joblib
import os
from datetime import datetime

# Configure logger
log_dir = "logs"
os.makedirs(log_dir, exist_ok=True)  # Ensure the log directory exists
log_filename = f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
log_path = os.path.join(log_dir, log_filename)

logging.basicConfig(filename=log_path, level=logging.INFO)

# Load your model and vectorizer
model = joblib.load("models/random_forest_ids.pkl")
vectorizer = joblib.load("models/tfidf_vectorizer.pkl")

# Set up a threshold for consecutive malicious syscalls
MALICIOUS_THRESHOLD = 1  # Threshold set to 1 for immediate alerts
syscall_history = deque(maxlen=10)

# Define a function to log alerts
def log_alert(message):
    logging.info(message)
    print(message)  # Optionally print to console

# Function to process syscalls and make predictions
def monitor_syscalls():
    consecutive_malicious = 0  # Counter for consecutive malicious predictions
    first_run = True

    # Ensure an initial log entry to indicate the system is running
    if first_run:
        logging.info("[INFO] Model loaded. Starting batch-based IDS...")
        first_run = False

    while True:
        syscall = get_syscall()  # Implement syscall extraction (e.g., using Tracee)
        if syscall:
            # Add the syscall to history
            syscall_history.append(str(syscall))
            print(f"[DEBUG] Extracted syscall: {syscall}")

            # Make prediction
            prediction = model.predict([syscall_history])
            print(f"[DEBUG] Model Prediction: {prediction[0]} (1: Malicious, 0: Normal)")

            # If malicious, increase counter
            if prediction[0] == 1:
                consecutive_malicious += 1
            else:
                consecutive_malicious = 0  # Reset counter if normal

            # If the consecutive malicious count exceeds threshold, generate an alert
            if consecutive_malicious >= MALICIOUS_THRESHOLD:
                alert_message = f"ALERT! Detected {consecutive_malicious} consecutive malicious syscalls: {syscall_history}"
                log_alert(alert_message)
                consecutive_malicious = 0  # Reset after alerting

            # Log normal activity (optional)
            else:
                print(f"✅ Normal syscall activity: {' '.join(syscall_history)}")

# Helper function to simulate syscall extraction (replace with actual method)
def get_syscall():
    # This function should return a syscall ID (e.g., based on Tracee or similar)
    # Here we'll simulate with a random syscall ID for demonstration purposes
    import random
    return random.choice([41, 56, 257, 59])  # Example syscall IDs

# Run the syscall monitoring function
monitor_syscalls()
s
