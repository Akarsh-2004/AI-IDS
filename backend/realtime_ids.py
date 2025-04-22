import os
import time
import re
import logging
import joblib
from datetime import datetime
from main import get_connected_clients  # FastAPI websocket clients
from threading import Thread

alert_buffer =[]
# Paths
AUDIT_LOG_PATH = "/var/log/audit/audit.log"
MODEL_PATH = os.path.join("models", "random_forest_ids.pkl")
VECTORIZER_PATH = os.path.join("models", "tfidf_vectorizer.pkl")

SYSCALL_ID_REGEX = re.compile(r"syscall=(\d+)")
PID_REGEX = re.compile(r"pid=(\d+)")

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

def load_model():
    model = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)
    return model, vectorizer

def parse_syscall_info(line):
    syscall_match = SYSCALL_ID_REGEX.search(line)
    pid_match = PID_REGEX.search(line)
    return (
        int(syscall_match.group(1)) if syscall_match else None,
        int(pid_match.group(1)) if pid_match else None,
    )

def predict_batch(model, vectorizer, syscall_batch):
    input_texts = [f"{sid} {pid}" for sid, pid in syscall_batch]
    features = vectorizer.transform(input_texts)
    return model.predict(features)

def follow(file):
    file.seek(0, os.SEEK_END)
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line.strip()

async def push_to_clients(message):
    for client in get_connected_clients().copy():
        try:
            await client.send_text(message)
        except Exception as e:
            logging.warning(f"WebSocket send error: {e}")


def stream_audit_log():
    model, vectorizer = load_model()
    syscall_batch = []
    raw_lines_batch = []

    with open(AUDIT_LOG_PATH, "r") as f:
        for line in follow(f):
            if "type=SYSCALL" not in line:
                continue
            sid, pid = parse_syscall_info(line)
            if sid is None or pid is None:
                continue
            syscall_batch.append((sid, pid))
            raw_lines_batch.append(line)

            if len(syscall_batch) == 300:
                preds = predict_batch(model, vectorizer, syscall_batch)
                for i, pred in enumerate(preds):
                    label = "Malicious" if pred else "Normal"
                    alert = f"{label} - syscall={syscall_batch[i][0]}, pid={syscall_batch[i][1]}"
                    import asyncio
                    asyncio.run(push_to_clients(alert))

                syscall_batch.clear()
                raw_lines_batch.clear()

# Run as background thread
def start_ids():
    thread = Thread(target=stream_audit_log)
    thread.start()
