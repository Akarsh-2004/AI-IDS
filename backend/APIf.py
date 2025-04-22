from fastapi import FastAPI
from fastapi.responses import JSONResponse
import threading
from realtime_ids import stream_audit_log, alert_buffer

app = FastAPI(title="Real-Time Intrusion Detection API")

@app.get("/")
def home():
    return {"message": "🚨 Real-Time IDS is Running!"}

@app.get("/alerts")
def get_alerts():
    return JSONResponse(content={"alerts": list(alert_buffer)})

# Start background thread when FastAPI starts
@app.on_event("startup")
def start_ids_monitor():
    thread = threading.Thread(target=stream_audit_log, daemon=True)
    thread.start()
