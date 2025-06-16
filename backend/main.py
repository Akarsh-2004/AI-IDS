# main.py - FastAPI application integrated with my_project_ids.py
from fastapi import FastAPI, BackgroundTasks, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional
import asyncio
import json
import threading
import queue
from datetime import datetime
from loguru import logger
import uvicorn
import os
from fastapi import Request

import time # Added for time.sleep in run_ids_monitoring

# Import RealtimeIDS and its module-level stats (debug_stats, model_stats)
import my_project_ids 
from my_project_ids import RealtimeIDS # Only RealtimeIDS class needed directly

# Import AlertManager from the new common.py file
from common import AlertManager

# Pydantic models for API
class AlertModel(BaseModel):
    id: int # Alert ID is now mandatory from my_project_ids
    timestamp: str
    severity: str # Severity (HIGH, MEDIUM, LOW) - Corrected field name
    prediction: str # "Malicious" or "Suspicious"
    confidence: float
    model_info: Dict
    details: Dict
    triggered_by: str
    analysis_time: str # This field is now ISO-formatted string
    type: str # Explicitly added for WebSocket filtering

class SystemStats(BaseModel):
    total_syscalls: int
    alerts_generated: int
    detection_rate: float
    uptime: str
    last_alert: Optional[str]
    lines_processed: int
    suppressed_alerts: int

class IDSConfig(BaseModel):
    monitoring_enabled: Optional[bool] = None
    alert_threshold: Optional[float] = None
    prob_alert_threshold: Optional[float] = None # Added for more granular control
    alert_cooldown: Optional[int] = None        # Added for more granular control
    max_alerts_per_process: Optional[int] = None # Added for more granular control
    whitelist: Optional[List[str]] = None
    suppression_enabled: Optional[bool] = None
    model_path: Optional[str] = None # This will be read-only from config, not set

# FastAPI app initialization
app = FastAPI(
    title="Real-Time Intrusion Detection System",
    description="AI-powered IDS with real-time syscall monitoring",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global IDS instance and state
ids_instance: Optional[RealtimeIDS] = None
ids_thread: Optional[threading.Thread] = None
alert_queue = queue.Queue() # Queue to pass alerts from IDS thread to main async loop
ids_stats = { # This will be periodically updated from my_project_ids's internal stats
    "total_syscalls": 0,
    "alerts_generated": 0,
    "detection_rate": 0.0,
    "uptime": "00:00:00",
    "last_alert": None,
    "is_running": False,
    "lines_processed": 0,
    "suppressed_alerts": 0,
    "start_time": None # Stores datetime object, not directly JSON-serialized
}

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket client disconnected. Total: {len(self.active_connections)}")

    async def send_alert(self, alert: dict):
        if self.active_connections:
            # Ensure the alert is JSON serializable before sending
            try:
                message = json.dumps(alert)
                logger.debug(f"Attempting to send alert via WebSocket: {alert.get('severity')} - {alert.get('details', {}).get('process_name')}")
            except TypeError as e:
                logger.error(f"Failed to JSON serialize alert for WebSocket: {e} - Alert: {alert}")
                return # Do not send if not serializable

            disconnected = []
            for connection in self.active_connections:
                try:
                    await connection.send_text(message)
                except Exception as e:
                    logger.warning(f"Failed to send WebSocket message to client: {e}. Removing connection.")
                    disconnected.append(connection)
            
            # Remove disconnected clients
            for conn in disconnected:
                self.disconnect(conn)

    async def broadcast_stats(self, stats: dict):
        if self.active_connections:
            # Create a copy and ensure all datetime objects are converted to string
            serializable_stats = stats.copy()
            if isinstance(serializable_stats.get("start_time"), datetime):
                serializable_stats["start_time"] = serializable_stats["start_time"].isoformat()
            
            try:
                message = json.dumps({"type": "stats", "data": serializable_stats})
                logger.debug(f"Attempting to broadcast stats via WebSocket: {serializable_stats.get('lines_processed')}")
            except TypeError as e:
                logger.error(f"Failed to JSON serialize stats for WebSocket: {e} - Stats: {stats}")
                return # Do not send if not serializable

            disconnected = []
            for connection in self.active_connections:
                try:
                    await connection.send_text(message)
                except Exception as e:
                    logger.warning(f"Failed to send stats via WebSocket to client: {e}. Removing connection.")
                    disconnected.append(connection)
            
            for conn in disconnected:
                self.disconnect(conn)

manager = ConnectionManager()

# Custom Alert Manager that integrates with FastAPI's queue
class FastAPIAlertManager(AlertManager): # Inherit from the AlertManager in common.py
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.alert_queue = alert_queue

    def send_alert(self, alert_data: dict):
        # Send to parent class (file logging, etc.)
        super().send_alert(alert_data)
        
        # Add to queue for FastAPI processing in the main event loop
        try:
            self.alert_queue.put_nowait(alert_data)
            logger.info(f"Alert successfully queued for WebSocket: {alert_data.get('severity')} - {alert_data.get('details', {}).get('process_name')}")
        except queue.Full:
            logger.warning("Alert queue is full, dropping alert from IDS thread.")
        except Exception as e:
            logger.error(f"Error adding alert to queue: {e} - Alert: {alert_data}")


def run_ids_monitoring_thread_manager():
    """
    Manages the RealtimeIDS instance in a separate thread.
    Initializes RealtimeIDS and continuously updates global `ids_stats`
    from the IDS instance's internal statistics.
    """
    global ids_instance, ids_stats
    
    try:
        logger.info("Initializing Real-time IDS instance in background thread...")
        
        # Initialize IDS with custom alert manager (FastAPIAlertManager)
        alert_manager_instance = FastAPIAlertManager()
        ids_instance = RealtimeIDS(alert_manager=alert_manager_instance) # Pass the alert manager
        
        # Start the main IDS monitoring loop, which runs in its own daemon thread
        ids_instance.start_monitoring()
        
        # Continuously update main.py's global ids_stats from my_project_ids module's global debug_stats
        # The loop condition now primarily relies on the ids_instance's internal monitoring_active flag.
        while ids_instance.monitoring_active: 
            # Get stats directly from the my_project_ids module's global state
            # This ensures we're reading the most up-to-date counters
            current_debug_stats = my_project_ids.debug_stats
            
            # Recalculate detection rate as it's not a direct counter
            detection_rate = (current_debug_stats["malicious_detected"] / 
                              max(1, current_debug_stats["predictions_made"]))

            # Update global ids_stats dictionary in main.py
            ids_stats.update({
                "total_syscalls": current_debug_stats["syscalls_parsed"],
                "alerts_generated": current_debug_stats["malicious_detected"],
                "detection_rate": detection_rate,
                "lines_processed": current_debug_stats["lines_processed"],
                "suppressed_alerts": current_debug_stats["alerts_suppressed"],
                "is_running": ids_instance.monitoring_active # Explicitly get the current state from IDS instance
            })

            # Calculate uptime
            if ids_stats["start_time"]:
                uptime_seconds = (datetime.now() - ids_stats["start_time"]).total_seconds()
                hours, remainder = divmod(uptime_seconds, 3600)
                minutes, seconds = divmod(remainder, 60)
                ids_stats["uptime"] = f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"
            
            # `last_alert` is updated in `process_alert_queue` when an alert is consumed.

            time.sleep(1) # Update global stats every second
        
    except Exception as e:
        logger.error(f"Error in IDS monitoring management thread: {e}")
        # Ensure the IDS instance is stopped if an error occurs in its management thread
        if ids_instance:
            ids_instance.stop_monitoring() 
        ids_stats["is_running"] = False # Set main app status to stopped
    finally:
        logger.info("IDS monitoring management thread finished.")
        # Ensure ids_stats["is_running"] is false when this thread exits its loop
        ids_stats["is_running"] = False


# Background task to process alerts from queue (runs in FastAPI's main event loop)
async def process_alert_queue():
    """Processes alerts from the IDS queue and sends them via WebSocket."""
    while True:
        try:
            if not alert_queue.empty():
                alert_data = alert_queue.get_nowait()
                
                # 'type' field should already be set by my_project_ids.create_detailed_alert
                # or FastAPIAlertManager. If not, add a default.
                if "type" not in alert_data:
                    alert_data["type"] = "alert"

                # Update the global last_alert timestamp if this is an actual alert
                if alert_data.get("type") == "alert":
                    ids_stats["last_alert"] = alert_data.get("timestamp")
                
                # Send via WebSocket
                await manager.send_alert(alert_data)
                # Corrected logging to use 'severity' and 'details.process_name'
                logger.info(f"Alert sent via WebSocket: {alert_data.get('severity', 'UNKNOWN')} - {alert_data.get('details', {}).get('process_name', 'unknown')}")
            
            await asyncio.sleep(0.1)  # Small delay to prevent CPU spinning
        except Exception as e:
            logger.error(f"Error processing alert queue: {e}")
            await asyncio.sleep(1)

# API Routes
@app.get("/")
async def root():
    return {
        "message": "Real-Time IDS API", 
        "status": "running" if ids_stats["is_running"] else "stopped",
        "version": "1.0.0",
        "model_loaded": ids_instance is not None and ids_instance.model is not None
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy", 
        "timestamp": datetime.now().isoformat(),
        "ids_running": ids_stats["is_running"],
        "model_loaded": ids_instance is not None and ids_instance.model is not None
    }

@app.get("/stats", response_model=SystemStats)
async def get_stats():
    try:
        current_debug_stats = my_project_ids._get_current_debug_stats()
        return SystemStats(
            total_syscalls=current_debug_stats["syscalls_parsed"],
            alerts_generated=current_debug_stats["malicious_detected"],
            detection_rate=current_debug_stats["detection_rate"],
            uptime=ids_stats.get("uptime", "00:00:00"),
            last_alert=ids_stats.get("last_alert", "N/A"),
            lines_processed=current_debug_stats["lines_processed"],
            suppressed_alerts=current_debug_stats["alerts_suppressed"]
        )
    except Exception as e:
        logger.error(f"Error in /stats route: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch system stats.")


@app.get("/alerts/latest")
async def get_latest_alerts(limit: int = 10):
    """Get latest alerts from log file."""
    alerts = []
    try:
        alert_log_path = "alerts.log" # This path is from common.py's AlertManager
        if os.path.exists(alert_log_path):
            with open(alert_log_path, 'r', encoding='utf-8') as f:
                # Read all lines and reverse to get latest efficiently, then take limit
                lines = f.readlines()
                # Ensure the last N lines are read for efficiency, in case the log is huge
                for line in reversed(lines[-500:]): # Read from the last 500 lines to find N alerts
                    if len(alerts) >= limit:
                        break
                    try:
                        alert = json.loads(line.strip())
                        alerts.append(alert)
                    except json.JSONDecodeError:
                        logger.warning(f"Could not parse alert log line: {line.strip()}")
                        continue
                alerts.reverse() # Put them back in chronological order for consistency
    except Exception as e:
        logger.error(f"Error reading alert log: {e}")
    
    return {"alerts": alerts, "count": len(alerts), "limit": limit}

@app.post("/alerts/test", response_model=AlertModel)
async def generate_test_alert():
    # Simulate an alert being generated by the IDS and put into the queue
    test_alert = {
        "id": 9999, # Dummy ID for test alerts
        "timestamp": datetime.now().isoformat(),
        "severity": "MEDIUM", # Use 'severity' as per my_project_ids.py
        "prediction": "Suspicious",
        "confidence": 0.75,
        "model_info": {"version": "test", "accuracy_estimate": 0.0},
        "details": {"type": "test", "description": "Test alert from API", "simulated": True, "process_name": "test_process", "syscall_id": 123}, # Added process_name and syscall_id in details
        "triggered_by": "API_Test",
        "analysis_time": datetime.now().isoformat(),
        "type": "alert" # Ensure type is set for WebSocket filtering
    }
    try:
        alert_queue.put_nowait(test_alert)
        logger.info("Test alert put into queue.")
        return AlertModel(**test_alert) # Return as Pydantic model
    except queue.Full:
        raise HTTPException(status_code=503, detail="Alert queue is full, cannot send test alert.")


@app.post("/control/start")
async def start_monitoring(background_tasks: BackgroundTasks):
    global ids_thread, ids_instance
    
    if ids_stats["is_running"]:
        raise HTTPException(status_code=400, detail="IDS is already running")
    
    # Check if model files exist before starting IDS
    model_path_main = os.path.join(my_project_ids.MODEL_DIR, "rf_ids_model.joblib")
    backup_model_path_main = os.path.join(my_project_ids.MODEL_DIR, "rf_ids_model_backup.joblib")

    if not os.path.exists(model_path_main) and not os.path.exists(backup_model_path_main):
        raise HTTPException(
            status_code=400, 
            detail=f"ML models not found at {model_path_main} or {backup_model_path_main}. Please train the model first."
        )
    
    ids_stats["is_running"] = True # Set initial status to True
    ids_stats["start_time"] = datetime.now() # Store datetime object here
    
    # Start IDS monitoring management in background thread (this thread will manage RealtimeIDS instance)
    ids_thread = threading.Thread(target=run_ids_monitoring_thread_manager, daemon=True)
    ids_thread.start()
    
    # Start alert processing in the main FastAPI event loop
    background_tasks.add_task(process_alert_queue)
    
    logger.info("IDS monitoring started via API")
    return {"message": "IDS monitoring started", "status": "running"}

@app.post("/control/stop")
async def stop_monitoring(request: Request = None):
    global ids_instance
    
    if not ids_stats["is_running"]:
        raise HTTPException(status_code=400, detail="IDS is not running")
    
    # Signal to the management thread and IDS instance to stop
    ids_stats["is_running"] = False 
    if ids_instance:
        ids_instance.stop_monitoring()
    
    logger.info("IDS monitoring stopped via API")
    return {"message": "IDS monitoring stopped", "status": "stopped"}

@app.get("/config", response_model=IDSConfig)
async def get_config():
    # Retrieve current global config values from my_project_ids module
    config_values = {
        "monitoring_enabled": ids_stats["is_running"],
        "alert_threshold": my_project_ids.ALERT_THRESHOLD,
        "prob_alert_threshold": my_project_ids.PROB_ALERT_THRESHOLD,
        "alert_cooldown": my_project_ids.ALERT_COOLDOWN,
        "max_alerts_per_process": my_project_ids.MAX_ALERTS_PER_PROCESS,
        "whitelist": list(my_project_ids.SYSTEM_PROCESS_WHITELIST),
        "suppression_enabled": my_project_ids.ALERT_COOLDOWN > 0 or my_project_ids.MAX_ALERTS_PER_PROCESS > 0, # Simple heuristic
        "model_path": my_project_ids.MODEL_PATH
    }
    return IDSConfig(**config_values)

@app.post("/config", response_model=IDSConfig)
async def update_config(config: IDSConfig):
    """Update IDS configuration dynamically."""
    # Always update the module-level globals directly in my_project_ids
    # This ensures that even if IDS is not running, the next start picks up new config
    if config.alert_threshold is not None:
        my_project_ids.ALERT_THRESHOLD = config.alert_threshold
    if config.prob_alert_threshold is not None:
        my_project_ids.PROB_ALERT_THRESHOLD = config.prob_alert_threshold
    if config.alert_cooldown is not None:
        my_project_ids.ALERT_COOLDOWN = config.alert_cooldown
    if config.max_alerts_per_process is not None:
        my_project_ids.MAX_ALERTS_PER_PROCESS = config.max_alerts_per_process
    if config.whitelist is not None:
        # Note: If SYSTEM_PROCESS_WHITELIST is a set in my_project_ids, update it.
        # Ensure it's not reassigned as a list if it needs to remain a set.
        my_project_ids.SYSTEM_PROCESS_WHITELIST.clear()
        my_project_ids.SYSTEM_PROCESS_WHITELIST.update(config.whitelist)
    
    # If the IDS instance is running, tell it to update its internal config based on these globals
    if ids_instance: 
        ids_instance.update_config(config.dict(exclude_unset=True)) # Pass relevant config
    
    logger.info(f"Configuration update request received: {config.dict(exclude_unset=True)}")
    # Return the current state of the config after update
    return await get_config()


@app.get("/model/info")
async def get_model_info():
    try:
        from my_project_ids import model_stats, MODEL_PATH, RealtimeIDS
        if model_stats["load_time"] is None:
            return {"model_loaded": False, "error": "Model has not been loaded yet."}

        model_loaded = ids_instance and ids_instance.model is not None
        vectorizer_loaded = ids_instance and ids_instance.vectorizer is not None

        return {
            "model_loaded": model_loaded,
            "model_type": type(ids_instance.model).__name__ if model_loaded else "N/A",
            "features": len(ids_instance.vectorizer.get_feature_names_out()) if vectorizer_loaded else 0,
            "model_file": MODEL_PATH,
            "version": model_stats["model_version"],
            "accuracy_estimate": model_stats["model_accuracy_estimate"],
            "load_time": model_stats["load_time"]
        }
    except Exception as e:
        logger.error(f"Failed to return model info: {e}")
        return {"model_loaded": False, "error": str(e)}


# WebSocket endpoint for real-time alerts and stats
@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Send initial stats safely
        safe_stats = ids_stats.copy()
        # Ensure serializability
        if isinstance(safe_stats.get("start_time"), datetime):
            safe_stats["start_time"] = safe_stats["start_time"].isoformat()
        safe_stats["last_alert"] = str(safe_stats.get("last_alert") or "N/A")

        await websocket.send_text(json.dumps({"type": "stats", "data": safe_stats}))
        logger.info("✅ Sent initial stats to WebSocket client.")

        # Keep connection alive and send periodic updates
        while True:
            await asyncio.sleep(5)

            try:
                updated_stats = ids_stats.copy()
                if isinstance(updated_stats.get("start_time"), datetime):
                    updated_stats["start_time"] = updated_stats["start_time"].isoformat()
                updated_stats["last_alert"] = str(updated_stats.get("last_alert") or "N/A")

                await websocket.send_text(json.dumps({"type": "stats", "data": updated_stats}))
                logger.debug(f"📡 Stats broadcasted: {updated_stats['lines_processed']}")
            except Exception as ws_err:
                logger.warning(f"Failed to send periodic stats: {ws_err}")
                break

    except WebSocketDisconnect:
        logger.info("🔌 WebSocket disconnected by client.")
        manager.disconnect(websocket)

    except Exception as e:
        logger.error(f"❌ WebSocket error: {e}")
        manager.disconnect(websocket)


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Real-Time IDS Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
            .container { max-width: 1200px; margin: 0 auto; }
            .header { text-align: center; margin-bottom: 30px; }
            .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
            .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); border-left: 4px solid #007bff; }
            .card h3 { margin-top: 0; color: #333; }
            .card h2 { margin: 10px 0; font-size: 2em; }
            .status-running { border-left-color: #28a745; }
            .status-stopped { border-left-color: #dc3545; }
            .alert-high { border-left-color: #dc3545; background: #fff5f5; }
            .alert-medium { border-left-color: #ffc107; background: #fffdf5; }
            .alert-low { border-left-color: #17a2b8; background: #f5fffe; }
            .controls { text-align: center; margin: 20px 0; }
            .btn { padding: 10px 20px; margin: 0 10px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
            .btn-start { background: #28a745; color: white; }
            .btn-stop { background: #dc3545; color: white; }
            .btn-test { background: #ffc107; color: black; }
            #alerts { background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .alert-item { background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #007bff; }
            .alert-item.HIGH { border-left-color: #dc3545; background: #fff5f5; }
            .alert-item.MEDIUM { border-left-color: #ffc107; background: #fffdf5; }
            .alert-item.LOW { border-left-color: #17a2b8; background: #f5fffe; }
            .timestamp { color: #666; font-size: 0.9em; }
            .confidence { font-weight: bold; }
            .status-indicator { display: inline-block; width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; }
            .status-running .status-indicator { background: #28a745; }
            .status-stopped .status-indicator { background: #dc3545; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ Real-Time Intrusion Detection System</h1>
                <p>AI-powered syscall monitoring and threat detection</p>
            </div>
            
            <div class="stats">
                <div class="card" id="status-card">
                    <h3><span class="status-indicator"></span>System Status</h3>
                    <h2 id="status">Stopped</h2>
                    <p id="uptime">Uptime: 00:00:00</p>
                </div>
                <div class="card">
                    <h3>📊 Lines Processed</h3>
                    <h2 id="lines-processed">0</h2>
                    <p>Total audit log lines</p>
                </div>
                <div class="card">
                    <h3>🔍 System Calls</h3>
                    <h2 id="syscalls">0</h2>
                    <p>Parsed and analyzed</p>
                </div>
                <div class="card">
                    <h3>⚠️ Alerts Generated</h3>
                    <h2 id="alerts-count">0</h2>
                    <p>Security threats detected</p>
                </div>
                <div class="card">
                    <h3>🎯 Detection Rate</h3>
                    <h2 id="detection-rate">0%</h2>
                    <p>Malicious vs total</p>
                </div>
                <div class="card">
                    <h3>🔇 Suppressed</h3>
                    <h2 id="suppressed">0</h2>
                    <p>Duplicate alerts filtered</p>
                </div>
            </div>

            <div class="controls">
                <button class="btn btn-start" onclick="startMonitoring()">▶️ Start Monitoring</button>
                <button class="btn btn-stop" onclick="stopMonitoring()">⏹️ Stop Monitoring</button>
                <button class="btn btn-test" onclick="sendTestAlert()">🧪 Test Alert</button>
            </div>

            <div id="alerts">
                <h3>🚨 Live Alerts</h3>
                <div id="alert-list">
                    <p style="color: #666; text-align: center;">No alerts yet. Monitoring will show real-time threats here.</p>
                </div>
            </div>
        </div>

        <script>
            // Use window.location.host for dynamic host in WebSocket connection
            const ws = new WebSocket('ws://' + window.location.host + '/ws/alerts');
            
            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                
                if (data.type === 'stats') {
                    updateStats(data.data);
                } else if (data.type === 'alert') {
                    // Add console.log here to inspect the incoming alert object!
                    console.log('Received alert via WebSocket:', data); 
                    addAlert(data);
                } else {
                    // Fallback: Assume it's an alert if no specific type is provided
                    console.warn('Received unknown message type, assuming alert:', data);
                    addAlert(data);
                }
            };

            ws.onopen = function() {
                console.log('WebSocket connected');
            };

            ws.onclose = function() {
                console.log('WebSocket disconnected');
                // You might want to implement a reconnect logic here in a production app
                // For development, removed auto-reload to avoid refreshing dashboard during debugging
                // setTimeout(() => location.reload(), 5000); 
            };

            function updateStats(stats) {
                document.getElementById('lines-processed').textContent = stats.lines_processed || 0;
                document.getElementById('syscalls').textContent = stats.total_syscalls || 0;
                document.getElementById('alerts-count').textContent = stats.alerts_generated || 0;
                document.getElementById('detection-rate').textContent = ((stats.detection_rate || 0) * 100).toFixed(1) + '%';
                document.getElementById('suppressed').textContent = stats.suppressed_alerts || 0;
                document.getElementById('uptime').textContent = 'Uptime: ' + (stats.uptime || '00:00:00');
                
                const statusCard = document.getElementById('status-card');
                const statusText = document.getElementById('status');
                
                if (stats.is_running) {
                    statusCard.className = 'card status-running';
                    statusText.textContent = 'Running';
                } else {
                    statusCard.className = 'card status-stopped';
                    statusText.textContent = 'Stopped';
                }
            }

            function addAlert(alert) {
                const alertList = document.getElementById('alert-list');
                
                // Remove "no alerts" message if present
                if (alertList.innerHTML.includes('No alerts yet')) {
                    alertList.innerHTML = '';
                }
                
                const alertDiv = document.createElement('div');
                // Use alert.severity for dynamic styling classes (HIGH, MEDIUM, LOW)
                // Ensure alert.severity is a string (e.g., 'HIGH', 'MEDIUM', 'LOW')
                alertDiv.className = `alert-item ${alert.severity ? alert.severity.toUpperCase() : 'UNKNOWN'}`; 
                alertDiv.innerHTML = `
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <strong>${alert.severity || 'UNKNOWN'}</strong> - ${alert.details.process_name || 'N/A'}
                            <div class="timestamp">${new Date(alert.timestamp).toLocaleString()}</div>
                            <div>Syscall: ${alert.details && alert.details.syscall_id ? alert.details.syscall_id : 'N/A'}</div>
                        </div>
                        <div class="confidence">${(alert.confidence * 100).toFixed(1)}%</div>
                    </div>
                `;
                alertList.insertBefore(alertDiv, alertList.firstChild);
                
                // Keep only last 20 alerts to prevent UI overload
                while (alertList.children.length > 20) {
                    alertList.removeChild(alertList.lastChild);
                }
            }

            async function startMonitoring() {
                try {
                    const response = await fetch('/control/start', { method: 'POST' });
                    const result = await response.json();
                    if (response.ok) {
                        alert('✅ ' + result.message);
                    } else {
                        alert('❌ ' + result.detail);
                    }
                } catch (error) {
                    alert('❌ Error: ' + error.message);
                }
            }

            async function stopMonitoring() {
                try {
                    const response = await fetch('/control/stop', { method: 'POST' });
                    const result = await response.json();
                    if (response.ok) {
                        alert('⏹️ ' + result.message);
                    } else {
                        alert('❌ ' + result.detail);
                    }
                } catch (error) {
                    alert('❌ Error: ' + error.message);
                }
            }

            async function sendTestAlert() {
                try {
                    const response = await fetch('/alerts/test', { method: 'POST' });
                    const result = await response.json();
                    if (response.ok) {
                        console.log('Test alert sent successfully:', result);
                    } else {
                        alert('❌ Error: ' + result.detail);
                    }
                } catch (error) {
                    alert('❌ Error sending test alert: ' + error.message);
                }
            }

            // Load initial stats when the dashboard loads
            fetch('/stats')
                .then(response => response.json())
                .then(stats => updateStats(stats))
                .catch(error => console.error('Failed to load initial stats:', error));
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

# Startup event: Log startup and ensure model directory exists
@app.on_event("startup")
async def startup_event():
    logger.info("FastAPI IDS server starting up...")
    
    # Ensure the models directory exists, so my_project_ids can try to load models
    model_dir = os.path.join("models", "model_os")
    if not os.path.exists(model_dir):
        logger.warning(f"Model directory '{model_dir}' does not exist. Please ensure your ML models are in place for detection to work.")
        # Optionally create the directory if you expect models to be placed there later
        # os.makedirs(model_dir, exist_ok=True)


# Shutdown event: Gracefully stop IDS monitoring
@app.on_event("shutdown")
async def shutdown_event():
    global ids_instance
    logger.info("FastAPI IDS server shutting down...")
    
    # Signal to the management thread and IDS instance to stop
    # This also sets ids_stats["is_running"] to False within the thread.
    if ids_instance:
        ids_instance.stop_monitoring()
    
    # Give a small moment for threads to clean up
    time.sleep(1) 
    ids_stats["is_running"] = False # Final state update for dashboard clarity

if __name__ == "__main__":
    logger.info("Starting FastAPI IDS server...")
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True, # Reloads the server on code changes
        log_level="info"
    )

