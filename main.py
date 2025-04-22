from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import logging

app = FastAPI()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development, change in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static HTML/JS from "static" folder
app.mount("/", StaticFiles(directory="static", html=True), name="static")

# Connected clients store
connected_clients = set()

@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.add(websocket)
    logging.info("⚡ Client connected")

    try:
        while True:
            data = await websocket.receive_text()
            logging.info(f"🔔 Alert received: {data}")
    except Exception as e:
        logging.warning(f"⚠️ WebSocket error: {e}")
    finally:
        connected_clients.remove(websocket)
        logging.info("❌ Client disconnected")

# Access this globally from realtime_ids.py
def get_connected_clients():
    return connected_clients
