import os
import sys
import asyncio
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app.database import db
from app.engine import engine
from app.simulator import simulator

app = FastAPI(title="CryptoFlow-IDS API", version="2.0.0")

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

# Ensure static directories exist
os.makedirs(os.path.join(STATIC_DIR, "css"), exist_ok=True)
os.makedirs(os.path.join(STATIC_DIR, "js"), exist_ok=True)

# Mount static files
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# WebSocket Connection Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

manager = ConnectionManager()

# Background task to pipe sync engine events into async WebSocket broadcaster
event_queue = asyncio.Queue()

def sync_event_listener(event: Dict[str, Any]):
    try:
        # Schedule put on main event loop if available
        loop = getattr(app.state, "event_loop", None)
        if loop and loop.is_running():
            asyncio.run_coroutine_threadsafe(event_queue.put(event), loop)
    except Exception:
        pass

engine.subscribe(sync_event_listener)

async def telemetry_broadcaster():
    """Reads engine events and sends them through active WebSockets."""
    while True:
        try:
            event = await asyncio.wait_for(event_queue.get(), timeout=1.0)
            await manager.broadcast(event)
        except asyncio.TimeoutError:
            # Emit periodic status tick even if no packets
            if manager.active_connections:
                status = engine.get_status()
                await manager.broadcast({"type": "tick", "data": status})
        except Exception:
            await asyncio.sleep(0.1)

@app.on_event("startup")
async def startup_event():
    app.state.event_loop = asyncio.get_running_loop()
    asyncio.create_task(telemetry_broadcaster())

# --- Routes ---

@app.get("/")
async def get_index():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "CryptoFlow-IDS API Active. UI is building..."}

@app.get("/api/status")
async def get_status():
    return {
        "engine": engine.get_status(),
        "simulator": simulator.get_status(),
        "db_stats": db.get_stats_summary()
    }

@app.get("/api/interfaces")
async def get_interfaces():
    return engine.get_available_interfaces()

class EngineControlReq(BaseModel):
    interface: Optional[str] = None

@app.post("/api/engine/start")
async def start_engine(req: EngineControlReq = None):
    iface = req.interface if req else None
    engine.start(interface=iface)
    return {"status": "started", "interface": engine.selected_interface}

@app.post("/api/engine/stop")
async def stop_engine():
    engine.stop()
    return {"status": "stopped"}

@app.get("/api/threats")
async def get_threats(limit: int = 50):
    return db.get_recent_threats(limit=limit)

@app.get("/api/blocked-ips")
async def get_blocked_ips():
    return db.get_active_blocked_ips()

@app.delete("/api/blocked-ips/{ip}")
async def unblock_ip(ip: str):
    # Call mitigator unblock
    success = engine.mitigator.unblock_ip(ip)
    db.remove_blocked_ip(ip)
    await manager.broadcast({"type": "ip_unblocked", "data": {"ip": ip, "success": success}})
    return {"status": "unblocked", "ip": ip, "success": success}

class SimReq(BaseModel):
    mode: str = "both"
    chunks: int = 5

@app.post("/api/simulate")
async def run_simulation(req: SimReq):
    started = simulator.run_simulation_async(
        mode=req.mode,
        chunks=req.chunks,
        callback=lambda res: sync_event_listener({"type": "sim_completed", "data": res})
    )
    if not started:
        raise HTTPException(status_code=400, detail="Simulation already running.")
    return {"status": "simulation_started", "mode": req.mode}

@app.websocket("/ws/telemetry")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Send initial state snapshot
        await websocket.send_json({
            "type": "init",
            "data": {
                "engine": engine.get_status(),
                "threats": db.get_recent_threats(limit=20),
                "blocked_ips": db.get_active_blocked_ips(),
                "interfaces": engine.get_available_interfaces()
            }
        })
        while True:
            # Keep socket alive
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
