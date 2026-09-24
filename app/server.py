import os
import sys
import asyncio
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, UploadFile, File
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from pydantic import BaseModel

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app.database import db
from app.engine import engine
from app.simulator import simulator
from app.forensics import forensics
from app.intel import intel_provider
from app.reports import report_generator

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

# Background task to pipe sync engine events into async WebSocket broadcaster (bounded buffer)
event_queue = asyncio.Queue(maxsize=1000)

def sync_event_listener(event: Dict[str, Any]):
    try:
        loop = getattr(app.state, "event_loop", None)
        if loop and loop.is_running():
            if event_queue.full():
                try:
                    event_queue.get_nowait()
                except Exception:
                    pass
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

# --- Phase 3 Forensics, Threat Intel & Reporting Endpoints ---

@app.get("/api/reports/audit", response_class=HTMLResponse)
async def get_audit_report():
    """Generates an executive forensic security incident audit report."""
    html = report_generator.generate_html_report()
    return HTMLResponse(content=html, status_code=200)

@app.get("/api/incidents")
async def list_incident_pcaps():
    """Returns list of captured incident PCAP files available for forensic download."""
    return forensics.get_incident_files()

@app.get("/api/incidents/{filename}")
async def download_incident_pcap(filename: str):
    """Downloads a raw forensic PCAP file for inspection in Wireshark."""
    filepath = forensics.get_filepath(filename)
    if not filepath or not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Incident PCAP not found.")
    return FileResponse(filepath, media_type="application/vnd.tcpdump.pcap", filename=filename)

@app.post("/api/pcap/analyze")
async def analyze_uploaded_pcap(file: UploadFile = File(...)):
    """
    Offline PCAP Analysis Studio:
    Accepts user-uploaded .pcap/.pcapng file and performs full Random Forest
    threat inference and Shannon entropy profiling.
    """
    if not file.filename.lower().endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(status_code=400, detail="Invalid file format. Upload .pcap or .pcapng files.")

    import shutil
    import tempfile

    temp_dir = tempfile.gettempdir()
    safe_name = f"analyze_{os.path.basename(file.filename)}"
    temp_path = os.path.join(temp_dir, safe_name)

    try:
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        analysis = forensics.analyze_pcap_file(temp_path)
        analysis["filename"] = file.filename
        return analysis
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing PCAP: {e}")
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass

CURRENT_VERSION = "2.1.0"

@app.get("/api/version/check")
async def check_for_updates():
    """
    Checks GitHub Releases API to see if a newer version of CryptoFlow-IDS
    has been published. Returns update status, download URL, and release notes.
    """
    import urllib.request
    import json

    result = {
        "current_version": f"v{CURRENT_VERSION}",
        "latest_version": f"v{CURRENT_VERSION}",
        "update_available": False,
        "download_url": f"https://github.com/Santhosh939s/CryptoFlow-IDS/releases/download/v{CURRENT_VERSION}/CryptoFlow-IDS-Setup.exe",
        "release_url": f"https://github.com/Santhosh939s/CryptoFlow-IDS/releases/tag/v{CURRENT_VERSION}",
        "release_name": f"v{CURRENT_VERSION}"
    }

    try:
        url = "https://api.github.com/repos/Santhosh939s/CryptoFlow-IDS/releases/latest"
        req = urllib.request.Request(url, headers={"User-Agent": f"CryptoFlow-IDS/{CURRENT_VERSION}"})

        loop = asyncio.get_running_loop()
        def _fetch():
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                if resp.status == 200:
                    return json.loads(resp.read().decode('utf-8'))
            return None

        data = await loop.run_in_executor(None, _fetch)
        if data and "tag_name" in data:
            latest_tag = data["tag_name"].strip()
            latest_clean = latest_tag.lstrip("v").strip()
            current_clean = CURRENT_VERSION.lstrip("v").strip()

            def parse_ver(v_str):
                return [int(x) for x in v_str.split(".") if x.isdigit()]

            is_newer = parse_ver(latest_clean) > parse_ver(current_clean)

            setup_download_url = data.get("html_url")
            for asset in data.get("assets", []):
                if asset.get("name", "").endswith("-Setup.exe"):
                    setup_download_url = asset.get("browser_download_url")
                    break

            result["latest_version"] = latest_tag
            result["update_available"] = is_newer
            result["download_url"] = setup_download_url
            result["release_url"] = data.get("html_url")
            result["release_name"] = data.get("name", latest_tag)
    except Exception:
        pass

    return result

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
