import os
import sys
import time
import socket
import threading
import webbrowser
import uvicorn
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("CryptoFlowApp")

def is_admin() -> bool:
    """Check if the current process has administrative privileges."""
    if sys.platform == "win32":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0

def find_free_port(default_port: int = 8000) -> int:
    """Find a free TCP port to host the local application server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if s.connect_ex(('127.0.0.1', default_port)) != 0:
            return default_port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def run_server(port: int):
    """Run uvicorn server serving FastAPI."""
    from app.server import app
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")

def main():
    print("=" * 60)
    print("      CryptoFlow-IDS — Next-Generation Cyber Defense App")
    print("=" * 60)

    if not is_admin():
        print("\n⚠️  [NOTICE] Not running with Administrator / Root privileges.")
        print("   Real-time packet sniffing and automated firewall mitigation")
        print("   require Administrator rights to modify firewall rules.\n")

    port = find_free_port(8000)
    app_url = f"http://127.0.0.1:{port}"

    # Start FastAPI server in background daemon thread
    server_thread = threading.Thread(target=run_server, args=(port,), daemon=True)
    server_thread.start()

    # Wait for server to bind
    time.sleep(1.2)
    print(f"\n🚀 CryptoFlow-IDS Server active at: {app_url}")
    print("   Starting desktop interface...\n")

    # Try native desktop window via pywebview if available
    launched_native = False
    try:
        import webview
        print("[*] Launching native desktop window (pywebview)...")
        webview.create_window(
            title="CryptoFlow-IDS — Cyber Defense HUD",
            url=app_url,
            width=1320,
            height=860,
            min_size=(900, 600)
        )
        launched_native = True
        webview.start()
    except ImportError:
        pass
    except Exception as e:
        logger.warning(f"Native desktop window error: {e}")

    # Fallback to system browser
    if not launched_native:
        print("[*] Opening CryptoFlow HUD in your default desktop browser...")
        webbrowser.open(app_url)
        print("\nPress Ctrl+C in this terminal to shut down the application.\n")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down CryptoFlow-IDS...")

    # Teardown
    from app.engine import engine
    engine.stop()
    engine.mitigator.cleanup()
    print("Clean shutdown complete. Goodbye!")

if __name__ == "__main__":
    main()
