"""
HopTrace Forensics Platform - Runner Script.
Launches the FastAPI backend and opens the Cyber SOC Dashboard in your browser.
"""

import os
import sys
import webbrowser
import threading
import time
import uvicorn

def open_browser():
    """Waits 1.5 seconds for the server to bind, then launches the dashboard."""
    time.sleep(1.5)
    webbrowser.open("http://127.0.0.1:8050")

if __name__ == "__main__":
    print("=" * 70)
    print("    HOPTRACE FORENSICS PLATFORM — SIH 2026 (PS 26106)")
    print("    AI-Powered Email Threat Detection & GeoLocation Intelligence")
    print("    Organization: AICTE Cyber Security Cell")
    print("=" * 70)
    print("\n[+] Starting SOC Dashboard on http://127.0.0.1:8050 ...")
    print("[+] Press Ctrl+C to stop.\n")

    # Check if running in cloud (PORT env var present)
    port = int(os.environ.get("PORT", 8050))
    is_cloud = "PORT" in os.environ
    host = "0.0.0.0" if is_cloud else "127.0.0.1"

    if not is_cloud:
        # Start browser launcher in a background thread only on local machine
        threading.Thread(target=open_browser, daemon=True).start()

    # Run FastAPI app
    uvicorn.run("server:app", host=host, port=port, log_level="info")

