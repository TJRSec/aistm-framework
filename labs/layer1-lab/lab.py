#!/usr/bin/env python3
"""
AISTM 4-Layer Security Lab - Unified Setup/Start/Stop Script

Complete implementation of all 4 AISTM security layers:
- Layer 1: Pre-AI Input Validation (11 controls, 63 tests)
- Layer 2: AI Interaction Security (4 controls, 24 tests)
- Layer 3: Post-AI Output Security (5 controls, 26 tests)
- Layer 4: Backend Integration Security (4 controls, 44 tests)

Total: 24 controls, 157 tests, 100% coverage

Usage:
    python lab.py start   # Setup (if needed) and start the lab server
    python lab.py stop    # Stop any running lab server
    python lab.py reset   # Reset config and re-run setup

Features:
- Installs dependencies if missing
- Loads or creates config
- Prompts for API keys if needed
- Downloads ML models (optional)
- Starts/stops FastAPI server with all 4 layers active
"""
import os
import sys
import subprocess
import signal
import time
import json
from pathlib import Path

LAB_DIR = Path(__file__).parent
CONFIG_PATH = LAB_DIR / "config.json"
ENV_PATH = LAB_DIR / ".env"
REQUIREMENTS_PATH = LAB_DIR / "requirements.txt"
PID_PATH = LAB_DIR / "lab_server.pid"

# --- Utility Functions ---
def print_info(msg):
    print(f"\033[96m[INFO]\033[0m {msg}")
def print_success(msg):
    print(f"\033[92m✓\033[0m {msg}")
def print_error(msg):
    print(f"\033[91m✗\033[0m {msg}")

def install_deps():
    if not REQUIREMENTS_PATH.exists():
        print_error("requirements.txt not found!")
        sys.exit(1)
    print_info("Installing Python dependencies...")
    result = subprocess.run([sys.executable, "-m", "pip", "install", "-r", str(REQUIREMENTS_PATH)])
    if result.returncode == 0:
        print_success("Dependencies installed.")
    else:
        print_error("Dependency installation failed.")
        sys.exit(1)

def prompt_api_keys():
    print_info("API key setup for providers (leave blank to skip)")
    keys = {}
    for provider, envvar in [
        ("anthropic", "ANTHROPIC_API_KEY"),
        ("gemini", "GOOGLE_API_KEY"),
        ("openai", "OPENAI_API_KEY")]:
        val = input(f"  {provider} ({envvar}): ").strip()
        if val:
            keys[envvar] = val
    if keys:
        with open(ENV_PATH, "w") as f:
            for k, v in keys.items():
                f.write(f"{k}={v}\n")
        print_success("API keys saved to .env")
    else:
        print_info("No API keys entered.")

def ensure_config(reset=False):
    if reset or not CONFIG_PATH.exists():
        print_info("Creating new config.json...")
        config = {
            "provider": "anthropic",
            "providers": {
                "anthropic": {"model": "claude-2.1", "temperature": 0.7, "max_tokens": 2048},
                "gemini": {"model": "gemini-pro", "temperature": 0.7, "max_tokens": 2048},
                "openai": {"model": "gpt-3.5-turbo", "temperature": 0.7, "max_tokens": 2048}
            },
            "controls": {},
            "api_keys": {}
        }
        with open(CONFIG_PATH, "w") as f:
            json.dump(config, f, indent=2)
        print_success("config.json created/reset.")
    else:
        print_info("Using existing config.json.")

def download_models():
    print_info("Checking for required ML models...")
    # Check for spaCy model
    try:
        import spacy
        try:
            spacy.load("en_core_web_lg")
            print_success("spaCy model 'en_core_web_lg' is already installed.")
        except OSError:
            # Try to load from local path
            local_model_path = str(LAB_DIR / "models" / "en_core_web_lg")
            try:
                spacy.load(local_model_path)
                print_success(f"spaCy model loaded from local path: {local_model_path}")
            except OSError:
                print_info("spaCy model 'en_core_web_lg' not found globally or locally. Attempting download...")
                try:
                    subprocess.run([sys.executable, "-m", "spacy", "download", "en_core_web_lg"], check=True)
                    print_success("spaCy model 'en_core_web_lg' downloaded.")
                except Exception:
                    print_error("spaCy model download failed. See models/README.md for manual instructions.")
    except ImportError:
        print_error("spaCy is not installed. Please install it via requirements.txt.")
    print_info("For sentence-transformers and detoxify, see models/README.md if needed.")

def start_server():
    print_info("Starting lab server...")
    # Use uvicorn for production-like run
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "server:app", "--host", "127.0.0.1", "--port", "8847"], cwd=LAB_DIR)
    with open(PID_PATH, "w") as f:
        f.write(str(proc.pid))
    print_success(f"Server started (PID {proc.pid}). Open http://127.0.0.1:8847/")
    try:
        proc.wait()
    except KeyboardInterrupt:
        print_info("Shutting down server...")
        proc.terminate()
        proc.wait()
        print_success("Server stopped.")

def stop_server():
    if PID_PATH.exists():
        with open(PID_PATH) as f:
            pid = int(f.read().strip())
        try:
            os.kill(pid, signal.SIGTERM)
            print_success(f"Stopped server (PID {pid})")
        except Exception:
            print_error("Could not stop server (already stopped?)")
        PID_PATH.unlink()
    else:
        print_info("No running server found.")

def main():
    menu = [
        ("Start the lab server (setup if needed)", "start"),
        ("Stop the running lab server", "stop"),
        ("Reset config and re-run setup", "reset"),
        ("Exit", "exit")
    ]
    cmd = None
    # If run with a command-line arg, use it; else show menu
    if len(sys.argv) >= 2 and sys.argv[1] in {"start", "stop", "reset"}:
        cmd = sys.argv[1]
    else:
        print("""
============================
 AISTM Layer 1 Lab Toolbox
============================
""")
        for i, (desc, _) in enumerate(menu, 1):
            print(f"  {i}. {desc}")
        while True:
            choice = input("\nSelect an option [1-4]: ").strip()
            if choice.isdigit() and 1 <= int(choice) <= len(menu):
                cmd = menu[int(choice)-1][1]
                break
            else:
                print("Invalid selection. Please enter a number 1-4.")
    if cmd == "start":
        install_deps()
        ensure_config()
        if not ENV_PATH.exists():
            prompt_api_keys()
        download_models()
        start_server()
    elif cmd == "stop":
        stop_server()
    elif cmd == "reset":
        stop_server()
        ensure_config(reset=True)
        prompt_api_keys()
        download_models()
        print_success("Lab reset. Run 'python lab.py start' to launch.")
    elif cmd == "exit":
        print("Goodbye!")
        sys.exit(0)

if __name__ == "__main__":
    main()
