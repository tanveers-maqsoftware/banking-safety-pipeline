#!/usr/bin/env python3
import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path


class LauncherError(Exception):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the banking safety pipeline locally")
    parser.add_argument("--port", type=int, default=8000, help="Local port for the FastAPI app")
    parser.add_argument("--no-tunnel", action="store_true", help="Start the API without opening a Cloudflare tunnel")
    return parser.parse_args()


def wait_for_health(port: int, timeout_seconds: int = 60) -> dict:
    deadline = time.time() + timeout_seconds
    last_error: Exception | None = None

    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/v1/health", timeout=2) as response:
                data = json.load(response)
                if data.get("status") == "ok":
                    return data
        except Exception as exc:  # pragma: no cover - runtime behavior
            last_error = exc
        time.sleep(1)

    raise LauncherError(f"API did not become healthy within {timeout_seconds}s: {last_error}")


def ensure_port_available(port: int, host: str = "127.0.0.1") -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError as exc:
            raise LauncherError(
                f"Port {port} is already in use on {host}. Stop the existing process or run with a different --port."
            ) from exc


def start_process(cmd: list[str], cwd: Path, env: dict | None = None) -> subprocess.Popen:
    return subprocess.Popen(
        cmd,
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )


def stream_output(process: subprocess.Popen, sink: list[str]) -> None:
    assert process.stdout is not None
    for line in process.stdout:
        sink.append(line.rstrip())


def stop_process(process: subprocess.Popen | None) -> None:
    if process is None:
        return
    if process.poll() is None:
        if os.name == "nt":
            process.terminate()
        else:
            process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parent

    python_exe = None
    venv_candidates = [
        root / ".venv" / "Scripts" / "python.exe",
        root / ".venv" / "bin" / "python",
    ]
    for candidate in venv_candidates:
        if candidate.exists() and os.access(candidate, os.X_OK):
            python_exe = str(candidate)
            break

    if not python_exe:
        python_exe = sys.executable or "python3"
    if not python_exe:
        raise LauncherError("Could not determine the current Python interpreter")

    if not (root / "main.py").exists():
        raise LauncherError("main.py not found in the project root")

    ensure_port_available(args.port)
    print(f"Starting API on 127.0.0.1:{args.port} ...")
    api_process = start_process([python_exe, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", str(args.port)], root)

    try:
        health = wait_for_health(args.port)
    except LauncherError as exc:
        stop_process(api_process)
        raise RuntimeError(str(exc)) from exc

    print("API healthy. Serving prompts:")
    for name, version in health.get("active_prompts", {}).items():
        print(f"  {name}@{version}")

    if not args.no_tunnel:
        print("\nOpening Cloudflare tunnel ...")
        tunnel_process = start_process(["cloudflared", "tunnel", "--url", f"http://127.0.0.1:{args.port}"], root)
        tunnel_lines: list[str] = []
        tunnel_thread = threading.Thread(target=stream_output, args=(tunnel_process, tunnel_lines), daemon=True)
        tunnel_thread.start()

        url = ""
        for _ in range(45):
            time.sleep(1)
            for line in tunnel_lines:
                if "https://" in line and ".trycloudflare.com" in line:
                    url = line.split("https://", 1)[1].split()[0]
                    if not url.startswith("http"):
                        url = f"https://{url}"
                    break
            if url:
                break
            if tunnel_process.poll() is not None:
                raise LauncherError("cloudflared exited before a tunnel URL was produced")

        if not url:
            stop_process(api_process)
            stop_process(tunnel_process)
            raise LauncherError("Could not read the tunnel URL from cloudflared output")

        print()
        print(f"  Public URL : {url}")
        print(f"  Connector  : {url}/v1/process")
        print(f"  Health     : {url}/v1/health")
        print(f"  API docs   : http://127.0.0.1:{args.port}/docs")
        print()
        print("This URL is new on every restart -- re-point the Copilot Studio")
        print("connector whenever you restart this script.")
        print("\nCtrl+C to stop both processes.")
    else:
        print(f"\nLocal API ready at http://127.0.0.1:{args.port}")
        print("Run with --no-tunnel to skip Cloudflare.")

    try:
        while True:
            time.sleep(1)
            if api_process.poll() is not None:
                raise LauncherError("The API process exited unexpectedly")
            if not args.no_tunnel and tunnel_process.poll() is not None:
                raise LauncherError("The tunnel process exited unexpectedly")
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        stop_process(api_process)
        if not args.no_tunnel:
            stop_process(tunnel_process)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(0)
    except Exception as exc:  # pragma: no cover - CLI error reporting
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
