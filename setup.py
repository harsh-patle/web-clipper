#!/usr/bin/env python3
"""
setup.py - Web Clipper Multi-User Setup v3.0
Run once to configure OAuth credentials, then it starts the server.
"""

import subprocess, sys, os, json, webbrowser

BASE = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.path.join(BASE, ".env")

def check_python():
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ required"); sys.exit(1)
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor}")

def install_deps():
    print("\n📦 Installing dependencies...")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r",
         os.path.join(BASE, "requirements.txt"), "--quiet"],
        capture_output=True, text=True)
    if result.returncode != 0:
        print("❌ Install failed:", result.stderr[:300]); sys.exit(1)
    print("✅ Dependencies installed")

def load_env():
    env = {}
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, _, v = line.partition("=")
                    env[k.strip()] = v.strip()
    return env

def save_env(env: dict):
    with open(ENV_FILE, "w") as f:
        for k, v in env.items():
            f.write(f"{k}={v}\n")

def setup_oauth():
    env = load_env()

    if (env.get("NOTION_CLIENT_ID","").startswith("YOUR")
            or not env.get("NOTION_CLIENT_ID")):
        print("\n🔑  Notion OAuth Setup")
        print("─" * 55)
        print("Web Clipper v3.0 uses OAuth so ANY user can log in.")
        print()
        print("Create a PUBLIC Notion integration:")
        print("  1. Go to https://www.notion.so/my-integrations")
        print("  2. Click '+ New integration'")
        print("  3. Set type to 'Public' (not Internal)")
        print("  4. Add redirect URI: http://localhost:5001/auth/callback")
        print("  5. Copy the OAuth Client ID and Client Secret")
        print()
        client_id     = input("OAuth Client ID:     ").strip()
        client_secret = input("OAuth Client Secret: ").strip()

        env["NOTION_CLIENT_ID"]     = client_id
        env["NOTION_CLIENT_SECRET"] = client_secret
        env["REDIRECT_URI"]         = "http://localhost:5001/auth/callback"
        env["NOTION_VERSION"]       = "2022-06-28"
        save_env(env)
        print("\n✅ Credentials saved to .env")
    else:
        print(f"\n✅ OAuth credentials found ({env['NOTION_CLIENT_ID'][:12]}…)")

    return env

def start_server(env: dict):
    print("\n🚀 Starting Web Clipper v3.0 on http://localhost:5001")
    print("─" * 55)
    print("  Login page:  http://localhost:5001/login-page")
    print("  Auth status: http://localhost:5001/auth/status")
    print()
    print("Keep this terminal open while using the extension!")
    print("Press Ctrl+C to stop.")
    print("─" * 55)

    merged = {**os.environ, **env}
    subprocess.run([sys.executable, os.path.join(BASE, "server.py")], env=merged)

if __name__ == "__main__":
    print("=" * 55)
    print("Web Clipper v3.0 — Multi-User Setup")
    print("=" * 55)
    check_python()
    install_deps()
    env = setup_oauth()
    print("\n" + "=" * 55)
    print("✅ Setup complete! Starting server…")
    print("=" * 55)
    start_server(env)