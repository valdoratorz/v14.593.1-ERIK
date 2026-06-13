import subprocess
import re
import os
import sys

PROTOCOL_DIR = "protocal"
CLIENT_DIR = os.path.join(PROTOCOL_DIR, "client")
SERVER_DIR = os.path.join(PROTOCOL_DIR, "server")

FRIDA_CMD = ["frida", "-U", "gadget", "-l", "v14dump.js"]

seen_packets = set()

def ensure_dirs():
    os.makedirs(CLIENT_DIR, exist_ok=True)
    os.makedirs(SERVER_DIR, exist_ok=True)

def generate_server_file(packet_id, hex_data):
    path = os.path.join(SERVER_DIR, f"{packet_id}.js")
    if os.path.exists(path):
        return
    content = f"""const PiranhaMessage = require('../../PiranhaMessage')

class _{packet_id} extends PiranhaMessage {{
  constructor (client) {{
    super()
    this.id = {packet_id}
    this.client = client
    this.version = 0
  }}

  async encode () {{
    this.writeHex('{hex_data}')
  }}
}}

module.exports = _{packet_id}
"""
    with open(path, "w") as f:
        f.write(content)
    print(f"[GEN] server/{packet_id}.js")

def generate_client_file(packet_id, hex_data):
    path = os.path.join(CLIENT_DIR, f"{packet_id}.js")
    if os.path.exists(path):
        return
    content = f"""const PiranhaMessage = require('../../PiranhaMessage')

class _{packet_id} extends PiranhaMessage {{
  constructor (bytes, client) {{
    super(bytes)
    this.client = client
    this.id = {packet_id}
    this.version = 0
  }}

  async decode () {{
    // TODO: {len(hex_data) // 2} bytes — hex: {hex_data[:48]}{'...' if len(hex_data) > 48 else ''}
  }}

  async process () {{
    // TODO
  }}
}}

module.exports = _{packet_id}
"""
    with open(path, "w") as f:
        f.write(content)
    print(f"[GEN] client/{packet_id}.js")

def parse_line(line, state):
    dump_match = re.search(r"Stream dump of (\d+) \(raw hex\):\s*([0-9a-fA-F]*)", line)
    if dump_match:
        state["current_id"] = int(dump_match.group(1))
        state["current_hex"] = dump_match.group(2).strip()
        return

    if state["current_id"] is not None and state["current_hex"] is not None:
        packet_id = state["current_id"]
        hex_data = state["current_hex"]

        if packet_id not in seen_packets:
            seen_packets.add(packet_id)
            if str(packet_id).startswith("2"):
                generate_server_file(packet_id, hex_data)
            elif str(packet_id).startswith("1"):
                generate_client_file(packet_id, hex_data)
            else:
                print(f"[UNKNOWN] packet {packet_id} — skipping")

        state["current_id"] = None
        state["current_hex"] = None

def run_frida():
    ensure_dirs()
    print(f"[*] Running: {' '.join(FRIDA_CMD)}")
    print(f"[*] Watching for packets... Ctrl+C to stop\n")

    state = {"current_id": None, "current_hex": None}

    try:
        proc = subprocess.Popen(
            FRIDA_CMD,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        for line in proc.stdout:
            line = line.rstrip()
            if line:
                print(f"[frida] {line}")
            parse_line(line, state)

    except KeyboardInterrupt:
        print(f"\n[*] Stopped. Generated {len(seen_packets)} unique packet files.")
        proc.terminate()
    except FileNotFoundError:
        print("[ERROR] frida not found. Install with: pip install frida-tools")
        sys.exit(1)

if __name__ == "__main__":
    run_frida()