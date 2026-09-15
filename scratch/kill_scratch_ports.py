"""Kill any process bound to scratch app ports (5001-5005) before starting fresh.

Usage:
    import kill_scratch_ports
    kill_scratch_ports.kill()          # kills all
    kill_scratch_ports.kill([5005])    # kills only port 5005
"""

import subprocess
import sys
import re

DEFAULT_PORTS = [5001, 5002, 5003, 5004, 5005]


def _find_pids_on_ports(ports):
    """Return set of PIDs bound to any of the given ports."""
    pids = set()
    try:
        result = subprocess.run(
            ["netstat", "-ano"],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.splitlines():
            for port in ports:
                pattern = rf":\s*{port}\s+"
                if re.search(pattern, line) and "LISTENING" in line:
                    parts = line.strip().split()
                    if parts:
                        try:
                            pid = int(parts[-1])
                            if pid > 0:
                                pids.add(pid)
                        except ValueError:
                            pass
    except Exception as e:
        print(f"[kill_scratch_ports] Warning: netstat failed: {e}", file=sys.stderr)
    return pids


def kill(ports=None):
    """Find and kill all processes on the given ports (default: 5001-5005)."""
    ports = ports or DEFAULT_PORTS
    pids = _find_pids_on_ports(ports)
    if not pids:
        print(f"[kill_scratch_ports] No processes found on ports {ports}")
        return

    print(f"[kill_scratch_ports] Found PIDs {pids} on ports {ports}, killing...")
    for pid in pids:
        try:
            subprocess.run(
                ["taskkill", "/F", "/PID", str(pid)],
                capture_output=True, text=True, timeout=10,
            )
            print(f"[kill_scratch_ports] Killed PID {pid}")
        except Exception as e:
            print(f"[kill_scratch_ports] Failed to kill PID {pid}: {e}", file=sys.stderr)

    # Brief pause for port release
    import time
    time.sleep(1)

    # Verify ports are free
    remaining = _find_pids_on_ports(ports)
    if remaining:
        print(f"[kill_scratch_ports] WARNING: PIDs {remaining} still on ports after kill", file=sys.stderr)
    else:
        print(f"[kill_scratch_ports] All ports {ports} are now free")


if __name__ == "__main__":
    kill()
