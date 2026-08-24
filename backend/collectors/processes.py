import json
import os
import subprocess


def read_file(path):
    try:
        with open(path, "r") as file:
            return file.read().strip()
    except (PermissionError, FileNotFoundError):
        return None


def get_executable(pid, privileged=False):
    """Get the executable path for a process."""

    path = f"/proc/{pid}/exe"

    try:
        return os.readlink(path)

    except (PermissionError, FileNotFoundError, OSError):

        if not privileged:
            return None

        try:
            result = subprocess.run(
                ["sudo", "-n", "readlink", path],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )

            if result.returncode == 0:
                return result.stdout.strip() or None

        except (subprocess.TimeoutExpired, OSError):
            pass

        return None

def get_command_line(pid):
    """Get the process command line."""

    try:
        with open(f"/proc/{pid}/cmdline", "rb") as file:
            data = file.read()

        return data.replace(
            b"\x00",
            b" "
        ).decode(
            "utf-8",
            errors="replace"
        ).strip()

    except (PermissionError, FileNotFoundError, OSError):
        return None


def collect_processes(privileged=False):
    """
    Collect basic process metadata from /proc.
    """

    processes = []

    for entry in os.listdir("/proc"):

        if not entry.isdigit():
            continue

        pid = entry

        name = read_file(
            f"/proc/{pid}/comm"
        )

        status = read_file(
            f"/proc/{pid}/status"
        )

        if not name:
            continue

        uid = None

        if status:

            for line in status.splitlines():

                if line.startswith("Uid:"):

                    parts = line.split()

                    if len(parts) >= 2:
                        uid = int(parts[1])

                    break

        processes.append({
            "pid": int(pid),
            "name": name,
            "uid": uid,
            "executable": get_executable(
                pid,
                privileged=privileged
            ),
            "command_line": get_command_line(pid),
        })

    return processes


if __name__ == "__main__":

    data = collect_processes(
        privileged=True
    )

    print(
        json.dumps(
            {
                "process_count": len(data),
                "processes": data,
            },
            indent=4
        )
    )
