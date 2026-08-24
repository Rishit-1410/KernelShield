
import json
import subprocess


def run_command(command):
    """Run a read-only system command safely."""

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10
        )

        return {
            "success": result.returncode == 0,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "return_code": result.returncode,
        }

    except Exception as error:
        return {
            "success": False,
            "stdout": "",
            "stderr": str(error),
            "return_code": -1,
        }


def get_systemd_services():
    """Collect currently running systemd services."""

    result = run_command([
        "systemctl",
        "list-units",
        "--type=service",
        "--state=running",
        "--no-pager",
        "--no-legend"
    ])

    services = []

    if not result["success"]:
        return services

    for line in result["stdout"].splitlines():

        parts = line.split(None, 4)

        if len(parts) >= 4:
            services.append({
                "unit": parts[0],
                "load": parts[1],
                "active": parts[2],
                "sub": parts[3],
                "description": parts[4] if len(parts) >= 5 else ""
            })

    return services


def get_listening_processes():
    """Collect processes associated with listening network sockets."""

    result = run_command([
        "ss",
        "-tulnp"
    ])

    if not result["success"]:
        return []

    return result["stdout"].splitlines()


def collect_services_info():

    services = get_systemd_services()
    listening = get_listening_processes()

    return {
        "running_service_count": len(services),
        "running_services": services,
        "listening_processes": listening
    }


if __name__ == "__main__":

    data = collect_services_info()

    print(json.dumps(data, indent=4))
