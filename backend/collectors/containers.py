import json
import os
import subprocess


def run_command(command):
    """Run a read-only system command safely."""

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=15
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


def check_docker():

    result = run_command(["docker", "version", "--format", "{{.Server.Version}}"])

    return {
        "installed": result["return_code"] != 127,
        "daemon_accessible": result["success"],
        "version": result["stdout"],
    }


def get_containers():

    result = run_command([
        "docker",
        "ps",
        "-a",
        "--format",
        "{{json .}}"
    ])

    if not result["success"]:
        return []

    containers = []

    for line in result["stdout"].splitlines():

        try:
            containers.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return containers


def get_docker_socket():

    socket_path = "/var/run/docker.sock"

    return {
        "exists": os.path.exists(socket_path),
        "permissions": (
            oct(os.stat(socket_path).st_mode & 0o777)
            if os.path.exists(socket_path)
            else None
        )
    }


def collect_container_info():

    docker = check_docker()
    containers = get_containers()

    return {
        "docker": docker,

        "socket": get_docker_socket(),

        "container_count": len(containers),

        "containers": containers,
    }


if __name__ == "__main__":

    data = collect_container_info()

    print(json.dumps(data, indent=4))
