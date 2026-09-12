from pathlib import Path
import json
import subprocess


def run_command(command):
    """Run a read-only system command safely."""

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30
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


def get_suid_files():
    """Find files with the SUID permission bit."""

    result = run_command([
        "find",
        "/",
        "-xdev",
        "-type",
        "f",
        "-perm",
        "-4000",
        "-print"
    ])

    if not result["success"]:
        return []

    return [
        path
        for path in result["stdout"].splitlines()
        if path
    ]


def get_sgid_files():
    """Find files with the SGID permission bit."""

    result = run_command([
        "find",
        "/",
        "-xdev",
        "-type",
        "f",
        "-perm",
        "-2000",
        "-print"
    ])

    if not result["success"]:
        return []

    return [
        path
        for path in result["stdout"].splitlines()
        if path
    ]


def get_capabilities():
    """Find Linux file capabilities in common executable locations."""

    search_paths = [
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/lib",
        "/usr/libexec",
        "/lib",
        "/lib64",
        "/opt",
    ]

    existing_paths = [
        path
        for path in search_paths
        if Path(path).exists()
    ]

    try:
        result = subprocess.run(
            ["getcap", "-r", *existing_paths],
            capture_output=True,
            text=True,
            timeout=15
        )

        return [
            line
            for line in result.stdout.splitlines()
            if line
        ]

    except Exception:
        return []


def collect_filesystem_info():

    suid = get_suid_files()
    sgid = get_sgid_files()
    capabilities = get_capabilities()

    return {
        "suid": {
            "count": len(suid),
            "files": suid,
        },

        "sgid": {
            "count": len(sgid),
            "files": sgid,
        },

        "capabilities": {
            "count": len(capabilities),
            "entries": capabilities,
        },
    }


if __name__ == "__main__":

    data = collect_filesystem_info()

    print(json.dumps(data, indent=4))
