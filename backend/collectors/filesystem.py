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
    """Find files with Linux capabilities."""

    result = subprocess.run(
        ["getcap", "-r", "/"],
        capture_output=True,
        text=True,
        timeout=60
    )

    return [
        line
        for line in result.stdout.splitlines()
        if line
    ]


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
