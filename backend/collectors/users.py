import json
import pwd
import grp
import os
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


def get_users():
    """Collect local user accounts."""

    users = []

    for entry in pwd.getpwall():
        users.append({
            "username": entry.pw_name,
            "uid": entry.pw_uid,
            "gid": entry.pw_gid,
            "home": entry.pw_dir,
            "shell": entry.pw_shell,
        })

    return users


def get_root_accounts(users):
    """Find accounts with UID 0."""

    return [
        user
        for user in users
        if user["uid"] == 0
    ]


def get_current_user():
    """Collect current process identity."""

    return {
        "username": os.getenv("USER") or os.getenv("USERNAME"),
        "uid": os.getuid(),
        "gid": os.getgid(),
    }


def get_groups():
    """Collect local groups."""

    groups = []

    for entry in grp.getgrall():
        groups.append({
            "name": entry.gr_name,
            "gid": entry.gr_gid,
            "members": entry.gr_mem,
        })

    return groups


def get_sudo_configuration():
    """Check whether sudo is available and show sudo privileges."""

    result = run_command(["sudo", "-n", "-l"])

    return {
        "available": result["return_code"] != 127,
        "output": result["stdout"],
        "error": result["stderr"],
    }


def collect_users_info():

    users = get_users()

    return {
        "current_user": get_current_user(),

        "user_count": len(users),

        "users": users,

        "root_accounts": get_root_accounts(users),

        "groups": get_groups(),

        "sudo": get_sudo_configuration(),
    }


if __name__ == "__main__":

    data = collect_users_info()

    print(json.dumps(data, indent=4))
