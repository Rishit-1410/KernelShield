import json
import argparse

from backend.collectors.system import collect_system_info
from backend.collectors.kernel import collect_kernel_info
from backend.collectors.network import collect_network_info
from backend.collectors.services import collect_services_info
from backend.collectors.users import collect_users_info
from backend.collectors.filesystem import collect_filesystem_info
from backend.collectors.security import collect_security_info
from backend.collectors.containers import collect_container_info
from backend.collectors.processes import collect_processes
from backend.collectors.syscalls import collect_syscall_security

def run_scan(privileged=False):
    """
    Run all KernelShield collectors and combine
    their results into one scan object.
    """

    processes = collect_processes(privileged=privileged)

    scan = {
        "project": "KernelShield",
        "version": "0.1.0",

        "system": collect_system_info(),

        "kernel": collect_kernel_info(),

        "network": collect_network_info(privileged=privileged),

        "services": collect_services_info(),

        "users": collect_users_info(),

        "filesystem": collect_filesystem_info(),

        "security": collect_security_info(),

        "containers": collect_container_info(),

        "processes": {
            "process_count": len(processes),
            "processes": processes,
        },
        "syscalls": collect_syscall_security(),
    }

    return scan


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="KernelShield Linux Attack Surface Scanner"
    )

    parser.add_argument(
        "--privileged",
        action="store_true",
        help="Enable privileged process and socket attribution"
    )

    args = parser.parse_args()

    data = run_scan(
        privileged=args.privileged
    )

    print(json.dumps(data, indent=4))
