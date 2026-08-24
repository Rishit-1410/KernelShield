import json
import os


def read_seccomp_status(pid):
    """
    Read the Seccomp mode of a Linux process.

    Seccomp values:
        0 = disabled
        1 = strict mode
        2 = filter mode
    """

    try:
        with open(f"/proc/{pid}/status", "r") as file:
            for line in file:
                if line.startswith("Seccomp:"):
                    return int(line.split()[1])

    except (PermissionError, FileNotFoundError, ValueError, OSError):
        return None

    return None


def is_kernel_thread(pid):
    """
    Determine whether a process is a kernel thread.

    Kernel threads have an empty /proc/<pid>/exe link
    represented as a FileNotFoundError when read through
    /proc.
    """

    try:
        os.readlink(f"/proc/{pid}/exe")
        return False

    except FileNotFoundError:
        return True

    except (PermissionError, OSError):
        return False


def collect_syscall_security():
    """
    Collect system-call security posture using process Seccomp status.
    """

    processes = []

    seccomp_counts = {
        "disabled": 0,
        "strict": 0,
        "filter": 0,
        "unknown": 0,
    }

    userspace_counts = {
        "disabled": 0,
        "strict": 0,
        "filter": 0,
        "unknown": 0,
    }

    kernel_thread_count = 0

    for entry in os.listdir("/proc"):

        if not entry.isdigit():
            continue

        pid = entry

        try:
            with open(f"/proc/{pid}/comm", "r") as file:
                name = file.read().strip()

        except (PermissionError, FileNotFoundError, OSError):
            continue

        if not name:
            continue

        seccomp = read_seccomp_status(pid)

        if seccomp == 0:
            mode = "disabled"
            seccomp_counts["disabled"] += 1

        elif seccomp == 1:
            mode = "strict"
            seccomp_counts["strict"] += 1

        elif seccomp == 2:
            mode = "filter"
            seccomp_counts["filter"] += 1

        else:
            mode = "unknown"
            seccomp_counts["unknown"] += 1

        kernel_thread = is_kernel_thread(pid)

        if kernel_thread:
            kernel_thread_count += 1
        else:
            userspace_counts[mode] += 1

        processes.append({
            "pid": int(pid),
            "name": name,
            "seccomp": seccomp,
            "seccomp_mode": mode,
            "kernel_thread": kernel_thread,
        })

    return {
        "process_count": len(processes),

        "kernel_thread_count": kernel_thread_count,

        "userspace_process_count": (
            len(processes) - kernel_thread_count
        ),

        "seccomp_summary": seccomp_counts,

        "userspace_seccomp_summary": userspace_counts,

        "processes": processes,
    }


if __name__ == "__main__":

    data = collect_syscall_security()

    print(
        json.dumps(
            data,
            indent=4
        )
    )
