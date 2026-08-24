import os
import re


SOCKET_PATTERN = re.compile(r"socket:\[(\d+)\]")


def get_socket_inode_map():
    """
    Build a mapping:

        socket inode -> process information
    """

    socket_map = {}

    for pid in os.listdir("/proc"):

        if not pid.isdigit():
            continue

        process_dir = f"/proc/{pid}"

        try:
            process_name = open(
                f"{process_dir}/comm"
            ).read().strip()

            status = open(
                f"{process_dir}/status"
            ).read()

            uid = None

            for line in status.splitlines():

                if line.startswith("Uid:"):

                    parts = line.split()

                    if len(parts) >= 2:
                        uid = int(parts[1])

                    break

            fd_dir = f"{process_dir}/fd"

            for fd in os.listdir(fd_dir):

                fd_path = os.path.join(fd_dir, fd)

                try:
                    target = os.readlink(fd_path)

                except (PermissionError, FileNotFoundError, OSError):
                    continue

                match = SOCKET_PATTERN.match(target)

                if not match:
                    continue

                inode = match.group(1)

                socket_map[inode] = {
                    "pid": int(pid),
                    "process": process_name,
                    "uid": uid,
                    "fd": int(fd),
                }

        except (PermissionError, FileNotFoundError, OSError):
            continue

    return socket_map
def get_tcp_socket_inodes():
    """
    Read Linux TCP socket tables and return
    local-port -> socket inode information.
    """

    results = []

    for table in ["/proc/net/tcp", "/proc/net/tcp6"]:

        try:
            with open(table, "r") as file:
                lines = file.readlines()[1:]

        except (PermissionError, FileNotFoundError, OSError):
            continue

        for line in lines:

            parts = line.split()

            if len(parts) < 10:
                continue

            local_address = parts[1]
            state = parts[3]
            inode = parts[9]

            try:
                address_hex, port_hex = local_address.split(":")
                port = int(port_hex, 16)
            except ValueError:
                continue

            # 0A = TCP LISTEN
            if state != "0A":
                continue

            results.append({
                "table": table,
                "port": port,
                "inode": inode,
            })

    return results
