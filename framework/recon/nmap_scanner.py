import subprocess


def run_nmap(host, port):

    command = [
        "nmap",
        "-sV",
        "-p",
        str(port),
        host
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True
    )

    return result.stdout