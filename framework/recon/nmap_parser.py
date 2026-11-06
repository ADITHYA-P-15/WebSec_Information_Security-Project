import re


def parse_nmap_output(output):

    assets = []

    lines = output.splitlines()

    for line in lines:

        match = re.match(
            r"(\d+)/(\w+)\s+(\w+)\s+(\S+)\s+(.*)",
            line
        )

        if match:

            port = int(match.group(1))
            protocol = match.group(2)
            state = match.group(3)
            service = match.group(4)
            version = match.group(5)

            assets.append({
                "port": port,
                "protocol": protocol,
                "state": state,
                "service": service,
                "version": version
            })

    return assets