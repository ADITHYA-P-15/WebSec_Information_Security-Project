from recon.nmap_scanner import run_nmap
from recon.nmap_parser import parse_nmap_output


output = run_nmap(
    "127.0.0.1",
    5001
)

assets = parse_nmap_output(output)

for asset in assets:
    print(asset)