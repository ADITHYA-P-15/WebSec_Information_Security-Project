from recon.nmap_scanner import run_nmap


output = run_nmap(
    "127.0.0.1",
    5001
)

print(output)