from recon.nmap_scanner import run_nmap
from recon.nmap_parser import parse_nmap_output
from recon.save_assets import save_assets


output = run_nmap(
    "127.0.0.1",
    5001
)

assets = parse_nmap_output(output)

save_assets(
    assessment_id=1,
    host="127.0.0.1",
    assets=assets
)

print("Assets saved successfully.")