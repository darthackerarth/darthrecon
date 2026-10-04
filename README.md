# 🌑 DarthRecon

> "I find your lack of reconnaissance disturbing."

Automated reconnaissance pipeline focused on **IDOR** and **SQLi**, built for bug bounty hunters, pentesters, and red teamers who need to map an attack surface fast and prioritize what actually matters.

## Overview

DarthRecon is an automated recon pipeline that orchestrates the best tools in the industry — subfinder, httpx, gau, katana, nuclei, gf, sqlmap — into a single command with a clean, colorized workflow. Unlike generic recon tools that dump thousands of URLs and leave you to figure it out, DarthRecon is designed from the ground up to surface injectable parameters and predictable object references as first-class citizens. The philosophy is simple: recon is not about running more tools, it's about running the right tools, in the right order, and knowing where to look afterward.

## Features

### Focus on IDOR
Numeric IDs (/user/123, ?id=1), UUIDs v1/v4 (?uuid=..., /doc/xxxx-xxxx-...), MD5 and SHA hashes (opaque object references), and classic IDOR parameters (user_id, account, order, invoice, file, doc, ticket, profile).

### Focus on SQLi
Priority parameter names (id, search, q, filter, sort, where, select), gf sqli pattern matching, ready-to-use payloads file, and optional automatic sqlmap execution with safe defaults.

### Recon pipeline
Recursive subdomain enumeration, DNS resolution with dnsx, HTTP probing with tech detection, historical URL collection (Wayback, Common Crawl), active crawling with Katana, JavaScript endpoint extraction, and Nuclei vulnerability scan.

### Developer experience
One-command installer, colorized banner and phase-by-phase output, full flag system (--skip-*, --resume, --threads), zero Python dependencies (pure standard library), and a GitHub Actions CI workflow included.

## Pipeline

DarthRecon runs ten chained phases in a single command. Each phase feeds the next, and outputs are cleanly separated so you can review them in Burp, sqlmap, or nuclei.

| # | Phase | Tools | Output |
|---|-------|-------|--------|
| 1 | Subdomain Enumeration | subfinder, assetfinder | subs/all.txt |
| 2 | DNS Resolution | dnsx | subs/resolved.txt |
| 3 | HTTP Probing | httpx | hosts/live.txt, hosts/urls.txt |
| 4 | URL Collection | gau, waybackurls, katana | urls/all.txt |
| 5 | Parameter Extraction | grep, sort | params/clean.txt, params/sqli_priority.txt |
| 6 | IDOR Separation | grep, regex | idor/numeric_ids.txt, idor/uuids.txt, idor/hashes.txt, idor/classic_params.txt |
| 7 | JS Analysis | xnLinkFinder, grep | js/files.txt, js/endpoints.txt |
| 8 | Nuclei Scan | nuclei | patterns/nuclei.txt |
| 9 | SQLi Filtering | gf sqli | sqli/candidates.txt, sqli/payloads.txt |
| 10 | SQLMap (optional) | sqlmap | sqli/results/ |

## Installation

One-liner recommended:

git clone https://github.com/darthackerarth/darthrecon.git && cd darthrecon && ./install.sh

The installer handles everything: system packages, Go tools, gf patterns, nuclei templates, and installs the darthrecon binary globally.

Manual installation:

git clone https://github.com/darthackerarth/darthrecon.git
cd darthrecon
sudo apt update
sudo apt install -y python3 python3-pip golang-go git curl jq sqlmap
echo 'export GOPATH=$HOME/go' >> ~/.zshrc
echo 'export PATH=$PATH:$HOME/go/bin:/usr/local/go/bin' >> ~/.zshrc
source ~/.zshrc
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/lc/gau/v2/cmd/gau@latest
mkdir -p ~/.gf
git clone https://github.com/1ndianl33t/Gf-Patterns /tmp/gf-patterns
cp /tmp/gf-patterns/*.json ~/.gf/
nuclei -update-templates
chmod +x darthrecon.py
sudo cp darthrecon.py /usr/local/bin/darthrecon
sudo chmod +x /usr/local/bin/darthrecon

Requirements: Python 3.8+, Go 1.20+, Kali Linux / Parrot OS / Debian, sqlmap (optional, only for --sqli-run).

## Usage

echo "example.com" > scope.txt
darthrecon -d scope.txt
darthrecon -d scope.txt -o target_run --threads 150
darthrecon -d scope.txt --sqli-run
darthrecon -d scope.txt -o darthrecon_20260101_120000 --resume
darthrecon -d scope.txt --skip-js --skip-nuclei
darthrecon -h

Flags reference:

-d, --domains FILE — Required. Scope file, one domain per line (# for comments)
-o, --output DIR — Output directory (default: darthrecon_<timestamp>)
--resume — Reuse existing output directory (skip already-done files)
-t, --threads N — Threads for httpx / nuclei (default: 100)
--skip-subs — Skip subdomain enumeration
--skip-resolve — Skip DNS resolution
--skip-probe — Skip HTTP probing
--skip-urls — Skip URL collection
--skip-params — Skip parameter extraction
--skip-idor — Skip IDOR candidate separation
--skip-js — Skip JavaScript analysis
--skip-nuclei — Skip nuclei scan
--skip-sqli — Skip SQLi candidate filtering
--sqli-run — Execute sqlmap automatically against SQLi candidates (slow)
--no-color — Disable colored output
-h, --help — Show help and exit

## Output Structure

darthrecon_YYYYMMDD_HHMMSS/
├── subs/
│   ├── subfinder_<domain>.txt
│   ├── assetfinder_<domain>.txt
│   ├── all.txt
│   └── resolved.txt
├── hosts/
│   ├── live.txt
│   └── urls.txt
├── urls/
│   ├── gau.txt
│   ├── wayback.txt
│   ├── katana.txt
│   └── all.txt
├── params/
│   ├── clean.txt
│   ├── names.txt
│   └── sqli_priority.txt
├── idor/
│   ├── numeric_ids.txt
│   ├── uuids.txt
│   ├── hashes.txt
│   └── classic_params.txt
├── js/
│   ├── files.txt
│   ├── endpoints.txt
│   └── xn.txt
├── patterns/
│   └── nuclei.txt
└── sqli/
    ├── candidates.txt
    ├── payloads.txt
    └── results/

## Post-Recon Workflow

Test IDOR candidates: run cat darthrecon_*/idor/classic_params.txt | head -20 and open the URLs in Burp Suite. Swap the ID and compare responses. A 200 response with another user's data means IDOR confirmed. A 403 or 401 means protected. A 200 with the same data means not vulnerable.

Test SQLi candidates manually: run cat darthrecon_*/sqli/candidates.txt | head -10 and then sqlmap -u "https://target.com/api?id=1" --batch --level 3 --risk 2.

Bulk test with sqlmap: darthrecon -d scope.txt --sqli-run --resume -o darthrecon_XXXX.

Look for hidden endpoints in JavaScript: grep -iE "(internal|admin|v1|api|debug|graphql)" darthrecon_*/js/endpoints.txt.

## FAQ

Do I need all the tools installed to run DarthRecon? No. DarthRecon checks for each tool at startup. Missing tools just cause their phases to be skipped, and you will see a [!] MISSING warning in the tool check table.

Is --sqli-run safe to use on production targets? No. --sqli-run executes active SQL injection payloads against target URLs. Only use it on systems you own, authorized bug bounty in-scope targets, or explicitly permitted pentest engagements. For everything else, use DarthRecon up to phase 9 and test manually.

Can I resume a run that was interrupted? Yes. Use --resume -o <existing_dir> and DarthRecon will skip phases whose output already exists.

Why is xnLinkFinder optional? It is not always installed on every system, and its install path varies (pipx, pip, git clone). If it is not present, DarthRecon falls back to a simple regex extraction of JS endpoints.

Does it work on macOS or Windows? Officially tested on Kali Linux, Parrot OS, and Debian. On macOS, most Go tools work but the installer targets apt, so you will need to install tools manually. On Windows, use WSL2 with a Debian-based distro.

Can I contribute? Yes, see CONTRIBUTING.md. PRs, issues, ideas, and stars are all welcome.

## Roadmap

- [x] v1.0 — Initial release with IDOR + SQLi focus
- [ ] v1.1 — Docker image and docker-compose.yml
- [ ] v1.2 — HTML reporting (Jinja2 template)
- [ ] v1.3 — Discord / Telegram notifications for findings
- [ ] v1.4 — Burp Suite extension integration
- [ ] v1.5 — Multi-threaded per-domain execution
- [ ] v2.0 — Interactive TUI mode

## Disclaimer

This tool is provided for authorized security testing only. Using DarthRecon against systems you do not own or lack explicit written permission to test is illegal in most jurisdictions. The author assumes no liability for misuse, damage, or legal consequences. You are solely responsible for your actions. Always read and respect the scope of any bug bounty program or pentest engagement.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Author

darthackerarth — https://github.com/darthackerarth

The Force is strong with those who recon properly. Use your powers responsibly.
