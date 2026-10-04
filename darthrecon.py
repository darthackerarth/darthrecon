#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  DarthRecon v1.0 - Automated Recon Pipeline for IDOR & SQLi                  ║
║  For authorized bug bounty / pentest use only.                               ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import argparse
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# ---------------- COLORS ----------------
class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'
    B = '\033[94m'; M = '\033[95m'; Cy = '\033[96m'
    W = '\033[97m'; Bold = '\033[1m'; Dim = '\033[2m'
    X = '\033[0m'

BANNER = f"""{C.R}
    ██████╗  █████╗ ██████╗ ████████╗██╗  ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
    ██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
    ██║  ██║███████║██████╔╝   ██║   ███████║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
    ██║  ██║██╔══██║██╔══██╗   ██║   ██╔══██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
    ██████╔╝██║  ██║██║  ██║   ██║   ██║  ██║██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{C.X}
{C.Cy}  ┌──────────────────────────────────────────────────────────────────────────┐
  │{C.X}  {C.Y}DarthRecon{C.X} - Automated Recon Pipeline for {C.R}IDOR{C.X} & {C.R}SQLi{C.X}              {C.Cy}│
  │{C.X}  {C.Dim}v1.0 · For authorized bug bounty / pentest use only{C.X}                    {C.Cy}│
  └──────────────────────────────────────────────────────────────────────────┘{C.X}
     {C.R}"I find your lack of reconnaissance disturbing."{C.X}
"""

# ---------------- UTILS ----------------
def log(phase, msg, kind='info'):
    prefix = {
        'info':  f"{C.Cy}[*]{C.X}",
        'ok':    f"{C.G}[+]{C.X}",
        'warn':  f"{C.Y}[!]{C.X}",
        'err':   f"{C.R}[x]{C.X}",
        'phase': f"{C.M}[»]{C.X}",
    }.get(kind, f"{C.Cy}[*]{C.X}")
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{C.Dim}{ts}{C.X} {prefix} {C.Bold}{phase}{C.X} {msg}", flush=True)


def sh(cmd, out_file=None, timeout=None):
    """Executa comando shell. Se out_file informado, redireciona stdout."""
    try:
        if out_file:
            p = Path(out_file)
            p.parent.mkdir(parents=True, exist_ok=True)
            with open(p, 'w') as f:
                subprocess.run(cmd, shell=True, stdout=f,
                               stderr=subprocess.DEVNULL,
                               timeout=timeout)
            return True
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return r.stdout.strip()
    except subprocess.TimeoutExpired:
        return False if out_file else ""
    except Exception:
        return False if out_file else ""


def have(tool):
    return shutil.which(tool) is not None


def count_lines(path):
    try:
        with open(path, errors='ignore') as f:
            return sum(1 for _ in f)
    except Exception:
        return 0


def nonempty(path):
    return path and Path(path).exists() and count_lines(path) > 0


def first_col(src, dst):
    with open(src, errors='ignore') as fi, open(dst, 'w') as fo:
        for line in fi:
            parts = line.split()
            if parts:
                fo.write(parts[0] + "\n")


def check_tools():
    tools = {
        "subfinder":    "Subdomain enum",
        "assetfinder":  "Subdomain enum",
        "dnsx":         "DNS resolver",
        "httpx":        "HTTP prober",
        "gau":          "URL collector",
        "waybackurls":  "URL collector",
        "katana":       "Crawler",
        "nuclei":       "Vuln scanner",
        "gf":           "Pattern filter",
        "qsreplace":    "Payload injector",
        "sqlmap":       "SQLi exploit",
    }
    print(f"\n{C.Cy}  ┌── Tool check ────────────────────────────────────────────┐{C.X}")
    missing = []
    for t, desc in tools.items():
        status = f"{C.G}OK{C.X}" if have(t) else f"{C.R}MISSING{C.X}"
        print(f"  {C.Cy}│{C.X}  {t:<15} {C.Dim}{desc:<18}{C.X} [{status}] {C.Cy}│{C.X}")
        if not have(t):
            missing.append(t)
    print(f"{C.Cy}  └──────────────────────────────────────────────────────────┘{C.X}")
    if missing:
        log("SETUP", f"Missing: {', '.join(missing)} (tool will skip those phases)", 'warn')
    return missing


# ---------------- PHASES ----------------
def phase_subs(domains, out, skip):
    if skip:
        p = out / "subs" / "all.txt"
        return p if p.exists() else None
    log("PHASE 1", "Subdomain Enumeration", 'phase')
    t0 = time.time()
    subs = out / "subs"; subs.mkdir(parents=True, exist_ok=True)

    for d in domains:
        if have("subfinder"):
            sh(f"subfinder -d {d} -all -recursive -silent",
               subs / f"subfinder_{d}.txt", timeout=1800)
        if have("assetfinder"):
            sh(f"assetfinder --subs-only {d}",
               subs / f"assetfinder_{d}.txt", timeout=600)

    all_f = subs / "all.txt"
    sh(f"cat {subs}/*.txt 2>/dev/null | sort -u > {all_f}", timeout=120)
    with open(all_f, 'a') as f:
        for d in domains:
            f.write(d + "\n")
    sh(f"sort -u {all_f} -o {all_f}")
    log("PHASE 1", f"{count_lines(all_f)} unique subs ({time.time()-t0:.1f}s)", 'ok')
    return all_f


def phase_resolve(subs_file, out, skip):
    if skip:
        p = out / "subs" / "resolved.txt"
        return p if p.exists() else subs_file
    log("PHASE 2", "DNS Resolution", 'phase')
    t0 = time.time()
    r = out / "subs" / "resolved.txt"
    if have("dnsx"):
        sh(f"dnsx -l {subs_file} -silent -o {r}", timeout=1800)
    if not nonempty(r):
        log("PHASE 2", "dnsx empty/missing → using raw subs", 'warn')
        shutil.copy(subs_file, r)
    log("PHASE 2", f"{count_lines(r)} hosts resolved ({time.time()-t0:.1f}s)", 'ok')
    return r


def phase_probe(hosts_file, out, threads, skip):
    if skip:
        p = out / "hosts" / "urls.txt"
        return p if p.exists() else None
    log("PHASE 3", "HTTP Probing", 'phase')
    t0 = time.time()
    h = out / "hosts"; h.mkdir(parents=True, exist_ok=True)
    live = h / "live.txt"; urls = h / "urls.txt"
    if have("httpx"):
        sh(f"httpx -l {hosts_file} -ports 80,443,8080,8443,8000,8888,3000,5000 "
           f"-sc -title -tech-detect -silent -threads {threads} -o {live}",
           timeout=3600)
    if not nonempty(live):
        log("PHASE 3", "no live hosts", 'err'); return None
    first_col(live, urls)
    log("PHASE 3", f"{count_lines(urls)} live URLs ({time.time()-t0:.1f}s)", 'ok')
    return urls


def phase_urls(hosts_urls, out, skip):
    if skip:
        p = out / "urls" / "all.txt"
        return p if p.exists() else None
    log("PHASE 4", "URL Collection (gau / waybackurls / katana)", 'phase')
    t0 = time.time()
    u = out / "urls"; u.mkdir(parents=True, exist_ok=True)

    if have("gau"):
        sh(f"cat {hosts_urls} | gau --threads 20 --subs", u / "gau.txt", timeout=2400)
    if have("waybackurls"):
        sh(f"cat {hosts_urls} | waybackurls", u / "wayback.txt", timeout=2400)
    if have("katana"):
        sh(f"cat {hosts_urls} | katana -d 3 -jc -kf all -silent -c 20",
           u / "katana.txt", timeout=3600)

    all_f = u / "all.txt"
    sh(f"cat {u}/*.txt 2>/dev/null | sort -u > {all_f}", timeout=120)
    log("PHASE 4", f"{count_lines(all_f)} unique URLs ({time.time()-t0:.1f}s)", 'ok')
    return all_f


def phase_params(urls_file, out, skip):
    if skip:
        p = out / "params" / "clean.txt"
        return p if p.exists() else None
    log("PHASE 5", "Parameter Extraction", 'phase')
    t0 = time.time()
    p = out / "params"; p.mkdir(parents=True, exist_ok=True)
    clean = p / "clean.txt"
    names = p / "names.txt"
    priority = p / "sqli_priority.txt"

    sh(f"grep -E '\\?.*=' {urls_file} "
       f"| grep -vE '\\.(jpg|jpeg|png|gif|css|js|woff|woff2|ttf|svg|ico|pdf|mp4|webp)($|\\?)' "
       f"| sort -u > {clean}", timeout=120)
    sh(f"grep -oE '[?&][^=&]+=' {clean} | sed 's/[?&]//;s/=//' | sort -u > {names}", timeout=120)
    sh(f"grep -iE '^(id|cat|category|product|item|page|view|filter|search|q|query|"
       f"sort|order|column|table|report|type|field|select|where|from|user|login|email)$' "
       f"{names} > {priority}", timeout=60)

    log("PHASE 5", f"{count_lines(clean)} URLs with params ({time.time()-t0:.1f}s)", 'ok')
    return clean


def phase_idor(urls_file, out, skip):
    if skip:
        return out / "idor"
    log("PHASE 6", "IDOR Candidate Separation", 'phase')
    i = out / "idor"; i.mkdir(parents=True, exist_ok=True)

    sh(f"grep -E '(/|=)([0-9]{{1,10}})(/|$|&|\\?)' {urls_file} | sort -u > {i}/numeric_ids.txt", timeout=120)
    sh(f"grep -iE '[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}' "
       f"{urls_file} | sort -u > {i}/uuids.txt", timeout=120)
    sh(f"grep -iE '[0-9a-f]{{32}}|[0-9a-f]{{40}}|[0-9a-f]{{64}}' "
       f"{urls_file} | sort -u > {i}/hashes.txt", timeout=120)
    sh(f"grep -iE '(id|user|uid|account|order|invoice|doc|file|report|ticket|profile|"
       f"key|token|customer|member)=' {urls_file} | sort -u > {i}/classic_params.txt", timeout=120)

    log("PHASE 6",
        f"numeric={count_lines(i/'numeric_ids.txt')} "
        f"uuid={count_lines(i/'uuids.txt')} "
        f"classic={count_lines(i/'classic_params.txt')}", 'ok')
    return i


def phase_js(urls_file, hosts_urls, out, skip):
    if skip:
        return None
    log("PHASE 7", "JavaScript Analysis", 'phase')
    t0 = time.time()
    j = out / "js"; j.mkdir(parents=True, exist_ok=True)
    files = j / "files.txt"
    endpoints = j / "endpoints.txt"

    sh(f"grep -E '\\.js($|\\?)' {urls_file} | sort -u > {files}", timeout=120)

    # xnLinkFinder (opcional)
    if have("xnLinkFinder"):
        sh(f"xnLinkFinder -i {hosts_urls} -sp {hosts_urls} -o {j}/xn.txt", timeout=2400)

    # Extração simples de rotas a partir das URLs de JS
    sh(f"grep -oE '[/][a-zA-Z0-9_\\-/]{{3,}}' {files} | sort -u > {endpoints}", timeout=120)

    log("PHASE 7", f"{count_lines(files)} JS files ({time.time()-t0:.1f}s)", 'ok')
    return endpoints


def phase_nuclei(hosts_urls, out, skip):
    if skip:
        return None
    log("PHASE 8", "Nuclei Scan", 'phase')
    t0 = time.time()
    p = out / "patterns"; p.mkdir(parents=True, exist_ok=True)
    out_f = p / "nuclei.txt"
    if have("nuclei"):
        sh(f"nuclei -l {hosts_urls} -severity low,medium,high,critical -silent "
           f"-o {out_f}", timeout=7200)
    log("PHASE 8", f"{count_lines(out_f)} findings ({time.time()-t0:.1f}s)", 'ok')
    return out_f


def phase_sqli(clean_params, out, skip):
    if skip:
        return None
    log("PHASE 9", "SQLi Candidate Filtering", 'phase')
    s = out / "sqli"; s.mkdir(parents=True, exist_ok=True)
    cand = s / "candidates.txt"

    if have("gf"):
        sh(f"cat {clean_params} | gf sqli | sort -u > {cand}", timeout=180)
    if not nonempty(cand):
        shutil.copy(clean_params, cand)

    # wordlist de payloads prontos pra revisão manual
    payloads = s / "payloads.txt"
    with open(payloads, 'w') as f:
        f.write("\n".join([
            "'", "\"", "`", "')", "\"))", "'||'",
            "' AND 1=1-- -", "' AND 1=2-- -",
            "1' AND SLEEP(5)-- -", "1 OR 1=1-- -",
            "1' UNION SELECT NULL-- -", "1' UNION SELECT NULL,NULL-- -",
            "') OR ('1'='1", "';WAITFOR DELAY '0:0:5'--",
        ]))
    log("PHASE 9", f"{count_lines(cand)} SQLi candidates ready", 'ok')
    return cand


def phase_sqlmap_run(cand_file, out, threads):
    log("PHASE 9b", "SQLMap Execution (may take a while)", 'phase')
    if not have("sqlmap"):
        log("PHASE 9b", "sqlmap not installed, skipping", 'warn')
        return
    s = out / "sqli"
    logf = s / "results.log"
    results = s / "results"; results.mkdir(exist_ok=True)
    with open(cand_file) as f:
        urls = [l.strip() for l in f if l.strip()]
    log("PHASE 9b", f"Scanning {len(urls)} URLs with sqlmap...", 'info')
    for idx, url in enumerate(urls, 1):
        print(f"  {C.Dim}[{idx}/{len(urls)}]{C.X} {url[:100]}")
        sh(f"sqlmap -u '{url}' --batch --random-agent --level 3 --risk 2 "
           f"--technique=BEUSTQ --threads {threads} --timeout 15 --retries 2 "
           f"--output-dir={results}", out_file=None, timeout=900)
    log("PHASE 9b", f"done. check {results}", 'ok')


# ---------------- SUMMARY ----------------
def summary(out):
    print(f"\n{C.G}{C.Bold}  ════════════════ DARTHRECON COMPLETE ════════════════{C.X}\n")
    rows = [
        ("Subdomains",          out / "subs"   / "all.txt"),
        ("Resolved hosts",      out / "subs"   / "resolved.txt"),
        ("Live URLs",           out / "hosts"  / "urls.txt"),
        ("All collected URLs",  out / "urls"   / "all.txt"),
        ("URLs with params",    out / "params" / "clean.txt"),
        ("IDOR: numeric",       out / "idor"   / "numeric_ids.txt"),
        ("IDOR: UUIDs",         out / "idor"   / "uuids.txt"),
        ("IDOR: classic",       out / "idor"   / "classic_params.txt"),
        ("JS endpoints",        out / "js"     / "endpoints.txt"),
        ("Nuclei findings",     out / "patterns" / "nuclei.txt"),
        ("SQLi candidates",     out / "sqli"   / "candidates.txt"),
    ]
    print(f"  {C.Cy}┌──────────────────────────┬──────────┐{C.X}")
    print(f"  {C.Cy}│{C.X} {C.Bold}{'Artefato':<24}{C.X} {C.Cy}│{C.X} {C.Bold}{'Linhas':>8}{C.X} {C.Cy}│{C.X}")
    print(f"  {C.Cy}├──────────────────────────┼──────────┤{C.X}")
    for label, path in rows:
        n = count_lines(path)
        color = C.G if n > 0 else C.Dim
        print(f"  {C.Cy}│{C.X} {label:<24} {C.Cy}│{C.X} {color}{n:>8}{C.X} {C.Cy}│{C.X}")
    print(f"  {C.Cy}└──────────────────────────┴──────────┘{C.X}")
    print(f"\n  {C.Y}Output:{C.X} {out}\n")
    print(f"  {C.M}{C.Bold}Next steps:{C.X}")
    print(f"    {C.Dim}▸{C.X} Review {C.Cy}idor/classic_params.txt{C.X} manually (swap IDs, check auth)")
    print(f"    {C.Dim}▸{C.X} Run sqlmap/ghauri on {C.Cy}sqli/candidates.txt{C.X}")
    print(f"    {C.Dim}▸{C.X} Inspect {C.Cy}js/endpoints.txt{C.X} for hidden API routes")
    print(f"\n  {C.R}\"The Force is strong with those who recon properly.\"{C.X}\n")


# ---------------- MAIN ----------------
def parse_args():
    p = argparse.ArgumentParser(
        prog="darthrecon",
        description="DarthRecon - Automated Recon Pipeline for IDOR & SQLi",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  darthrecon -d scope.txt
  darthrecon -d scope.txt -o myout --threads 150
  darthrecon -d scope.txt --sqli-run
  darthrecon -d scope.txt --skip-js --skip-nuclei
        """
    )
    p.add_argument("-d", "--domains", required=True, help="File with domains (one per line)")
    p.add_argument("-o", "--output", default=None, help="Output directory")
    p.add_argument("-t", "--threads", type=int, default=100, help="Threads for httpx/nuclei")
    p.add_argument("--resume", action="store_true", help="Reuse existing output dir")
    p.add_argument("--skip-subs",    action="store_true")
    p.add_argument("--skip-resolve", action="store_true")
    p.add_argument("--skip-probe",   action="store_true")
    p.add_argument("--skip-urls",    action="store_true")
    p.add_argument("--skip-params",  action="store_true")
    p.add_argument("--skip-idor",    action="store_true")
    p.add_argument("--skip-js",      action="store_true")
    p.add_argument("--skip-nuclei",  action="store_true")
    p.add_argument("--skip-sqli",    action="store_true")
    p.add_argument("--sqli-run",     action="store_true", help="Actually run sqlmap on candidates")
    p.add_argument("--no-color",     action="store_true")
    return p.parse_args()


def main():
    args = parse_args()

    if args.no_color or not sys.stdout.isatty():
        for attr in ['R','G','Y','B','M','Cy','W','Bold','Dim','X']:
            setattr(C, attr, '')

    print(BANNER)
    t_start = time.time()

    # Load scope
    scope = Path(args.domains)
    if not scope.exists():
        log("ERROR", f"Scope file not found: {scope}", 'err'); sys.exit(1)
    domains = [l.strip() for l in scope.read_text().splitlines()
               if l.strip() and not l.startswith("#")]
    if not domains:
        log("ERROR", "Scope file is empty", 'err'); sys.exit(1)

    log("SCOPE", f"{len(domains)} domain(s): {', '.join(domains[:3])}"
        + (" ..." if len(domains) > 3 else ""), 'info')

    # Output dir
    if args.output:
        out = Path(args.output)
    else:
        out = Path(f"darthrecon_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    out.mkdir(parents=True, exist_ok=True)
    log("OUTPUT", str(out.resolve()), 'info')

    check_tools()

    try:
        subs_f  = phase_subs(domains, out, args.skip_subs)
        res_f   = phase_resolve(subs_f, out, args.skip_resolve) if subs_f else None
        urls_f  = phase_probe(res_f, out, args.threads, args.skip_probe) if res_f else None
        allurls = phase_urls(urls_f, out, args.skip_urls) if urls_f else None
        params  = phase_params(allurls, out, args.skip_params) if allurls else None
        if allurls:
            phase_idor(allurls, out, args.skip_idor)
        if allurls and urls_f:
            phase_js(allurls, urls_f, out, args.skip_js)
        if urls_f:
            phase_nuclei(urls_f, out, args.skip_nuclei)
        cand = phase_sqli(params, out, args.skip_sqli) if params else None
        if cand and args.sqli_run:
            phase_sqlmap_run(cand, out, min(args.threads, 10))
    except KeyboardInterrupt:
        print(f"\n{C.Y}[!] Interrupted by user. Partial results in {out}{C.X}\n")
        sys.exit(130)

    elapsed = time.time() - t_start
    log("DONE", f"Total time: {elapsed/60:.1f} min", 'ok')
    summary(out)


if __name__ == "__main__":
    main()
