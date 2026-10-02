# pentrix-recon

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![No dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)](recon.py)

Passive subdomain enumeration from multiple free, keyless sources. It never sends a single packet to the target: everything comes from public certificate-transparency logs and passive DNS records.

## Features

- **100% passive** - queries CT logs and passive DNS APIs only; no DNS brute-forcing, no traffic to the target
- **Three keyless sources** - crt.sh, CertSpotter, hackertarget hostsearch
- **Resilient** - each source is wrapped in its own try/except with a timeout; if one is down, the others still run and you get a warning on stderr
- **Clean output** - deduplicated (case-insensitive), trailing dots stripped, wildcards resolved, sorted alphabetically, non-matching domains filtered out
- **Zero dependencies** - Python 3 standard library only (`urllib`, `json`, `argparse`). Nothing to install.
- **Pipe-friendly** - progress goes to stderr, results to stdout; use `-q` for results only

## Install

```bash
git clone https://github.com/mizazhaider-ceh/pentrix-recon.git
cd pentrix-recon
python3 recon.py --help
```

That is it. No `pip install`, no virtualenv, no API keys.

## Usage

Basic run (results print to stdout):

```bash
python3 recon.py hackerone.com
```

Save results to a file:

```bash
python3 recon.py hackerone.com -o subs.txt
```

Pick sources and raise the timeout:

```bash
python3 recon.py hackerone.com --sources crtsh,certspotter --timeout 20
```

Quiet mode (only subdomains on stdout, nothing else):

```bash
python3 recon.py hackerone.com -q > subs.txt
```

Show version:

```bash
python3 recon.py --version
```

### Real output

The command below was run against `hackerone.com` during testing (progress lines go to stderr, subdomain list to stdout):

```
$ python3 recon.py hackerone.com
[*] querying crt.sh certificate transparency ...
[+] crt.sh certificate transparency: 15 names
[*] querying CertSpotter certificate transparency ...
[+] CertSpotter certificate transparency: 4 names
[*] querying hackertarget hostsearch ...
[+] hackertarget hostsearch: 11 names
[*] 17 unique subdomains after dedupe
a.ns.hackerone.com
api.hackerone.com
b.ns.hackerone.com
design.hackerone.com
docs.hackerone.com
events.hackerone.com
go.hackerone.com
gslink.hackerone.com
hackerone.com
info.hackerone.com
links.hackerone.com
mta-sts.forwarding.hackerone.com
mta-sts.hackerone.com
mta-sts.managed.hackerone.com
support.hackerone.com
websockets.hackerone.com
www.hackerone.com
```

When a source is down, the tool keeps going and tells you:

```
$ python3 recon.py example.com
[*] querying crt.sh certificate transparency ...
[-] warning: crt.sh certificate transparency failed: HTTP Error 502: Bad Gateway
[*] querying CertSpotter certificate transparency ...
[+] CertSpotter certificate transparency: 8 names
[*] querying hackertarget hostsearch ...
[+] hackertarget hostsearch: 2 names
[*] 2 unique subdomains after dedupe
example.com
www.example.com
```

## Options

| Option | Default | Description |
|---|---|---|
| `domain` | (required) | Target domain, e.g. `example.com` |
| `-o`, `--output` | stdout | Write subdomains to a file (one per line) |
| `--timeout` | 15 | Per-source HTTP timeout in seconds |
| `--sources` | all three | Comma-separated: `crtsh,certspotter,hackertarget` |
| `-q`, `--quiet` | off | Print only subdomains (no progress messages) |
| `--version` | - | Print version and exit |

Exit codes: `0` on success, `1` when every source failed or the output file cannot be written, `2` on bad arguments.

## Data sources

| Source | URL | What it is |
|---|---|---|
| crt.sh | https://crt.sh/?q=%25.example.com&output=json | Certificate transparency search (Sectigo) |
| CertSpotter | https://api.certspotter.com/v1/issuances?domain=example.com&expand=dns_names | Certificate transparency API (SSLMate) |
| hackertarget | https://api.hackertarget.com/hostsearch/?q=example.com | Passive host lookup |

All three are free and need no API key. Rate limits are modest; do not hammer them. If a source starts failing consistently, check the `--timeout` flag first.

## Limitations

- This is passive enumeration only. It finds subdomains that have appeared in public certificates or passive DNS; it cannot discover subdomains that never appear in those datasets.
- crt.sh can be slow or return 502s under load; the tool warns and continues with the remaining sources.
- Results are only as fresh as the underlying logs.

## Ethical use

Only enumerate domains you own or are explicitly authorized to test (bug bounty scope, penetration test engagement, CTF). Passive or not, unauthorized reconnaissance against systems you do not have permission to assess is illegal in most jurisdictions.

## License

MIT - see [LICENSE](LICENSE).
