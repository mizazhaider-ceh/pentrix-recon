#!/usr/bin/env python3
"""pentrix-recon: passive subdomain enumeration from multiple keyless sources.

Queries certificate-transparency logs and a passive DNS service to discover
subdomains without sending any traffic to the target itself. All sources are
free and require no API key.

Sources:
  - crt.sh (https://crt.sh)          : certificate transparency JSON API
  - certspotter (https://certspotter.com) : certificate transparency API
  - hackertarget hostsearch (https://hackertarget.com) : passive host lookup

Example:
    python3 recon.py example.com
    python3 recon.py example.com -o subs.txt
    python3 recon.py example.com --sources crtsh,certspotter --timeout 20
"""

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

VERSION = "1.0.0"
USER_AGENT = "pentrix-recon/1.0.0 (passive subdomain enumeration)"

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def fetch_json(url, timeout):
    """GET a URL and return the parsed JSON body.

    Raises URLError / HTTPError on failure, ValueError on bad JSON.
    """
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise urllib.error.HTTPError(url, resp.status, "unexpected status", resp.headers, None)
        charset = resp.headers.get_content_charset() or "utf-8"
        return json.loads(resp.read().decode(charset, errors="replace"))


def fetch_text(url, timeout):
    """GET a URL and return the raw text body. Raises URLError / HTTPError."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise urllib.error.HTTPError(url, resp.status, "unexpected status", resp.headers, None)
        charset = resp.headers.get_content_charset() or "utf-8"
        return resp.read().decode(charset, errors="replace")


def warn(msg):
    """Print a warning to stderr (used when one source fails)."""
    print("[-] warning: %s" % msg, file=sys.stderr)


# ---------------------------------------------------------------------------
# sources
# ---------------------------------------------------------------------------

def source_crtsh(domain, timeout):
    """Enumerate via crt.sh certificate transparency search.

    Returns a set of subdomains (wildcards stripped).
    """
    q = urllib.parse.quote("%%.%s" % domain, safe="")
    url = "https://crt.sh/?q=%s&output=json" % q
    found = set()
    for entry in fetch_json(url, timeout):
        # name_value may contain several names separated by newlines
        names = entry.get("name_value", "") or ""
        for name in names.splitlines():
            name = name.strip().lower()
            # skip wildcards like *.example.com (they enumerate nothing new)
            if name.startswith("*."):
                name = name[2:]
            if name:
                found.add(name)
    return found


def source_certspotter(domain, timeout):
    """Enumerate via the CertSpotter v1 issuances API.

    Returns a set of subdomains.
    """
    q = urllib.parse.quote(domain, safe="")
    url = "https://api.certspotter.com/v1/issuances?domain=%s&expand=dns_names" % q
    found = set()
    for issuance in fetch_json(url, timeout):
        for name in issuance.get("dns_names", []) or []:
            name = name.strip().lower()
            if name.startswith("*."):
                name = name[2:]
            if name:
                found.add(name)
    return found


def source_hackertarget(domain, timeout):
    """Enumerate via the hackertarget hostsearch API.

    Returns a set of hostnames (format: host,ip per line).
    """
    q = urllib.parse.quote(domain, safe="")
    url = "https://api.hackertarget.com/hostsearch/?q=%s" % q
    found = set()
    body = fetch_text(url, timeout).strip()
    if "error" in body.lower():
        raise ValueError("hackertarget returned an error: %s" % body[:120])
    for line in body.splitlines():
        line = line.strip()
        if not line or "," not in line:
            continue
        host = line.split(",", 1)[0].strip().lower()
        if host:
            found.add(host)
    return found


SOURCES = {
    "crtsh": ("crt.sh certificate transparency", source_crtsh),
    "certspotter": ("CertSpotter certificate transparency", source_certspotter),
    "hackertarget": ("hackertarget hostsearch", source_hackertarget),
}


def normalize(subs, domain):
    """Dedupe (case-insensitive), strip trailing dots, keep only subdomains."""
    domain = domain.lower()
    clean = set()
    for s in subs:
        s = s.strip().rstrip(".").lower()
        if not s:
            continue
        # keep the domain itself and its subdomains, drop noise from other domains
        if s == domain or s.endswith("." + domain):
            clean.add(s)
    return sorted(clean)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="recon.py",
        description="pentrix-recon: passive subdomain enumeration from multiple "
                    "keyless sources (crt.sh, CertSpotter, hackertarget). "
                    "Sends no traffic to the target; all data comes from "
                    "public certificate-transparency logs and passive DNS.",
        epilog="Examples:\n"
               "  python3 recon.py example.com\n"
               "  python3 recon.py example.com -o subs.txt\n"
               "  python3 recon.py example.com --sources crtsh,certspotter\n"
               "  python3 recon.py example.com --timeout 20 --quiet",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("domain", help="domain to enumerate, e.g. example.com")
    p.add_argument("-o", "--output",
                   help="write subdomains to this file (one per line)")
    p.add_argument("--timeout", type=float, default=15, metavar="SECONDS",
                   help="per-source HTTP timeout in seconds (default: 15)")
    p.add_argument("--sources", default=",".join(SOURCES),
                   help="comma-separated sources to query: %s (default: all)"
                   % ",".join(SOURCES))
    p.add_argument("-q", "--quiet", action="store_true",
                   help="print only subdomains (no progress messages)")
    p.add_argument("--version", action="version",
                   version="pentrix-recon %s" % VERSION)
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    domain = args.domain.strip().lower().rstrip(".")
    if not domain or "." not in domain:
        print("[-] error: '%s' does not look like a valid domain" % args.domain,
              file=sys.stderr)
        return 2

    wanted = [s.strip() for s in args.sources.split(",") if s.strip()]
    bad = [s for s in wanted if s not in SOURCES]
    if bad:
        print("[-] error: unknown source(s): %s (choose from: %s)"
              % (", ".join(bad), ", ".join(SOURCES)), file=sys.stderr)
        return 2

    if args.timeout <= 0:
        print("[-] error: --timeout must be positive", file=sys.stderr)
        return 2

    all_subs = set()
    ok_sources = 0
    for key in wanted:
        label, func = SOURCES[key]
        if not args.quiet:
            print("[*] querying %s ..." % label, file=sys.stderr)
        try:
            got = func(domain, args.timeout)
        except Exception as e:  # noqa: BLE001 - one source must not kill the run
            warn("%s failed: %s" % (label, e))
            continue
        if not args.quiet:
            print("[+] %s: %d names" % (label, len(got)), file=sys.stderr)
        all_subs |= got
        ok_sources += 1

    if ok_sources == 0:
        print("[-] error: every source failed; nothing to report", file=sys.stderr)
        return 1

    results = normalize(all_subs, domain)
    if not args.quiet:
        print("[*] %d unique subdomains after dedupe" % len(results),
              file=sys.stderr)

    lines = "\n".join(results)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(lines + ("\n" if lines else ""))
        except OSError as e:
            print("[-] error: cannot write %s: %s" % (args.output, e),
                  file=sys.stderr)
            return 1
        if not args.quiet:
            print("[*] wrote %d subdomains to %s" % (len(results), args.output),
                  file=sys.stderr)
    else:
        print(lines)

    return 0


if __name__ == "__main__":
    sys.exit(main())
