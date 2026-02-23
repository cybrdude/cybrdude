#!/usr/bin/env python3
"""
Censys Global Threat Ops Center — SVG Generator
Pulls real-time internet scanning data from the Censys Search API
and renders a dark-themed SVG operations dashboard for GitHub profile README.

Requires: CENSYS_API_ID and CENSYS_API_SECRET as environment variables.
Research Tier: (Impact - Minial) this action uses ~6 queries per run.
"""

import json
import os
import sys
import urllib.request
import urllib.error
import base64
from datetime import datetime, timezone

CENSYS_API_ID = os.environ.get("CENSYS_API_ID", "")
CENSYS_API_SECRET = os.environ.get("CENSYS_API_SECRET", "")
AGGREGATE_URL = "https://search.censys.io/api/v2/hosts/aggregate"

def censys_aggregate(query: str, field: str, num_buckets: int = 10) -> dict:
    """Call the Censys v2 hosts aggregate endpoint."""
    payload = json.dumps({
        "query": query,
        "field": field,
        "num_buckets": num_buckets,
    }).encode()
    creds = base64.b64encode(f"{CENSYS_API_ID}:{CENSYS_API_SECRET}".encode()).decode()
    req = urllib.request.Request(
        AGGREGATE_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Basic {creds}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        print(f"[!] Censys API error {e.code}: {e.read().decode()}", file=sys.stderr)
        return {}
    except Exception as e:
        print(f"[!] Request failed: {e}", file=sys.stderr)
        return {}

def get_total_hosts(query: str) -> int:
    """Get total host count for a query via aggregate."""
    result = censys_aggregate(query, "location.country_code", 1)
    return result.get("result", {}).get("total", 0)

def format_count(n: int) -> str:
    """Format large numbers: 1234567 -> 1.23M"""
    if n >= 1_000_000_000:
        return f"{n / 1_000_000_000:.2f}B"
    if n >= 1_000_000:
        return f"{n / 1_000_000:.2f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}K"
    return str(n)

def fetch_metrics() -> dict:
    """Fetch all metrics from Censys."""
    print("[*] Fetching global host metrics from Censys...")

    # Total observable hosts
    total = get_total_hosts("services.service_name: *")

    # Regional breakdown by continent
    region_result = censys_aggregate("services.service_name: *", "location.continent", 10)
    region_buckets = {b["key"]: b["count"] for b in region_result.get("result", {}).get("buckets", [])}

    na_count = region_buckets.get("North America", 0)
    eu_count = region_buckets.get("Europe", 0)
    ap_count = region_buckets.get("Asia", 0)

    # Top exposed services
    svc_result = censys_aggregate("services.service_name: *", "services.service_name", 5)
    top_services = [(b["key"], b["count"]) for b in svc_result.get("result", {}).get("buckets", [])]

    # Exposed critical services (potential attack surface)
    rdp_count = get_total_hosts("services.service_name: RDP")
    smb_count = get_total_hosts("services.service_name: SMB")
    telnet_count = get_total_hosts("services.service_name: TELNET")

    now = datetime.now(timezone.utc)

    return {
        "total_hosts": total,
        "na_hosts": na_count,
        "eu_hosts": eu_count,
        "ap_hosts": ap_count,
        "top_services": top_services,
        "rdp_exposed": rdp_count,
        "smb_exposed": smb_count,
        "telnet_exposed": telnet_count,
        "timestamp": now.strftime("%Y-%m-%d %H:%M UTC"),
        "date_short": now.strftime("%d %b %Y"),
    }

def make_bar(fraction: float, width: int = 180) -> str:
    """Create an SVG rect bar."""
    filled = max(4, int(fraction * width))
    return (
        f'<rect x="0" y="0" width="{width}" height="10" rx="2" fill="#1a1a2e" stroke="#2a2a4a" stroke-width="0.5"/>'
        f'<rect x="0" y="0" width="{filled}" height="10" rx="2" fill="url(#barGrad)"/>'
    )

def generate_svg(m: dict) -> str:
    """Generate the dark-themed ops center SVG."""
    total_fmt = format_count(m["total_hosts"])
    na_fmt = format_count(m["na_hosts"])
    eu_fmt = format_count(m["eu_hosts"])
    ap_fmt = format_count(m["ap_hosts"])

    # Fractions for bars (relative to total)
    na_frac = m["na_hosts"] / max(m["total_hosts"], 1)
    eu_frac = m["eu_hosts"] / max(m["total_hosts"], 1)
    ap_frac = m["ap_hosts"] / max(m["total_hosts"], 1)

    # Top services formatted
    svc_lines = ""
    for i, (name, count) in enumerate(m["top_services"][:5]):
        y = 284 + i * 18
        svc_lines += f'<text x="40" y="{y}" class="mono dim">▸ {name:<12s}</text>'
        svc_lines += f'<text x="220" y="{y}" class="mono accent">{format_count(count)}</text>'

    rdp_fmt = format_count(m["rdp_exposed"])
    smb_fmt = format_count(m["smb_exposed"])
    telnet_fmt = format_count(m["telnet_exposed"])

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="820" height="520" viewBox="0 0 820 520">
  <defs>
    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#0a0a1a"/>
      <stop offset="50%" style="stop-color:#0d0d24"/>
      <stop offset="100%" style="stop-color:#0a0a1a"/>
    </linearGradient>
    <linearGradient id="barGrad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:#e63946"/>
      <stop offset="100%" style="stop-color:#ff6b35"/>
    </linearGradient>
    <linearGradient id="borderGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#e63946;stop-opacity:0.6"/>
      <stop offset="50%" style="stop-color:#ff6b35;stop-opacity:0.3"/>
      <stop offset="100%" style="stop-color:#e63946;stop-opacity:0.6"/>
    </linearGradient>
    <filter id="glow">
      <feGaussianBlur stdDeviation="2" result="coloredBlur"/>
      <feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
    <style>
      .mono {{ font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', 'SF Mono', monospace; }}
      .title {{ font-size: 13px; fill: #e63946; letter-spacing: 3px; font-weight: 700; }}
      .subtitle {{ font-size: 10px; fill: #555577; letter-spacing: 1px; }}
      .label {{ font-size: 11px; fill: #8888aa; }}
      .value {{ font-size: 11px; fill: #e0e0f0; font-weight: 600; }}
      .accent {{ font-size: 11px; fill: #e63946; font-weight: 600; }}
      .dim {{ font-size: 10px; fill: #6a6a8a; }}
      .bright {{ font-size: 12px; fill: #ff6b35; font-weight: 700; }}
      .section {{ font-size: 10px; fill: #e63946; letter-spacing: 2px; font-weight: 600; }}
      .stat-big {{ font-size: 22px; fill: #e0e0f0; font-weight: 700; }}
      .stat-label {{ font-size: 9px; fill: #555577; letter-spacing: 1px; }}
      .warning {{ font-size: 10px; fill: #ff6b35; }}
      .live {{ font-size: 9px; fill: #00e676; }}
      .scanline {{ animation: scanline 4s linear infinite; }}
      @keyframes scanline {{
        0% {{ opacity: 0.03; transform: translateY(0); }}
        50% {{ opacity: 0.06; }}
        100% {{ opacity: 0.03; transform: translateY(520px); }}
      }}
    </style>
  </defs>

  <!-- Background -->
  <rect width="820" height="520" rx="8" fill="url(#bgGrad)"/>
  <rect width="820" height="520" rx="8" fill="none" stroke="url(#borderGrad)" stroke-width="1.5"/>

  <!-- Scan line effect -->
  <rect class="scanline" width="820" height="2" fill="#e63946" opacity="0.04"/>

  <!-- Grid pattern overlay -->
  <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
    <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#1a1a3a" stroke-width="0.3"/>
  </pattern>
  <rect width="820" height="520" fill="url(#grid)" opacity="0.5"/>

  <!-- Corner decorations -->
  <path d="M 2 20 L 2 8 Q 2 2 8 2 L 20 2" fill="none" stroke="#e63946" stroke-width="1.5" opacity="0.8"/>
  <path d="M 800 2 L 812 2 Q 818 2 818 8 L 818 20" fill="none" stroke="#e63946" stroke-width="1.5" opacity="0.8"/>
  <path d="M 2 500 L 2 512 Q 2 518 8 518 L 20 518" fill="none" stroke="#e63946" stroke-width="1.5" opacity="0.8"/>
  <path d="M 800 518 L 812 518 Q 818 518 818 512 L 818 500" fill="none" stroke="#e63946" stroke-width="1.5" opacity="0.8"/>

  <!-- Header -->
  <text x="410" y="38" text-anchor="middle" class="mono title" filter="url(#glow)">◆  GLOBAL THREAT OPERATIONS CENTER  ◆</text>
  <text x="410" y="54" text-anchor="middle" class="mono subtitle">CENSYS INTERNET INTELLIGENCE  //  {m["timestamp"]}</text>

  <!-- Live indicator -->
  <circle cx="30" cy="46" r="4" fill="#00e676" opacity="0.9">
    <animate attributeName="opacity" values="0.9;0.3;0.9" dur="2s" repeatCount="indefinite"/>
  </circle>
  <text x="40" y="50" class="mono live">LIVE</text>

  <!-- Divider -->
  <line x1="30" y1="66" x2="790" y2="66" stroke="#2a2a4a" stroke-width="0.5"/>

  <!-- Total hosts stat -->
  <text x="410" y="100" text-anchor="middle" class="mono stat-big" filter="url(#glow)">{total_fmt}</text>
  <text x="410" y="116" text-anchor="middle" class="mono stat-label">OBSERVABLE HOSTS WORLDWIDE</text>

  <!-- Divider -->
  <line x1="30" y1="132" x2="790" y2="132" stroke="#2a2a4a" stroke-width="0.5"/>

  <!-- LEFT COLUMN: Regional Coverage -->
  <text x="40" y="156" class="mono section">◈ REGIONAL COVERAGE</text>

  <!-- North America -->
  <text x="40" y="182" class="mono label">NORTH AMERICA</text>
  <text x="290" y="182" class="mono value" text-anchor="end">{na_fmt}</text>
  <g transform="translate(40, 188)">{make_bar(na_frac)}</g>

  <!-- Europe -->
  <text x="40" y="216" class="mono label">EUROPE</text>
  <text x="290" y="216" class="mono value" text-anchor="end">{eu_fmt}</text>
  <g transform="translate(40, 222)">{make_bar(eu_frac)}</g>

  <!-- Asia-Pacific -->
  <text x="40" y="250" class="mono label">ASIA-PACIFIC</text>
  <text x="290" y="250" class="mono value" text-anchor="end">{ap_fmt}</text>
  <g transform="translate(40, 256)">{make_bar(ap_frac)}</g>

  <!-- RIGHT COLUMN: Exposed Attack Surface -->
  <text x="440" y="156" class="mono section">◈ EXPOSED ATTACK SURFACE</text>

  <!-- Critical services boxes -->
  <rect x="440" y="170" width="160" height="60" rx="4" fill="#1a1a2e" stroke="#2a2a4a" stroke-width="0.5"/>
  <text x="520" y="192" text-anchor="middle" class="mono bright">{rdp_fmt}</text>
  <text x="520" y="206" text-anchor="middle" class="mono dim">RDP EXPOSED</text>

  <rect x="615" y="170" width="160" height="60" rx="4" fill="#1a1a2e" stroke="#2a2a4a" stroke-width="0.5"/>
  <text x="695" y="192" text-anchor="middle" class="mono bright">{smb_fmt}</text>
  <text x="695" y="206" text-anchor="middle" class="mono dim">SMB EXPOSED</text>

  <rect x="440" y="240" width="335" height="30" rx="4" fill="#1a1a2e" stroke="#2a2a4a" stroke-width="0.5"/>
  <text x="460" y="260" class="mono warning">⚠ TELNET STILL ACTIVE:</text>
  <text x="670" y="260" class="mono bright">{telnet_fmt} HOSTS</text>

  <!-- Bottom section divider -->
  <line x1="30" y1="290" x2="790" y2="290" stroke="#2a2a4a" stroke-width="0.5"/>

  <!-- Bottom: Active Campaigns -->
  <text x="40" y="314" class="mono section">◈ ACTIVE CAMPAIGNS</text>

  <rect x="40" y="326" width="340" height="36" rx="4" fill="#1a1a2e" stroke="#e63946" stroke-width="0.5" opacity="0.8"/>
  <text x="55" y="349" class="mono accent">CVE-2026-1731</text>
  <text x="200" y="349" class="mono dim">BeyondTrust RCE</text>
  <text x="345" y="349" class="mono warning" text-anchor="end">CVSS 9.9</text>

  <rect x="40" y="370" width="340" height="36" rx="4" fill="#1a1a2e" stroke="#ff6b35" stroke-width="0.5" opacity="0.6"/>
  <text x="55" y="393" class="mono accent">CVE-2025-55182</text>
  <text x="200" y="393" class="mono dim">Next.js Server Actions</text>
  <text x="345" y="393" class="mono warning" text-anchor="end">HIGH</text>

  <rect x="40" y="414" width="340" height="36" rx="4" fill="#1a1a2e" stroke="#ff6b35" stroke-width="0.5" opacity="0.4"/>
  <text x="55" y="437" class="mono accent">ENVOY-JWT</text>
  <text x="200" y="437" class="mono dim">Proxy Auth Bypass</text>
  <text x="345" y="437" class="mono warning" text-anchor="end">HIGH</text>

  <!-- Bottom right: Top Services -->
  <text x="440" y="314" class="mono section">◈ TOP INTERNET SERVICES</text>
  <g>
    {"".join(
        f'<text x="460" y="{338 + i * 22}" class="mono dim">▸ {name}</text>'
        f'<text x="700" y="{338 + i * 22}" class="mono value" text-anchor="end">{format_count(count)}</text>'
        for i, (name, count) in enumerate(m["top_services"][:5])
    )}
  </g>

  <!-- Footer -->
  <line x1="30" y1="470" x2="790" y2="470" stroke="#2a2a4a" stroke-width="0.5"/>
  <text x="410" y="492" text-anchor="middle" class="mono dim">DATA SOURCE: CENSYS UNIVERSAL INTERNET DATASET  ·  UPDATED {m["date_short"]}</text>
  <text x="410" y="508" text-anchor="middle" class="mono dim">cybrdude // netguard24-7.com // attack surface management</text>

</svg>'''
    return svg


def generate_fallback_svg() -> str:
    """Generate a static SVG when no API keys are available."""
    now = datetime.now(timezone.utc)
    ts = now.strftime("%Y-%m-%d %H:%M UTC")
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="820" height="200" viewBox="0 0 820 200">
  <defs>
    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#0a0a1a"/>
      <stop offset="100%" style="stop-color:#0d0d24"/>
    </linearGradient>
    <style>
      .mono {{ font-family: 'JetBrains Mono', 'Fira Code', monospace; }}
    </style>
  </defs>
  <rect width="820" height="200" rx="8" fill="url(#bgGrad)"/>
  <rect width="820" height="200" rx="8" fill="none" stroke="#e63946" stroke-width="1" opacity="0.4"/>
  <text x="410" y="80" text-anchor="middle" class="mono" font-size="14" fill="#e63946" letter-spacing="3">◆  GLOBAL THREAT OPERATIONS CENTER  ◆</text>
  <text x="410" y="110" text-anchor="middle" class="mono" font-size="11" fill="#555577">AWAITING CENSYS API CONFIGURATION</text>
  <text x="410" y="140" text-anchor="middle" class="mono" font-size="10" fill="#3a3a5a">{ts}</text>
</svg>'''


if __name__ == "__main__":
    output_path = os.environ.get("OUTPUT_PATH", "assets/threat-ops.svg")
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    if CENSYS_API_ID and CENSYS_API_SECRET:
        metrics = fetch_metrics()
        if metrics.get("total_hosts", 0) > 0:
            svg = generate_svg(metrics)
            print(f"[+] Generated ops center with {format_count(metrics['total_hosts'])} total hosts")
        else:
            print("[!] No data returned from Censys, generating fallback")
            svg = generate_fallback_svg()
    else:
        print("[!] No Censys API credentials found, generating fallback SVG")
        svg = generate_fallback_svg()

    with open(output_path, "w") as f:
        f.write(svg)
    print(f"[+] SVG written to {output_path}")
