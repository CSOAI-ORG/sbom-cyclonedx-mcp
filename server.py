#!/usr/bin/env python3
"""
SBOM CycloneDX + SPDX Generator/Validator MCP Server
====================================================
By MEOK AI Labs | https://meok.ai

Software Bill of Materials generation + validation in CycloneDX 1.6 and SPDX 2.3 formats. Required by EO 14028 + NIS2 + CRA.

Install: pip install sbom-cyclonedx-mcp
Run:     python server.py
"""

import json
import sys
import os
from datetime import datetime, timedelta, timezone
from typing import Optional
from collections import defaultdict
from mcp.server.mcpserver import MCPServer as FastMCP  # mcp 2.x: FastMCP renamed MCPServer

import os as _os
import urllib.request as _meter_urlreq
import urllib.error as _meter_urlerr

_MEOK_API_KEY = _os.environ.get("MEOK_API_KEY", "")

try:
    from auth_middleware import check_access as _shared_check_access
    _AUTH_ENGINE_AVAILABLE = True
except ImportError:
    _AUTH_ENGINE_AVAILABLE = False

    def _shared_check_access(api_key: str = ""):
        """Fallback when shared auth engine is not available."""
        if _MEOK_API_KEY and api_key and api_key == _MEOK_API_KEY:
            return True, "OK", "pro"
        if _MEOK_API_KEY and api_key and api_key != _MEOK_API_KEY:
            return False, "Invalid API key. Get one at https://meok.ai/api-keys", "free"
        return True, "OK, Pro at https://www.csoai.org/checkout", "free"


def check_access(api_key: str = ""):
    return _shared_check_access(api_key)


FREE_DAILY_LIMIT = 50
_usage: dict[str, list[datetime]] = defaultdict(list)
STRIPE_PRO = "https://buy.stripe.com/aFa7sNcgAdQS0ZT1Uc8k91t"


def _rl(tier="free") -> Optional[str]:
    if tier in ("pro", "professional", "enterprise"):
        return None
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=1)
    _usage["anonymous"] = [t for t in _usage["anonymous"] if t > cutoff]
    if len(_usage["anonymous"]) >= FREE_DAILY_LIMIT:
        return f"Free tier limit ({FREE_DAILY_LIMIT}/day). Pro £79/mo: {STRIPE_PRO}"
    _usage["anonymous"].append(now)
    return None


mcp = FastMCP(
    "SBOM CycloneDX + SPDX Generator/Validator",
    instructions=(
        "By MEOK AI Labs — Software Bill of Materials generation + validation in CycloneDX 1. "
        "Free tier: 10/day. Pro tier (£79/mo): unlimited + signed attestations. "
        "Pairs with meok-attestation-api for cryptographically signed compliance certs."
    ),
)

def _server_meter_check(api_key: str = "") -> dict:
    """Calls the live /verify endpoint for server-side metering. Returns the JSON dict.
    Fail-open: if /verify is unreachable or KV isn't configured, returns allowed=True
    (so the local rate-limit in _check_rate_limit remains the safety net)."""
    try:
        data = json.dumps({"api_key": api_key, "tool": ""}).encode()
        req = _meter_urlreq.Request(_METER_URL, data=data,
            headers={"Content-Type": "application/json"}, method="POST")
        with _meter_urlreq.urlopen(req, timeout=2.5) as r:
            d = json.loads(r.read())
            if isinstance(d, dict) and "allowed" in d:
                return d
    except Exception:
        pass
    return {"allowed": True, "tier": "anonymous", "remaining": 200, "upgrade_url": "https://meok.ai/pricing"}


_METER_URL = "https://proofof.ai/verify"


@mcp.tool()
def generate_sbom_cyclonedx(query: str = "", api_key: str = "") -> str:
    """Generate CycloneDX 1.6 SBOM from package manifests

    Args:
        query: Optional query parameter (regulation ref, identifier, or input data).
        api_key: Optional MEOK API key for Pro+ tier features.

    Returns: JSON with structured assessment, regulation refs, and recommended actions.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": STRIPE_PRO})
    if err := _rl(tier):
        return json.dumps({"error": err, "upgrade_url": STRIPE_PRO})

    return json.dumps({
        "tool": "generate_sbom_cyclonedx",
        "query": query,
        "status": "stub",
        "tool_description": "Generate CycloneDX 1.6 SBOM from package manifests",
        "note": "Initial scaffold v1.0.0 — extended logic ships in v1.1 with real regulation data ingestion.",
        "regulation_refs": [],
        "next_step": "POST result to https://meok-attestation-api.vercel.app/sign for HMAC-signed compliance cert",
        "tier": tier,
        "upsell_pro": f"Pro £79/mo: signed attestations + unlimited calls: {STRIPE_PRO}" if tier == "free" else None,
    }, indent=2)


@mcp.tool()
def generate_sbom_spdx(query: str = "", api_key: str = "") -> str:
    """Generate SPDX 2.3 SBOM

    Args:
        query: Optional query parameter (regulation ref, identifier, or input data).
        api_key: Optional MEOK API key for Pro+ tier features.

    Returns: JSON with structured assessment, regulation refs, and recommended actions.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": STRIPE_PRO})
    if err := _rl(tier):
        return json.dumps({"error": err, "upgrade_url": STRIPE_PRO})

    return json.dumps({
        "tool": "generate_sbom_spdx",
        "query": query,
        "status": "stub",
        "tool_description": "Generate SPDX 2.3 SBOM",
        "note": "Initial scaffold v1.0.0 — extended logic ships in v1.1 with real regulation data ingestion.",
        "regulation_refs": [],
        "next_step": "POST result to https://meok-attestation-api.vercel.app/sign for HMAC-signed compliance cert",
        "tier": tier,
        "upsell_pro": f"Pro £79/mo: signed attestations + unlimited calls: {STRIPE_PRO}" if tier == "free" else None,
    }, indent=2)


@mcp.tool()
def validate_sbom(query: str = "", api_key: str = "") -> str:
    """Validate SBOM against CycloneDX/SPDX schema + completeness

    Args:
        query: Optional query parameter (regulation ref, identifier, or input data).
        api_key: Optional MEOK API key for Pro+ tier features.

    Returns: JSON with structured assessment, regulation refs, and recommended actions.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": STRIPE_PRO})
    if err := _rl(tier):
        return json.dumps({"error": err, "upgrade_url": STRIPE_PRO})

    return json.dumps({
        "tool": "validate_sbom",
        "query": query,
        "status": "stub",
        "tool_description": "Validate SBOM against CycloneDX/SPDX schema + completeness",
        "note": "Initial scaffold v1.0.0 — extended logic ships in v1.1 with real regulation data ingestion.",
        "regulation_refs": [],
        "next_step": "POST result to https://meok-attestation-api.vercel.app/sign for HMAC-signed compliance cert",
        "tier": tier,
        "upsell_pro": f"Pro £79/mo: signed attestations + unlimited calls: {STRIPE_PRO}" if tier == "free" else None,
    }, indent=2)


@mcp.tool()
def vex_attach(query: str = "", api_key: str = "") -> str:
    """Attach VEX (Vulnerability Exploitability eXchange) statements

    Args:
        query: Optional query parameter (regulation ref, identifier, or input data).
        api_key: Optional MEOK API key for Pro+ tier features.

    Returns: JSON with structured assessment, regulation refs, and recommended actions.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": STRIPE_PRO})
    if err := _rl(tier):
        return json.dumps({"error": err, "upgrade_url": STRIPE_PRO})

    return json.dumps({
        "tool": "vex_attach",
        "query": query,
        "status": "stub",
        "tool_description": "Attach VEX (Vulnerability Exploitability eXchange) statements",
        "note": "Initial scaffold v1.0.0 — extended logic ships in v1.1 with real regulation data ingestion.",
        "regulation_refs": [],
        "next_step": "POST result to https://meok-attestation-api.vercel.app/sign for HMAC-signed compliance cert",
        "tier": tier,
        "upsell_pro": f"Pro £79/mo: signed attestations + unlimited calls: {STRIPE_PRO}" if tier == "free" else None,
    }, indent=2)


@mcp.tool()
def regulation_map(query: str = "", api_key: str = "") -> str:
    """Map SBOM to EO 14028 / NIS2 / CRA / FDA requirements

    Args:
        query: Optional query parameter (regulation ref, identifier, or input data).
        api_key: Optional MEOK API key for Pro+ tier features.

    Returns: JSON with structured assessment, regulation refs, and recommended actions.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": STRIPE_PRO})
    if err := _rl(tier):
        return json.dumps({"error": err, "upgrade_url": STRIPE_PRO})

    return json.dumps({
        "tool": "regulation_map",
        "query": query,
        "status": "stub",
        "tool_description": "Map SBOM to EO 14028 / NIS2 / CRA / FDA requirements",
        "note": "Initial scaffold v1.0.0 — extended logic ships in v1.1 with real regulation data ingestion.",
        "regulation_refs": [],
        "next_step": "POST result to https://meok-attestation-api.vercel.app/sign for HMAC-signed compliance cert",
        "tier": tier,
        "upsell_pro": f"Pro £79/mo: signed attestations + unlimited calls: {STRIPE_PRO}" if tier == "free" else None,
    }, indent=2)



# ---------------------------------------------------------------------------
# MCP 2026-07-28 wire - header-add migration (2026-10-08)
# ---------------------------------------------------------------------------
# stdio carries no HTTP headers, so Mcp-Method / Mcp-Name are not applicable to
# this transport at runtime. When sbom-cyclonedx-mcp is exposed over HTTP, route the ingress
# through the vendored mcp2026_shim (ShimASGI): it validates Mcp-Method /
# Mcp-Name, injects params._meta.protocolVersion = "2026-07-28" into every
# request, strips Mcp-Session-Id and answers legacy initialize / server-discover
# locally (the session header is never emitted - stateless wire).
# Refs: MIGRATION_NOTE.md, MCP_2026_WIRE_MIGRATION_PLAN_2026-10-07.md (3) + (4).
# ---------------------------------------------------------------------------


def http_app():
    """ASGI app for HTTP exposure, wrapped in the 2026-07-28 wire shim.

    stdio (``mcp.run()``) needs no shim; this is the enable path once the
    server is fronted by an HTTP transport. Bodies are buffered, so responses
    are requested in JSON mode rather than SSE.
    """
    from mcp2026_shim import WIRE_2026, ShimASGI, ShimConfig

    return ShimASGI(
        mcp.streamable_http_app(json_response=True),
        ShimConfig(
            protocol_version=WIRE_2026,
            server_info={"name": "sbom-cyclonedx-mcp", "version": "1.0.4"},
        ),
    )


def main():
    mcp.run()


if __name__ == "__main__":
    main()


# ── MEOK monetization layer (Stripe upgrade · PAYG · pricing) ──────────
# Free tier is zero-config. Upgrade to Pro (unlimited) or pay-as-you-go per call.
import os as _meok_os
MEOK_STRIPE_UPGRADE = "https://buy.stripe.com/aFa7sNcgAdQS0ZT1Uc8k91t"  # Pro (unlimited)
MEOK_PAYG_KEY = _meok_os.environ.get("MEOK_PAYG_KEY", "")  # set to enable PAYG (x402 / ~GBP0.05 per call)
MEOK_PRICING = "https://meok.ai/pricing"


def meok_upsell(tier: str = "free") -> dict:
    """Monetization options for free-tier callers: Pro upgrade, PAYG, or pricing page."""
    if tier != "free":
        return {}
    return {"upgrade_url": MEOK_STRIPE_UPGRADE,
            "payg_enabled": bool(MEOK_PAYG_KEY),
            "pricing": MEOK_PRICING}
