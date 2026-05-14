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
from mcp.server.fastmcp import FastMCP

import os as _os

_MEOK_API_KEY = _os.environ.get("MEOK_API_KEY", "")

try:
    sys.path.insert(0, os.path.expanduser("~/clawd/meok-labs-engine/shared"))
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
        return True, "OK", "free"


def check_access(api_key: str = ""):
    return _shared_check_access(api_key)


FREE_DAILY_LIMIT = 10
_usage: dict[str, list[datetime]] = defaultdict(list)
STRIPE_PRO = "https://buy.stripe.com/14A4gB3K4eUWgYR56o8k836"


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



def main():
    mcp.run()


if __name__ == "__main__":
    main()
